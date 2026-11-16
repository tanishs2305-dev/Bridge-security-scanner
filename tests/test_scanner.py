"""
Regression tests for the Bridge Security Scanner.

These tests make sure a change to the patterns or scanning logic cannot silently
make detection worse. Run locally with:  python -m pytest tests/ -v
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import VulnerabilityScanner, OffchainScanner

EXAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples")


def load_example(filename):
    with open(os.path.join(EXAMPLES_DIR, filename), "r", encoding="utf-8") as f:
        return f.read()


def detectors(code):
    result = VulnerabilityScanner().scan_contract(code)
    return {v["detector"] for v in result["vulnerabilities"]}


# -------------------- ON-CHAIN: EXAMPLE FILES --------------------

def test_vulnerable_bridge_scores_higher_than_secure_bridge():
    vulnerable = VulnerabilityScanner().scan_contract(load_example("vulnerable_bridge.sol"))
    secure = VulnerabilityScanner().scan_contract(load_example("secure_bridge.sol"))
    assert vulnerable["risk_score"] > secure["risk_score"]


def test_vulnerable_bridge_flags_critical_issues():
    result = VulnerabilityScanner().scan_contract(load_example("vulnerable_bridge.sol"))
    assert result["summary"]["by_severity"]["CRITICAL"] > 0


def test_ronin_style_vulnerable_scores_higher_than_ronin_style_secure():
    """
    Previously a documented known bug (xfail): the reentrancy pattern was hardcoded to a
    mapping named 'balances', so the Ronin example (mapping named 'deposits') was missed.
    Fixed by the name-agnostic function-level rules.
    """
    vulnerable = VulnerabilityScanner().scan_contract(load_example("ronin_style_vulnerable.sol"))
    secure = VulnerabilityScanner().scan_contract(load_example("ronin_style_secure.sol"))
    assert vulnerable["risk_score"] > secure["risk_score"]


def test_secure_examples_stay_low_risk():
    for filename in ["secure_bridge.sol", "ronin_style_secure.sol"]:
        result = VulnerabilityScanner().scan_contract(load_example(filename))
        assert result["risk_level"] == "LOW", f"{filename} scored {result['risk_score']}"


# -------------------- ON-CHAIN: NAME-AGNOSTIC DETECTION --------------------

REENTRANT_TEMPLATE = """
pragma solidity ^0.8.0;
contract C {{
    mapping(address => uint256) public {name};
    function take() public {{
        uint256 a = {name}[msg.sender];
        (bool ok, ) = msg.sender.call{{value: a}}("");
        require(ok);
        {name}[msg.sender] = 0;
    }}
}}
"""


def test_reentrancy_detected_regardless_of_variable_name():
    for name in ["balances", "deposits", "userFunds", "x1", "ledger"]:
        assert "reentrancy" in detectors(REENTRANT_TEMPLATE.format(name=name)), name


def test_reentrancy_not_flagged_when_state_updated_first():
    code = """
pragma solidity ^0.8.0;
contract C {
    mapping(address => uint256) public funds;
    function take() public {
        uint256 a = funds[msg.sender];
        funds[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: a}("");
        require(ok);
    }
}
"""
    assert "reentrancy" not in detectors(code)


def test_unprotected_privileged_function_detected():
    code = """
pragma solidity ^0.8.0;
contract C {
    address public admin;
    function setAdmin(address a) public { admin = a; }
}
"""
    assert "unprotected_privileged_function" in detectors(code)


def test_protected_privileged_function_not_flagged():
    code = """
pragma solidity ^0.8.0;
contract C {
    address public admin;
    modifier onlyAdmin() { require(msg.sender == admin); _; }
    function setAdmin(address a) public onlyAdmin { admin = a; }
}
"""
    assert "unprotected_privileged_function" not in detectors(code)


def test_signature_count_only_detected():
    code = """
pragma solidity ^0.8.0;
contract C {
    uint256 public required = 3;
    function release(uint256 amt, bytes[] memory signatures) public {
        require(signatures.length >= required, "few");
        payable(msg.sender).transfer(amt);
    }
}
"""
    assert "signature_count_only" in detectors(code)


def test_missing_replay_protection_detected():
    code = """
pragma solidity ^0.8.0;
contract C {
    function withdraw(uint256 amt, bytes memory signature) public {
        require(signature.length == 65);
        payable(msg.sender).transfer(amt);
    }
}
"""
    assert "missing_replay_protection" in detectors(code)


def test_over_refund_detected():
    code = """
pragma solidity ^0.8.0;
contract C {
    mapping(bytes32 => uint256) public deposits;
    function refund(bytes32 id) public {
        uint256 amt = deposits[id];
        payable(msg.sender).transfer(amt);
    }
}
"""
    assert "over_refund" in detectors(code)


def test_refund_that_clears_record_not_flagged():
    code = """
pragma solidity ^0.8.0;
contract C {
    mapping(bytes32 => uint256) public deposits;
    function refund(bytes32 id) public {
        uint256 amt = deposits[id];
        deposits[id] = 0;
        payable(msg.sender).transfer(amt);
    }
}
"""
    assert "over_refund" not in detectors(code)


def test_validator_impersonation_detected():
    code = """
pragma solidity ^0.8.0;
contract C {
    function verify(bytes32 h, uint8 v, bytes32 r, bytes32 s) public pure returns (address) {
        return ecrecover(h, v, r, s);
    }
}
"""
    found = detectors(code)
    assert "unauthorized_signer" in found
    assert "ecrecover_zero_address" in found


def test_tx_origin_and_weak_randomness_detected():
    code = """
pragma solidity ^0.8.0;
contract C {
    address admin;
    function f(uint256 n) public view returns (uint256) {
        require(tx.origin == admin);
        return uint256(keccak256(abi.encodePacked(block.timestamp, n)));
    }
}
"""
    found = detectors(code)
    assert "tx_origin_auth" in found
    assert "weak_randomness" in found


def test_nomad_zero_root_detected():
    code = """
pragma solidity ^0.8.0;
contract C {
    mapping(bytes32 => uint256) public confirmAt;
    constructor() { confirmAt[bytes32(0)] = 1; }
}
"""
    assert "zero_root_accepted" in detectors(code)


def test_every_finding_has_remediation():
    for filename in ["vulnerable_bridge.sol", "ronin_style_vulnerable.sol"]:
        result = VulnerabilityScanner().scan_contract(load_example(filename))
        assert result["vulnerabilities"]
        for v in result["vulnerabilities"]:
            assert v.get("remediation"), v["vulnerability"]


def test_old_solidity_call_value_reentrancy_detected():
    code = """
pragma solidity ^0.4.24;
contract Bank {
    mapping(address => uint) public credit;
    function withdraw(uint amount) public {
        if (credit[msg.sender] >= amount) {
            msg.sender.call.value(amount)();
            credit[msg.sender] -= amount;
        }
    }
}
"""
    assert "reentrancy" in detectors(code)


def test_controlled_delegatecall_and_arbitrary_call_detected():
    delegate = "pragma solidity ^0.8.20;\ncontract P { function f(address t, bytes memory d) public { t.delegatecall(d); } }"
    call = "pragma solidity ^0.8.20;\ncontract R { function run(address t, bytes memory d) external { (bool ok,) = t.call(d); require(ok); } }"
    assert "controlled_delegatecall" in detectors(delegate)
    assert "arbitrary_external_call" in detectors(call)


def test_owner_only_call_target_not_flagged():
    code = """
pragma solidity ^0.8.20;
contract R {
    address owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function run(address t, bytes memory d) external onlyOwner { (bool ok,) = t.call(d); require(ok); }
}
"""
    assert "arbitrary_external_call" not in detectors(code)


def test_self_service_function_not_flagged_as_privileged():
    code = """
pragma solidity ^0.8.20;
contract P {
    mapping(address => string) public names;
    function updateName(string memory n) public { names[msg.sender] = n; }
}
"""
    assert "unprotected_privileged_function" not in detectors(code)


def test_incident_table_references_real_detectors():
    from data.incidents import INCIDENTS, all_detector_names, CATEGORIES
    names = all_detector_names()
    assert len(INCIDENTS) >= 19
    for inc in INCIDENTS:
        assert inc["category"] in CATEGORIES
        for d in inc["detectors"]:
            assert d in names, f"{inc['name']} references unknown detector {d}"


def test_benchmark_has_no_false_positives_or_misses():
    from evaluation.evaluate import run_evaluation
    r = run_evaluation()
    assert r["confusion"]["FP"] == 0
    assert r["confusion"]["FN"] == 0
    assert r["detector_hit_rate"] == 1.0


def test_merge_does_not_double_count_a_bug_found_by_both_engines():
    from scanner import merge_scan_results
    code = REENTRANT_TEMPLATE.format(name="ledger")
    pattern = VulnerabilityScanner().scan_contract(code)
    fake_slither = {
        "vulnerabilities": [{
            "category": "Slither: Reentrancy Eth", "vulnerability": "Reentrancy Eth",
            "description": "d", "severity": "CRITICAL", "explanation": "e", "line_number": 1,
            "code_snippet": "s", "remediation": "r", "detector": "reentrancy-eth", "source": "slither",
        }],
        "engine_error": None,
    }
    merged = merge_scan_results(pattern, fake_slither)
    assert merged["total_issues"] == pattern["total_issues"]
    assert merged["risk_score"] == pattern["risk_score"]
    assert any(v.get("confirmed_by") == "slither" for v in merged["vulnerabilities"])


def test_merge_keeps_slither_only_findings():
    from scanner import merge_scan_results
    pattern = VulnerabilityScanner().scan_contract("pragma solidity ^0.8.20; contract C {}")
    fake_slither = {
        "vulnerabilities": [{
            "category": "Slither: Missing Zero Check", "vulnerability": "Missing Zero Check",
            "description": "d", "severity": "LOW", "explanation": "e", "line_number": 1,
            "code_snippet": "s", "remediation": "r", "detector": "missing-zero-check", "source": "slither",
        }],
        "engine_error": None,
    }
    merged = merge_scan_results(pattern, fake_slither)
    assert merged["total_issues"] == pattern["total_issues"] + 1


# -------------------- OFF-CHAIN (RELAYER/VALIDATOR) --------------------

def test_offchain_scanner_detects_hardcoded_key():
    code = 'private_key = "0x1111111111111111111111111111111111111111111111111111111111111111"'
    result = OffchainScanner().scan_contract(code)
    names = [v["vulnerability"] for v in result["vulnerabilities"]]
    assert any("Hardcoded Private Key" in n for n in names)


def test_offchain_scanner_detects_shell_injection():
    result = OffchainScanner().scan_contract("subprocess.run(cmd, shell=True)")
    names = [v["vulnerability"] for v in result["vulnerabilities"]]
    assert any("Shell Injection" in n for n in names)


def test_offchain_scanner_flags_debug_mode():
    result = OffchainScanner().scan_contract('app.run(host="0.0.0.0", debug=True)')
    names = [v["vulnerability"] for v in result["vulnerabilities"]]
    assert any("Debug Mode" in n for n in names)


def test_offchain_findings_have_remediation():
    result = OffchainScanner().scan_contract("subprocess.run(cmd, shell=True)")
    assert all(v.get("remediation") for v in result["vulnerabilities"])


def test_offchain_scanner_on_clean_code_has_low_risk():
    code = "def add(a, b):\n    return a + b\n"
    result = OffchainScanner().scan_contract(code)
    assert result["risk_level"] in ("LOW", "MEDIUM")


# -------------------- CROSS-CUTTING --------------------

def test_risk_score_never_exceeds_100():
    result = VulnerabilityScanner().scan_contract(load_example("vulnerable_bridge.sol"))
    assert 0 <= result["risk_score"] <= 100


def test_empty_input_produces_zero_findings():
    result = VulnerabilityScanner().scan_contract("")
    assert result["total_issues"] == 0
    assert result["risk_score"] == 0
