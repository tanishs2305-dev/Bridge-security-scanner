"""
Regression tests for the Bridge Security Scanner.

These tests exist so that a change to the pattern files or scanning logic
can't silently make detection worse without anyone noticing. Run locally
with:  python -m pytest tests/ -v
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import VulnerabilityScanner, OffchainScanner

EXAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples")


def load_example(filename):
    path = os.path.join(EXAMPLES_DIR, filename)
    with open(path, "r") as f:
        return f.read()


# -------------------- ON-CHAIN (SOLIDITY) TESTS --------------------

def test_vulnerable_bridge_scores_higher_than_secure_bridge():
    """A contract with known injected bugs should score higher risk than its secure counterpart."""
    vulnerable = VulnerabilityScanner().scan_contract(load_example("vulnerable_bridge.sol"))
    secure = VulnerabilityScanner().scan_contract(load_example("secure_bridge.sol"))

    assert vulnerable["risk_score"] > secure["risk_score"], (
        f"Vulnerable example scored {vulnerable['risk_score']}, "
        f"secure example scored {secure['risk_score']}. "
        "The vulnerable example must score strictly higher."
    )


def test_vulnerable_bridge_flags_critical_issues():
    """The generic vulnerable example should surface at least one CRITICAL finding."""
    result = VulnerabilityScanner().scan_contract(load_example("vulnerable_bridge.sol"))
    assert result["summary"]["by_severity"]["CRITICAL"] > 0


@pytest.mark.xfail(
    reason=(
        "KNOWN BUG: reentrancy/false-topup patterns are hardcoded to the variable "
        "name 'balances'. ronin_style_vulnerable.sol uses 'deposits', so the real "
        "reentrancy bug goes undetected and this contract currently scores LOWER "
        "than its secure counterpart. Fix: make patterns variable-name-agnostic."
    ),
    strict=True
)
def test_ronin_style_vulnerable_scores_higher_than_ronin_style_secure():
    """
    This is the exact bug found during manual review: the Ronin-style vulnerable
    example (7 labeled real-world flaws) currently scores LOWER than the
    'secure' example. This test is expected to fail (xfail) until the
    variable-name-dependent regex patterns are generalized. Once fixed,
    remove the @pytest.mark.xfail decorator — if this test then passes,
    that's your confirmation the fix worked.
    """
    vulnerable = VulnerabilityScanner().scan_contract(load_example("ronin_style_vulnerable.sol"))
    secure = VulnerabilityScanner().scan_contract(load_example("ronin_style_secure.sol"))

    assert vulnerable["risk_score"] > secure["risk_score"]


def test_secure_examples_do_not_score_critical():
    """Secure examples shouldn't be flagged CRITICAL risk level, even with some false positives."""
    for filename in ["secure_bridge.sol", "ronin_style_secure.sol"]:
        result = VulnerabilityScanner().scan_contract(load_example(filename))
        assert result["risk_level"] != "CRITICAL", (
            f"{filename} was flagged CRITICAL — a secure example should never hit the top risk tier."
        )


# -------------------- OFF-CHAIN (RELAYER/VALIDATOR) TESTS --------------------

def test_offchain_scanner_detects_hardcoded_key():
    code = 'private_key = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"'
    result = OffchainScanner().scan_contract(code)

    vuln_names = [v["vulnerability"] for v in result["vulnerabilities"]]
    assert any("Hardcoded Private Key" in name for name in vuln_names)


def test_offchain_scanner_detects_shell_injection():
    code = 'subprocess.run(cmd, shell=True)'
    result = OffchainScanner().scan_contract(code)

    vuln_names = [v["vulnerability"] for v in result["vulnerabilities"]]
    assert any("Shell Injection" in name for name in vuln_names)


def test_offchain_scanner_flags_debug_mode():
    code = 'app.run(host="0.0.0.0", debug=True)'
    result = OffchainScanner().scan_contract(code)

    vuln_names = [v["vulnerability"] for v in result["vulnerabilities"]]
    assert any("Debug Mode" in name for name in vuln_names)


def test_offchain_scanner_on_clean_code_has_low_risk():
    """A short, unremarkable script with no bridge-relevant issues should not score high risk."""
    code = """
def add(a, b):
    return a + b

if __name__ == "__main__":
    print(add(2, 2))
"""
    result = OffchainScanner().scan_contract(code)
    assert result["risk_level"] in ("LOW", "MEDIUM")


# -------------------- CROSS-CUTTING SANITY CHECKS --------------------

def test_risk_score_never_exceeds_100():
    result = VulnerabilityScanner().scan_contract(load_example("vulnerable_bridge.sol"))
    assert 0 <= result["risk_score"] <= 100


def test_empty_input_produces_zero_findings():
    result = VulnerabilityScanner().scan_contract("")
    assert result["total_issues"] == 0
    assert result["risk_score"] == 0