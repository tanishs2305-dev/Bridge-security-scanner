"""
Labeled evaluation set for the Bridge Security Scanner.

Each entry is a small, self-contained contract with a ground-truth label:
    label    : "vulnerable" or "safe"
    expected : detector names that MUST fire for vulnerable contracts
Variable and function names are deliberately varied so the benchmark checks that
detection does not depend on naming.

NOTE: these contracts were written by the project author, so this is a sanity
benchmark of the scanner, not an independent one. Extending it with real audited
and exploited contracts (e.g. SmartBugs, SWC registry) is the next step.
"""

CONTRACTS = [
    # ------------------------------------------------------------ vulnerable
    {"name": "reentrancy_ledger", "label": "vulnerable", "expected": {"reentrancy"}, "code": """
pragma solidity ^0.8.20;
contract Pool {
    mapping(address => uint256) public ledger;
    function deposit() external payable { ledger[msg.sender] += msg.value; }
    function cashOut() external {
        uint256 amt = ledger[msg.sender];
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "send failed");
        ledger[msg.sender] = 0;
    }
}
"""},
    {"name": "open_governor_change", "label": "vulnerable", "expected": {"unprotected_privileged_function"}, "code": """
pragma solidity ^0.8.20;
contract Registry {
    address public governor;
    constructor() { governor = msg.sender; }
    function changeGovernor(address next) external { governor = next; }
}
"""},
    {"name": "signature_count_only", "label": "vulnerable", "expected": {"signature_count_only"}, "code": """
pragma solidity ^0.8.20;
contract Gate {
    uint256 public quorum = 3;
    function execute(address payable to, uint256 amount, bytes[] calldata sigs) external {
        require(sigs.length >= quorum, "not enough");
        to.transfer(amount);
    }
}
"""},
    {"name": "release_without_replay_guard", "label": "vulnerable", "expected": {"missing_replay_protection"}, "code": """
pragma solidity ^0.8.20;
contract Release {
    function release(address payable to, uint256 amount, bytes memory signature) external {
        require(signature.length == 65, "bad sig");
        to.transfer(amount);
    }
}
"""},
    {"name": "over_refund", "label": "vulnerable", "expected": {"over_refund"}, "code": """
pragma solidity ^0.8.20;
contract Escrow {
    mapping(bytes32 => uint256) public locked;
    function refundLock(bytes32 id) external {
        uint256 amt = locked[id];
        payable(msg.sender).transfer(amt);
    }
}
"""},
    {"name": "signer_never_checked", "label": "vulnerable", "expected": {"unauthorized_signer"}, "code": """
pragma solidity ^0.8.20;
contract Auth {
    function whoSigned(bytes32 h, uint8 v, bytes32 r, bytes32 s) external pure returns (address) {
        return ecrecover(h, v, r, s);
    }
}
"""},
    {"name": "tx_origin_wallet", "label": "vulnerable", "expected": {"tx_origin_auth"}, "code": """
pragma solidity ^0.8.20;
contract Wallet {
    address public holder;
    constructor() { holder = msg.sender; }
    function sendTo(address payable to, uint256 amt) external {
        require(tx.origin == holder, "no");
        to.transfer(amt);
    }
}
"""},
    {"name": "weak_randomness_lotto", "label": "vulnerable", "expected": {"weak_randomness"}, "code": """
pragma solidity ^0.8.20;
contract Lotto {
    function pick(uint256 n) external view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao))) % n;
    }
}
"""},
    {"name": "nomad_zero_root", "label": "vulnerable", "expected": {"zero_root_accepted"}, "code": """
pragma solidity ^0.8.20;
contract Replica {
    mapping(bytes32 => uint256) public confirmAt;
    constructor() { confirmAt[bytes32(0)] = 1; }
}
"""},
    {"name": "old_compiler_no_safemath", "label": "vulnerable", "expected": {"integer_overflow"}, "code": """
pragma solidity ^0.6.12;
contract Counter {
    uint256 public total;
    function bump(uint256 x) internal { total += x; }
}
"""},
    {"name": "unchecked_proof_result", "label": "vulnerable", "expected": {"unchecked_proof_result"}, "code": """
pragma solidity ^0.8.20;
interface IVerifier { function verifyProof(bytes calldata proof, bytes32 root) external view returns (bool); }
contract Claimer {
    IVerifier public verifier;
    function claimWith(bytes calldata proof, bytes32 root) external {
        verifier.verifyProof(proof, root);
        payable(msg.sender).transfer(1 ether);
    }
}
"""},
    {"name": "open_selfdestruct", "label": "vulnerable", "expected": {"unprotected_privileged_function"}, "code": """
pragma solidity ^0.8.20;
contract Killable {
    function shutdown(address payable to) external { selfdestruct(to); }
}
"""},
    {"name": "false_topup", "label": "vulnerable", "expected": {"false_topup"}, "code": """
pragma solidity ^0.8.20;
contract Credits {
    mapping(address => uint256) public credit;
    function depositFor(address user, uint256 amount) external { credit[user] += amount; }
}
"""},
    # ------------------------------------------------------------------ safe
    {"name": "safe_state_first_pool", "label": "safe", "expected": set(), "code": """
pragma solidity ^0.8.20;
contract SafePool {
    mapping(address => uint256) public funds;
    function deposit() external payable { funds[msg.sender] += msg.value; }
    function cashOut() external {
        uint256 amt = funds[msg.sender];
        require(amt > 0, "none");
        funds[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "send failed");
    }
}
"""},
    {"name": "safe_governed_admin", "label": "safe", "expected": set(), "code": """
pragma solidity ^0.8.20;
contract Governed {
    address public governor;
    modifier onlyGovernor() { require(msg.sender == governor, "not governor"); _; }
    constructor() { governor = msg.sender; }
    function changeGovernor(address next) external onlyGovernor {
        require(next != address(0));
        governor = next;
    }
}
"""},
    {"name": "safe_verified_release", "label": "safe", "expected": set(), "code": """
pragma solidity ^0.8.20;
contract Vault {
    mapping(address => bool) public isValidator;
    mapping(bytes32 => bool) public processed;
    address public admin;
    constructor() { admin = msg.sender; }
    modifier onlyAdmin() { require(msg.sender == admin, "admin"); _; }
    function setValidator(address v, bool ok) external onlyAdmin { isValidator[v] = ok; }
    function release(address payable to, uint256 amount, bytes32 id, uint8 v, bytes32 r, bytes32 s) external {
        require(!processed[id], "done");
        bytes32 h = keccak256(abi.encodePacked(block.chainid, address(this), to, amount, id));
        require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, "s");
        address signer = ecrecover(h, v, r, s);
        require(signer != address(0) && isValidator[signer], "bad signer");
        processed[id] = true;
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "fail");
    }
}
"""},
    {"name": "safe_refund_clears_record", "label": "safe", "expected": set(), "code": """
pragma solidity ^0.8.20;
contract SafeEscrow {
    mapping(bytes32 => uint256) public locked;
    mapping(bytes32 => address) public depositor;
    function refundLock(bytes32 id) external {
        require(depositor[id] == msg.sender, "not yours");
        uint256 amt = locked[id];
        delete locked[id];
        payable(msg.sender).transfer(amt);
    }
}
"""},
    {"name": "safe_plain_token", "label": "safe", "expected": set(), "code": """
pragma solidity ^0.8.20;
contract Token {
    mapping(address => uint256) public balanceOf;
    constructor() { balanceOf[msg.sender] = 1000000; }
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "low");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
"""},
    {"name": "safe_token_deposit", "label": "safe", "expected": set(), "code": """
pragma solidity ^0.8.20;
interface IERC20 { function transferFrom(address a, address b, uint256 c) external returns (bool); }
contract TokenVault2 {
    IERC20 public token;
    mapping(address => uint256) public credit;
    constructor(IERC20 t) { token = t; }
    function depositTokens(uint256 amount) external {
        require(token.transferFrom(msg.sender, address(this), amount), "pull failed");
        credit[msg.sender] += amount;
    }
}
"""},
    {"name": "safe_pausable", "label": "safe", "expected": set(), "code": """
pragma solidity ^0.8.20;
contract Pausable {
    address public owner;
    bool public paused;
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }
    constructor() { owner = msg.sender; }
    function pause() external onlyOwner { paused = true; }
    function unpause() external onlyOwner { paused = false; }
}
"""},
    {"name": "safe_merkle_claim", "label": "safe", "expected": set(), "code": """
pragma solidity ^0.8.20;
library MerkleProof {
    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        bytes32 h = leaf;
        for (uint256 i = 0; i < proof.length; i++) { h = keccak256(abi.encodePacked(h, proof[i])); }
        return h == root;
    }
}
contract Airdrop {
    bytes32 public root;
    mapping(address => bool) public claimed;
    constructor(bytes32 r) { root = r; }
    function claim(bytes32[] memory proof) external {
        require(!claimed[msg.sender], "claimed");
        require(MerkleProof.verify(proof, root, keccak256(abi.encodePacked(msg.sender))), "bad proof");
        claimed[msg.sender] = true;
        payable(msg.sender).transfer(1 ether);
    }
}
"""},
    # ---- cases added after adversarial probing (different coding styles) ----
    {"name": "old_syntax_dao_reentrancy", "label": "vulnerable", "expected": {"reentrancy"}, "code": """
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
"""},
    {"name": "delegatecall_user_target", "label": "vulnerable", "expected": {"controlled_delegatecall"}, "code": """
pragma solidity ^0.8.20;
contract Proxy {
    function forward(address target, bytes memory data) public { target.delegatecall(data); }
}
"""},
    {"name": "arbitrary_call_router", "label": "vulnerable", "expected": {"arbitrary_external_call"}, "code": """
pragma solidity ^0.8.20;
contract Router {
    function run(address target, bytes memory data) external {
        (bool ok, ) = target.call(data);
        require(ok);
    }
}
"""},
    {"name": "safe_self_service_profile", "label": "safe", "expected": set(), "code": """
pragma solidity ^0.8.20;
contract Profiles {
    mapping(address => string) public names;
    function updateName(string memory n) public { names[msg.sender] = n; }
}
"""},
    {"name": "safe_owner_only_router", "label": "safe", "expected": set(), "code": """
pragma solidity ^0.8.20;
contract Router2 {
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function run(address target, bytes memory data) external onlyOwner {
        (bool ok, ) = target.call(data);
        require(ok);
    }
}
"""},
]
