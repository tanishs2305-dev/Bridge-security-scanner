"""
Remediation guidance for every detector in the Bridge Security Scanner.

Lookup is keyed by the detector's internal name (the dictionary key used in
vulnerability_patterns.py, function_rules.py and offchain_patterns.py) or by
Slither's check name. Each entry is short, concrete, and says what to change.
"""

DEFAULT_REMEDIATION = (
    "Review this code path manually. Add explicit validation (require/revert) "
    "for every input and external call, and cover the fix with a test."
)

# ---------------------------------------------------------------- on-chain
ONCHAIN_REMEDIATION = {
    "phantom_function": (
        "Restrict who can call the function (onlyOwner / role check) and validate "
        "every argument before moving funds or making an external call."
    ),
    "missing_return_check": (
        "Capture the success flag of the low-level call and revert on failure: "
        "(bool ok, ) = target.call{value: v}(\"\"); require(ok, \"call failed\");"
    ),
    "unchecked_proof_result": (
        "Never ignore the boolean returned by a proof/signature verifier. Wrap it: "
        "require(MerkleProof.verify(proof, root, leaf), \"invalid proof\");"
    ),
    "unprotected_privileged_function": (
        "Add an access-control modifier (onlyOwner / onlyRole) or a "
        "require(msg.sender == authorizedAddress) check. Initializers should use an "
        "initializer modifier so they can run only once."
    ),
    "missing_replay_protection": (
        "Bind each message to a unique ID (nonce / message hash), check "
        "!processed[id] first, and set processed[id] = true before releasing funds."
    ),
    "over_refund": (
        "Tie the refund to the original deposit ID and amount stored on-chain, mark it "
        "as refunded (or delete the record) BEFORE sending value, and never trust a "
        "caller-supplied amount."
    ),
    "missing_chain_domain_separation": (
        "Include block.chainid, the bridge contract address and a message version in "
        "the signed/hashed data (EIP-712 domain separator) so a signature valid on one "
        "chain cannot be replayed on another."
    ),
    "controlled_delegatecall": (
        "Never delegatecall to a caller-supplied address. Use a fixed, audited implementation "
        "address (proxy pattern) that only governance can change."
    ),
    "arbitrary_external_call": (
        "Do not call addresses supplied by the caller. Use an allow-list of targets and "
        "function selectors, restrict the function with access control, and never hold token "
        "approvals that this function can spend."
    ),
    "signature_count_only": (
        "Verify every signature (ecrecover/ECDSA), require each recovered signer to be a "
        "registered validator, reject duplicate signers, and only then compare the count "
        "of VALID unique signers with the threshold."
    ),
    "unauthorized_signer": (
        "After ecrecover/ECDSA.recover, check that the recovered address is a registered "
        "validator, e.g. require(isValidator[signer]); and de-duplicate signers so one "
        "validator cannot be counted twice."
    ),
    "ecrecover_zero_address": (
        "ecrecover returns address(0) for an invalid signature. Add "
        "require(signer != address(0)) or use OpenZeppelin ECDSA.recover, which reverts."
    ),
    "reentrancy": (
        "Follow checks-effects-interactions: update balances / processed flags first and "
        "make the external call last. Add OpenZeppelin ReentrancyGuard (nonReentrant)."
    ),
    "false_topup": (
        "Credit balances only from verified deposits (verified event/proof or "
        "msg.value), never from unchecked caller-supplied amounts."
    ),
    "mapping_inconsistency": (
        "Verify the token mapping between chains (1:1 backing) before minting or "
        "releasing, and reject unknown token contracts."
    ),
    "weak_key_generation": (
        "Never derive keys or secrets on-chain; block.timestamp/prevrandao are "
        "predictable. Generate keys off-chain with a CSPRNG or use a verifiable "
        "randomness oracle."
    ),
    "weak_randomness": (
        "Do not use block.timestamp / difficulty / prevrandao / number for randomness. "
        "Use a verifiable randomness source (e.g. Chainlink VRF) or commit-reveal."
    ),
    "exposed_private_data": (
        "Nothing on-chain is private, including 'private' variables. Keep secrets off-chain."
    ),
    "signature_malleability": (
        "Use OpenZeppelin ECDSA (rejects malleable s/v values) and keep a used-signature "
        "/ nonce record so each signature works once."
    ),
    "tx_origin_auth": (
        "Authenticate with msg.sender, not tx.origin. tx.origin lets a malicious "
        "contract act with the victim's authority (phishing)."
    ),
    "event_log_manipulation": (
        "Treat events as untrusted input. Validate emitter address, event signature, "
        "chain and finality against a verified proof before acting on them."
    ),
    "merkle_root_fraud": (
        "Only update a Merkle root through an authenticated, verified path and reject "
        "the zero root."
    ),
    "zero_root_accepted": (
        "Never mark the zero hash as a confirmed/trusted root (the Nomad bug). Reject "
        "bytes32(0) in initialisation and in every root update."
    ),
    "integer_overflow": (
        "Use Solidity >= 0.8 (checked arithmetic) or SafeMath for older compilers."
    ),
}

# --------------------------------------------------------------- off-chain
OFFCHAIN_REMEDIATION = {
    "hardcoded_private_key": (
        "Remove the key from source and ROTATE it (assume it is compromised). Load keys "
        "from a KMS/HSM or an encrypted vault at runtime."
    ),
    "secret_in_log": (  # nosec B105 - advice text, not a credential
        "Never log keys or secrets. Redact sensitive fields in your logging layer and "
        "purge existing logs that contain them."
    ),
    "plaintext_key_file": (
        "Store signing keys in an HSM/KMS or encrypted keystore, not a plaintext file on "
        "the validator host."
    ),
    "missing_signer_verification": (
        "Verify each signature and check the recovered signer is in the authorized "
        "validator set; count UNIQUE valid signers against the threshold."
    ),
    "hardcoded_threshold_one": (
        "Use a real M-of-N threshold (majority of independent validators) and load it "
        "from audited configuration."
    ),
    "no_replay_protection_offchain": (
        "Persist processed message IDs (database/ledger) and skip any ID already relayed."
    ),
    "debug_mode_enabled": (
        "Disable debug mode in production (debug=False) and serve through a production "
        "WSGI/ASGI server."
    ),
    "bind_all_interfaces": (
        "Bind to 127.0.0.1 or a private interface and put admin/RPC endpoints behind "
        "authentication and a firewall."
    ),
    "hardcoded_rpc_with_key": (
        "Move RPC URLs with API keys to environment variables / a secrets manager and "
        "rotate the exposed key."
    ),
    "shell_injection_risk": (
        "Avoid shell=True and string-concatenated commands. Pass an argument list: "
        "subprocess.run([\"curl\", url], check=True) and validate inputs."
    ),
    "insecure_deserialization": (
        "Never unpickle untrusted data. Use JSON, and yaml.safe_load for YAML."
    ),
}

# ------------------------------------------------------------------ Slither
SLITHER_REMEDIATION = {
    "reentrancy-eth": "Update state before the external call and add a nonReentrant guard.",
    "reentrancy-no-eth": "Update state before the external call and add a nonReentrant guard.",
    "reentrancy-benign": "Move state updates before the external call (checks-effects-interactions).",
    "reentrancy-events": "Emit events before external calls so logs stay consistent under reentrancy.",
    "unchecked-lowlevel": "Check the boolean returned by .call/.send and revert on failure.",
    "unchecked-send": "Check the boolean returned by .send and revert on failure.",
    "low-level-calls": "Prefer typed interface calls; if a low-level call is required, check its result.",
    "solc-version": "Pin a recent, bug-fixed compiler (e.g. pragma solidity 0.8.24;) instead of a floating or old range.",
    "tx-origin": "Replace tx.origin with msg.sender for authorization.",
    "timestamp": "Do not rely on block.timestamp for critical logic; allow a tolerance window.",
    "weak-prng": "Use verifiable randomness (e.g. Chainlink VRF) instead of block fields.",
    "suicidal": "Protect selfdestruct behind strict access control or remove it.",
    "arbitrary-send-eth": "Restrict who can trigger ETH transfers and who receives them.",
    "controlled-delegatecall": "Never delegatecall to a user-controlled address.",
    "uninitialized-state": "Initialize the state variable explicitly (constructor/initializer).",
    "missing-zero-check": "Add require(addr != address(0)) on critical address parameters.",
    "unprotected-upgrade": "Protect upgrade/initialize functions with access control.",
    "incorrect-equality": "Avoid strict equality on balances/timestamps; use >= / <= with tolerance.",
    "calls-loop": "Avoid external calls inside loops; use pull-payments or batching.",
    "external-function": "Mark functions that are never called internally as external.",
    "naming-convention": "Follow Solidity naming conventions for readability.",
    "pragma": "Use a single fixed compiler version across all files.",
}


def get_remediation(detector_name: str, source: str = "pattern") -> str:
    """Return remediation text for a detector (never empty)."""
    key = (detector_name or "").strip()
    if source == "slither":
        return SLITHER_REMEDIATION.get(key, DEFAULT_REMEDIATION)
    return (
        ONCHAIN_REMEDIATION.get(key)
        or OFFCHAIN_REMEDIATION.get(key)
        or DEFAULT_REMEDIATION
    )
