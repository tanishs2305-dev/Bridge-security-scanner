"""
Function-level detection rules for bridge smart contracts.

The plain regex patterns in vulnerability_patterns.py match text on one line, so
they depend on how a contract happens to be written (for example a mapping that
is literally called `balances`). These rules first split the contract into
functions (brace matching), then reason about each function body:

    "is there a state write AFTER an external call in the same function?"
    "does a signature-processing function ever check WHO signed?"

They are independent of variable names, which is what fixes the Ronin-style
`deposits` miss. Each rule returns None (no finding) or a character offset inside
the function text, used for the reported line number.
"""

import regex as re

# ----------------------------------------------------------------- helpers
FUNC_RE = re.compile(r"\bfunction\s+(\w+)\s*\(([^)]*)\)([^{;]*)\{")

_SKIP_HEADER_WORDS = {
    "public", "external", "internal", "private", "payable", "virtual",
    "override", "view", "pure", "nonpayable",
}

EXTERNAL_CALL = re.compile(r"\.call\s*(\{[^}]*\})?\s*\(|\.call\.value\s*\(")
MOVES_VALUE = re.compile(
    r"\.call\s*(\{[^}]*\})?\s*\(|\.call\.value\s*\(|\.transfer\s*\(|\.send\s*\(|\b_?mint\s*\(|safeTransfer\w*\s*\("
)
# A write to a mapping/array element, or a compound assignment to a variable
STATE_WRITE = re.compile(
    r"(?m)(?:^|(?<=[;{}]))[ \t]*[A-Za-z_]\w*(?:\s*\[[^\]]*\])+\s*[+\-*/]?=(?!=)"
    r"|(?:^|(?<=[;{}]))[ \t]*[A-Za-z_]\w*\s*[+\-*/]=(?!=)"
)
ECRECOVER = re.compile(r"\becrecover\s*\(|\.recover\s*\(|ECDSA\.\w*recover\w*\s*\(")
ECRECOVER_RAW = re.compile(r"\becrecover\s*\(")

AUTH_IN_BODY = re.compile(
    r"msg\.sender\s*(==|!=)|(==|!=)\s*msg\.sender|_msgSender\(\)\s*(==|!=)"
    r"|\bonlyRole\b|\bhasRole\s*\(|_checkOwner|_checkRole|\bisOwner\b|\bisAdmin\b"
    r"|\bisValidator\s*\[|\bisAuthorized\b|\bauthorized\s*\["
)
SIGNER_CHECK = re.compile(
    r"\bisValidator\b|\bisSigner\b|\bisGuardian\b|\bisAuthorized\b|\bhasRole\b"
    r"|\bvalidators?\s*\[|\bsigners?\s*\[|\btrustedSigner\b|\bauthorizedSigner\b"
    r"|(==|!=)\s*(owner|admin|signer|validator|guardian|trusted\w*)\b"
    r"|\b(owner|admin|signer|validator|guardian|trusted\w*)\s*(==|!=)"
)
PRIVILEGED_NAME = re.compile(
    r"(?i)^(set|add|remove|update|change|upgrade|emergency|mint|burn|pause|unpause|"
    r"transferOwnership|renounce|initialize|init|grant|revoke|rescue|sweep|drain|"
    r"kill|destroy|migrate|enable|disable)"
)
PROCESSING_NAME = re.compile(
    r"(?i)(withdraw|release|claim|redeem|execute|relay|process|receive|handle|"
    r"unlock|finalize|complete|submit)"
)
MESSAGE_INPUT = re.compile(r"(?i)(signature|sigs\b|proof|merkle|ecrecover|message|payload)")
REPLAY_MARKER = re.compile(
    r"(?i)(nonce|processed|consumed|executed|claimed|\bused\b|usedhash|\bseen\b|isprocessed)"
)
CONSUME_WRITE = re.compile(
    r"\w+\s*(\[[^\]]*\])+\s*=\s*(true|false|0)\s*;|\w+\s*(\[[^\]]*\])+\s*-=|\bdelete\s+\w+"
)


def extract_functions(code: str):
    """Split Solidity source into functions using brace matching."""
    functions = []
    for m in FUNC_RE.finditer(code):
        open_idx = m.end() - 1
        depth = 0
        i = open_idx
        n = len(code)
        while i < n:
            ch = code[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        text = code[m.start(): i + 1]
        header = re.sub(r"returns\s*\([^)]*\)", "", m.group(3))
        functions.append({
            "name": m.group(1),
            "params": m.group(2),
            "header": header,
            "text": text,
            "body": code[open_idx: i + 1],
            "start": m.start(),
        })
    return functions


def _is_callable_state_changing(fn) -> bool:
    h = fn["header"]
    return bool(re.search(r"\b(public|external)\b", h)) and not re.search(r"\b(view|pure)\b", h)


def _has_modifier(fn) -> bool:
    tokens = [t for t in re.findall(r"\w+", fn["header"]) if t not in _SKIP_HEADER_WORDS]
    return bool(tokens)


# ------------------------------------------------------------------- rules
SELF_SERVICE = re.compile(r"\[\s*(msg\.sender|_msgSender\(\))\s*\]\s*[+\-*/]?=(?!=)")


def check_unprotected_privileged_function(fn, code):
    if not _is_callable_state_changing(fn):
        return None
    has_selfdestruct = "selfdestruct(" in fn["body"]
    if not (PRIVILEGED_NAME.search(fn["name"]) or has_selfdestruct):
        return None
    if _has_modifier(fn) or AUTH_IN_BODY.search(fn["body"]):
        return None
    # A function that only edits the CALLER's own record (x[msg.sender] = ...) is
    # self-service, not privileged, unless it also self-destructs.
    if SELF_SERVICE.search(fn["body"]) and not has_selfdestruct:
        return None
    return 0


def check_missing_replay_protection(fn, code):
    if not _is_callable_state_changing(fn):
        return None
    if not PROCESSING_NAME.search(fn["name"]):
        return None
    if not MESSAGE_INPUT.search(fn["text"]):
        return None
    m = MOVES_VALUE.search(fn["body"])
    if not m:
        return None
    if REPLAY_MARKER.search(fn["body"]):
        return None
    return m.start() + (len(fn["text"]) - len(fn["body"]))


def check_over_refund(fn, code):
    if not _is_callable_state_changing(fn):
        return None
    if not re.search(r"(?i)refund|reimburse", fn["name"]):
        return None
    m = MOVES_VALUE.search(fn["body"])
    if not m:
        return None
    if CONSUME_WRITE.search(fn["body"]):
        return None
    return m.start() + (len(fn["text"]) - len(fn["body"]))


def check_unauthorized_signer(fn, code):
    m = ECRECOVER.search(fn["body"])
    if not m:
        return None
    # The validator-registry check may live in the caller of an internal helper,
    # so look across the whole contract, not just this function.
    if SIGNER_CHECK.search(code):
        return None
    return m.start() + (len(fn["text"]) - len(fn["body"]))


BRIDGE_NAME = re.compile(r"(?i)bridge|crosschain|wrap|lock")
ANY_VALIDATION = re.compile(r"\brequire\s*\(|\brevert\b|\bassert\s*\(|\bif\s*\(")
CREDIT_NAME = re.compile(r"(?i)(deposit|credit|topup|top_up|lock|fund)")
CREDIT_WRITE = re.compile(r"\b\w+\s*\[[^\]]*\]\s*\+=\s*(?!msg\.value\b)\w+")
REAL_TRANSFER_IN = re.compile(r"transferFrom\s*\(|safeTransferFrom\s*\(|msg\.value|balanceOf\s*\(\s*address\s*\(\s*this")


def check_mapping_inconsistency(fn, code):
    if not _is_callable_state_changing(fn):
        return None
    if not BRIDGE_NAME.search(fn["name"]):
        return None
    if ANY_VALIDATION.search(fn["body"]):
        return None
    if not (MOVES_VALUE.search(fn["body"]) or STATE_WRITE.search(fn["body"])):
        return None
    return 0


def check_false_topup(fn, code):
    if not _is_callable_state_changing(fn):
        return None
    if not CREDIT_NAME.search(fn["name"]):
        return None
    m = CREDIT_WRITE.search(fn["body"])
    if not m:
        return None
    if REAL_TRANSFER_IN.search(fn["body"]):
        return None
    return m.start() + (len(fn["text"]) - len(fn["body"]))


TARGET_DELEGATECALL = re.compile(r"(\w+)\s*\.\s*delegatecall\s*\(")
TARGET_CALL = re.compile(r"(\w+)\s*\.\s*call\s*(?:\{[^}]*\})?\s*\(")


def _param_names(fn):
    names = set()
    for part in fn["params"].split(","):
        tokens = part.strip().split()
        if tokens:
            names.add(tokens[-1])
    return names


def _controlled_target(fn, pattern):
    if not _is_callable_state_changing(fn):
        return None
    if _has_modifier(fn) or AUTH_IN_BODY.search(fn["body"]):
        return None
    params = _param_names(fn)
    for m in pattern.finditer(fn["body"]):
        if m.group(1) in params:
            return m.start() + (len(fn["text"]) - len(fn["body"]))
    return None


def check_controlled_delegatecall(fn, code):
    return _controlled_target(fn, TARGET_DELEGATECALL)


def check_arbitrary_external_call(fn, code):
    return _controlled_target(fn, TARGET_CALL)


SIG_COUNT = re.compile(r"(?i)\b(signatures?|sigs)\s*\.\s*length\s*(>=|>|==)")
VERIFY_CALL = re.compile(
    r"(?i)\becrecover\b|\.recover\s*\(|\bverify\w*\s*\(|\brecoverSigner\b|\bisValidator\b|\bisSigner\b"
)


def check_signature_count_only(fn, code):
    m = SIG_COUNT.search(fn["body"])
    if not m:
        return None
    if VERIFY_CALL.search(fn["body"]):
        return None
    return m.start() + (len(fn["text"]) - len(fn["body"]))


def check_ecrecover_zero_address(fn, code):
    m = ECRECOVER_RAW.search(fn["body"])
    if not m:
        return None
    # A zero-address check, or a validator-registry lookup (which excludes the
    # zero address), anywhere in the contract makes this safe.
    if "address(0)" in code or SIGNER_CHECK.search(code):
        return None
    return m.start() + (len(fn["text"]) - len(fn["body"]))


MALLEABILITY_GUARD = re.compile(
    r"(?i)0x7fffffffffffffffffffffffffffffff5d576e73|\bECDSA\b|\bSignatureChecker\b|\btryRecover\b"
)


def check_signature_malleability(fn, code):
    m = ECRECOVER_RAW.search(fn["body"])
    if not m:
        return None
    if MALLEABILITY_GUARD.search(code):
        return None
    return m.start() + (len(fn["text"]) - len(fn["body"]))


def check_missing_chain_domain_separation(fn, code):
    # Only functions that take a message from outside; internal helpers get the
    # already-built hash from their caller.
    if not _is_callable_state_changing(fn):
        return None
    m = ECRECOVER.search(fn["body"])
    if not m:
        return None
    lowered = code.lower()
    if "chainid" in lowered or "domain_separator" in lowered or "domainseparator" in lowered:
        return None
    return m.start() + (len(fn["text"]) - len(fn["body"]))


def check_reentrancy(fn, code):
    if "nonReentrant" in fn["text"] or "ReentrancyGuard" in fn["text"]:
        return None
    call = EXTERNAL_CALL.search(fn["body"])
    if not call:
        return None
    after = STATE_WRITE.search(fn["body"], call.end())
    if not after:
        return None
    return call.start() + (len(fn["text"]) - len(fn["body"]))


FUNCTION_RULES = {
    "unprotected_privileged_function": {
        "category": "verification_bypass",
        "description": "Privileged function callable by anyone (no access control)",
        "severity": "HIGH",
        "explanation": (
            "A function that changes validators, owners, balances or contract state has "
            "no modifier or msg.sender check, so any account can call it (Ronin/Poly "
            "Network style privilege takeover)."
        ),
        "check": check_unprotected_privileged_function,
    },
    "mapping_inconsistency": {
        "category": "asymmetric_processing",
        "description": "Bridge function moves assets with no validation of the transfer",
        "severity": "HIGH",
        "explanation": (
            "A bridge/lock/wrap function changes balances or sends value without a single "
            "require/revert/if check, so cross-chain asset mapping (1:1 backing) is not enforced."
        ),
        "check": check_mapping_inconsistency,
    },
    "false_topup": {
        "category": "asymmetric_processing",
        "description": "Balance credited from a caller-supplied amount with no real deposit",
        "severity": "CRITICAL",
        "explanation": (
            "A deposit/credit function adds an arbitrary amount to a balance without pulling "
            "tokens (transferFrom) or receiving msg.value, so balances can be minted from nothing "
            "(false top-up, as in the Qubit and Meter.io incidents)."
        ),
        "check": check_false_topup,
    },
    "controlled_delegatecall": {
        "category": "diverse_exploits",
        "description": "delegatecall to an address supplied by the caller",
        "severity": "CRITICAL",
        "explanation": (
            "delegatecall runs foreign code with THIS contract's storage and balance; if the "
            "target is caller-controlled, anyone can take over the contract."
        ),
        "check": check_controlled_delegatecall,
    },
    "arbitrary_external_call": {
        "category": "verification_bypass",
        "description": "Unrestricted external call to a caller-supplied address",
        "severity": "HIGH",
        "explanation": (
            "A public function calls an address passed in by the caller with no access "
            "control, so an attacker can make the contract call anything it has approvals for "
            "(the LI.FI and Socket incidents)."
        ),
        "check": check_arbitrary_external_call,
    },
    "signature_count_only": {
        "category": "verification_bypass",
        "description": "Only the NUMBER of signatures is checked, never their validity or signers",
        "severity": "CRITICAL",
        "explanation": (
            "The function compares signatures.length with a threshold but never verifies the "
            "signatures or who signed them, so garbage or duplicate signatures pass "
            "(the flaw class behind the Ronin and Harmony multisig thefts)."
        ),
        "check": check_signature_count_only,
    },
    "unauthorized_signer": {
        "category": "verification_bypass",
        "description": "Signature verified but signer is never checked against the validator set",
        "severity": "CRITICAL",
        "explanation": (
            "The recovered signer is not compared with a registered validator, so an "
            "attacker can sign with any key (validator impersonation, as in ChainSwap and "
            "Poly Network)."
        ),
        "check": check_unauthorized_signer,
    },
    "missing_replay_protection": {
        "category": "asymmetric_processing",
        "description": "Message/proof processing function never records that a message was used",
        "severity": "CRITICAL",
        "explanation": (
            "A function that releases or mints value from a signature/proof has no "
            "nonce or processed-message record, so the same message can be replayed to "
            "drain funds."
        ),
        "check": check_missing_replay_protection,
    },
    "over_refund": {
        "category": "asymmetric_processing",
        "description": "Refund path moves value without marking the refund as consumed",
        "severity": "HIGH",
        "explanation": (
            "A refund function sends value but never records or deletes the refund, so it "
            "can be claimed repeatedly (over-refund, as in the THORChain incidents)."
        ),
        "check": check_over_refund,
    },
    "missing_chain_domain_separation": {
        "category": "asymmetric_processing",
        "description": "Signature scheme has no chain ID / domain separation",
        "severity": "HIGH",
        "explanation": (
            "Signed data does not include the chain ID or a domain separator, so a "
            "signature valid on one chain can be replayed on another."
        ),
        "check": check_missing_chain_domain_separation,
    },
    "ecrecover_zero_address": {
        "category": "key_theft",
        "description": "ecrecover result is not checked against address(0)",
        "severity": "HIGH",
        "explanation": (
            "ecrecover returns address(0) for malformed signatures; without a zero-address "
            "check an invalid signature may be accepted for an unset/zero signer."
        ),
        "check": check_ecrecover_zero_address,
    },
    "signature_malleability": {
        "category": "key_theft",
        "description": "ecrecover used without a malleability guard (s-value check / ECDSA library)",
        "severity": "MEDIUM",
        "explanation": (
            "Raw ecrecover accepts both (r,s,v) and the malleated (r,-s,v) form of a signature. "
            "If a signature is ever used as a unique ID or replay key, the second form bypasses it."
        ),
        "check": check_signature_malleability,
    },
    "reentrancy": {
        "category": "diverse_exploits",
        "description": "State is updated AFTER an external call in the same function",
        "severity": "CRITICAL",
        "explanation": (
            "The function sends control to an external address before updating storage, "
            "so a malicious receiver can re-enter and withdraw repeatedly. Detected "
            "structurally, independent of variable names."
        ),
        "check": check_reentrancy,
    },
}
