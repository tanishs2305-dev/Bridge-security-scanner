"""
Bridge incident taxonomy.

Maps real cross-chain bridge incidents to the four vulnerability categories and to the
detectors in this project (on-chain patterns, function rules, off-chain rules).

Coverage levels (deliberately conservative):
    Detected      - a detector targets the root-cause pattern of this incident
    Partial       - detectors cover the vulnerability class or adjacent hygiene,
                    but not the exact root cause (e.g. the code was not Solidity,
                    or the compromise happened outside the code)
    Out of scope  - not detectable by static analysis of contract/relayer code

Loss figures are approximate (USD millions) and compiled from public reporting;
verify them against your cited sources (e.g. Zhao et al. [3]) before presenting.
"""

from data.vulnerability_patterns import ALL_PATTERNS
from data.function_rules import FUNCTION_RULES
from data.offchain_patterns import ALL_OFFCHAIN_PATTERNS

CATEGORIES = [
    "Verification Bypass",
    "Asymmetric Processing",
    "Key Theft",
    "Diverse Exploits",
]

INCIDENTS = [
    {"name": "Ronin Bridge", "year": 2022, "loss_usd_m": 625, "category": "Key Theft",
     "root_cause": "Attackers controlled enough validator private keys to forge withdrawals",
     "detectors": ["hardcoded_private_key", "plaintext_key_file", "hardcoded_threshold_one", "signature_count_only"],
     "coverage": "Partial"},
    {"name": "Poly Network", "year": 2021, "loss_usd_m": 611, "category": "Verification Bypass",
     "root_cause": "Crafted cross-chain message let the attacker replace the privileged keeper role",
     "detectors": ["unprotected_privileged_function", "phantom_function"],
     "coverage": "Partial"},
    {"name": "BNB Token Hub bridge", "year": 2022, "loss_usd_m": 570, "category": "Diverse Exploits",
     "root_cause": "Forged Merkle proof accepted by the chain's proof verification",
     "detectors": ["unchecked_proof_result", "merkle_root_fraud"],
     "coverage": "Partial"},
    {"name": "Wormhole", "year": 2022, "loss_usd_m": 325, "category": "Verification Bypass",
     "root_cause": "Signature verification could be bypassed (Solana program, not Solidity)",
     "detectors": ["unchecked_proof_result", "unauthorized_signer", "signature_count_only"],
     "coverage": "Partial"},
    {"name": "Nomad", "year": 2022, "loss_usd_m": 190, "category": "Verification Bypass",
     "root_cause": "Zero hash was accepted as a trusted root after a faulty initialisation",
     "detectors": ["zero_root_accepted", "merkle_root_fraud"],
     "coverage": "Detected"},
    {"name": "Multichain (MPC keys)", "year": 2023, "loss_usd_m": 126, "category": "Key Theft",
     "root_cause": "Control of the MPC/private keys was lost or abused",
     "detectors": ["hardcoded_private_key", "plaintext_key_file"],
     "coverage": "Partial"},
    {"name": "Harmony Horizon", "year": 2022, "loss_usd_m": 100, "category": "Key Theft",
     "root_cause": "Low-threshold multisig (2 of 5) whose keys were compromised",
     "detectors": ["hardcoded_threshold_one", "signature_count_only"],
     "coverage": "Partial"},
    {"name": "Heco Bridge", "year": 2023, "loss_usd_m": 87, "category": "Key Theft",
     "root_cause": "Private key compromise",
     "detectors": ["hardcoded_private_key", "plaintext_key_file", "secret_in_log"],
     "coverage": "Partial"},
    {"name": "Orbit Chain", "year": 2024, "loss_usd_m": 81, "category": "Key Theft",
     "root_cause": "Multisig signer keys compromised",
     "detectors": ["hardcoded_private_key", "plaintext_key_file", "hardcoded_threshold_one"],
     "coverage": "Partial"},
    {"name": "Qubit QBridge", "year": 2022, "loss_usd_m": 80, "category": "Asymmetric Processing",
     "root_cause": "Legacy deposit path credited a deposit that never moved real assets",
     "detectors": ["false_topup", "mapping_inconsistency"],
     "coverage": "Partial"},
    {"name": "pNetwork", "year": 2021, "loss_usd_m": 12.7, "category": "Key Theft",
     "root_cause": "Node private key compromised",
     "detectors": ["hardcoded_private_key", "plaintext_key_file"],
     "coverage": "Partial"},
    {"name": "LI.FI", "year": 2024, "loss_usd_m": 10, "category": "Verification Bypass",
     "root_cause": "Facet made an external call with attacker-supplied target and calldata",
     "detectors": ["arbitrary_external_call", "phantom_function"],
     "coverage": "Detected"},
    {"name": "ChainSwap", "year": 2021, "loss_usd_m": 8, "category": "Verification Bypass",
     "root_cause": "Forged validator signatures accepted",
     "detectors": ["unauthorized_signer", "signature_count_only"],
     "coverage": "Detected"},
    {"name": "Meter.io Passport", "year": 2022, "loss_usd_m": 4.4, "category": "Asymmetric Processing",
     "root_cause": "Deposit credited without a matching real asset transfer",
     "detectors": ["false_topup"],
     "coverage": "Partial"},
    {"name": "Socket", "year": 2024, "loss_usd_m": 3.3, "category": "Verification Bypass",
     "root_cause": "Unvalidated user-supplied call data allowed draining approved tokens",
     "detectors": ["arbitrary_external_call", "phantom_function"],
     "coverage": "Detected"},
    {"name": "Multichain (permit)", "year": 2022, "loss_usd_m": None, "category": "Verification Bypass",
     "root_cause": "permit() verification bypassed through a token fallback function (phantom function)",
     "detectors": ["phantom_function"],
     "coverage": "Detected"},
    {"name": "THORChain", "year": 2021, "loss_usd_m": None, "category": "Asymmetric Processing",
     "root_cause": "Refund logic manipulated to receive more than was deposited (over-refund)",
     "detectors": ["over_refund", "missing_replay_protection"],
     "coverage": "Detected"},
    {"name": "Celer cBridge", "year": 2022, "loss_usd_m": 0.24, "category": "Diverse Exploits",
     "root_cause": "Network-level BGP hijack of the frontend, not a contract bug",
     "detectors": [],
     "coverage": "Out of scope"},
    {"name": "Rainbow Bridge (attempt)", "year": 2022, "loss_usd_m": 0, "category": "Diverse Exploits",
     "root_cause": "Attempted invalid block-header update, caught by off-chain monitoring",
     "detectors": ["event_log_manipulation"],
     "coverage": "Out of scope"},
]


def all_detector_names():
    """Every detector name that exists in the project (used to validate this table)."""
    names = set(FUNCTION_RULES)
    for group in ALL_PATTERNS.values():
        names.update(group)
    for group in ALL_OFFCHAIN_PATTERNS.values():
        names.update(group)
    return names


def coverage_summary():
    """Counts per coverage level, per category, and total losses covered."""
    summary = {"total": len(INCIDENTS), "by_coverage": {}, "by_category": {}, "loss_total_m": 0.0}
    for inc in INCIDENTS:
        summary["by_coverage"][inc["coverage"]] = summary["by_coverage"].get(inc["coverage"], 0) + 1
        summary["by_category"][inc["category"]] = summary["by_category"].get(inc["category"], 0) + 1
        summary["loss_total_m"] += inc["loss_usd_m"] or 0
    return summary
