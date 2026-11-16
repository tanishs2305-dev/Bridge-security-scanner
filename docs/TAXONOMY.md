# Cross-chain bridge incident taxonomy

Each incident is mapped to one of the four vulnerability categories and to the detectors in this
project. Loss figures are approximate (USD millions) - verify against your cited sources.

**19 incidents** | Partial: 11 | Detected: 6 | Out of scope: 2

| Incident | Year | Loss ($M) | Category | Root cause | Detectors | Coverage |
|---|---|---|---|---|---|---|
| Ronin Bridge | 2022 | 625 | Key Theft | Attackers controlled enough validator private keys to forge withdrawals | hardcoded_private_key, plaintext_key_file, hardcoded_threshold_one, signature_count_only | Partial |
| Poly Network | 2021 | 611 | Verification Bypass | Crafted cross-chain message let the attacker replace the privileged keeper role | unprotected_privileged_function, phantom_function | Partial |
| BNB Token Hub bridge | 2022 | 570 | Diverse Exploits | Forged Merkle proof accepted by the chain's proof verification | unchecked_proof_result, merkle_root_fraud | Partial |
| Wormhole | 2022 | 325 | Verification Bypass | Signature verification could be bypassed (Solana program, not Solidity) | unchecked_proof_result, unauthorized_signer, signature_count_only | Partial |
| Nomad | 2022 | 190 | Verification Bypass | Zero hash was accepted as a trusted root after a faulty initialisation | zero_root_accepted, merkle_root_fraud | Detected |
| Multichain (MPC keys) | 2023 | 126 | Key Theft | Control of the MPC/private keys was lost or abused | hardcoded_private_key, plaintext_key_file | Partial |
| Harmony Horizon | 2022 | 100 | Key Theft | Low-threshold multisig (2 of 5) whose keys were compromised | hardcoded_threshold_one, signature_count_only | Partial |
| Heco Bridge | 2023 | 87 | Key Theft | Private key compromise | hardcoded_private_key, plaintext_key_file, secret_in_log | Partial |
| Orbit Chain | 2024 | 81 | Key Theft | Multisig signer keys compromised | hardcoded_private_key, plaintext_key_file, hardcoded_threshold_one | Partial |
| Qubit QBridge | 2022 | 80 | Asymmetric Processing | Legacy deposit path credited a deposit that never moved real assets | false_topup, mapping_inconsistency | Partial |
| pNetwork | 2021 | 12.7 | Key Theft | Node private key compromised | hardcoded_private_key, plaintext_key_file | Partial |
| LI.FI | 2024 | 10 | Verification Bypass | Facet made an external call with attacker-supplied target and calldata | arbitrary_external_call, phantom_function | Detected |
| ChainSwap | 2021 | 8 | Verification Bypass | Forged validator signatures accepted | unauthorized_signer, signature_count_only | Detected |
| Meter.io Passport | 2022 | 4.4 | Asymmetric Processing | Deposit credited without a matching real asset transfer | false_topup | Partial |
| Socket | 2024 | 3.3 | Verification Bypass | Unvalidated user-supplied call data allowed draining approved tokens | arbitrary_external_call, phantom_function | Detected |
| Multichain (permit) | 2022 | n/a | Verification Bypass | permit() verification bypassed through a token fallback function (phantom function) | phantom_function | Detected |
| THORChain | 2021 | n/a | Asymmetric Processing | Refund logic manipulated to receive more than was deposited (over-refund) | over_refund, missing_replay_protection | Detected |
| Celer cBridge | 2022 | 0.24 | Diverse Exploits | Network-level BGP hijack of the frontend, not a contract bug | - | Out of scope |
| Rainbow Bridge (attempt) | 2022 | 0 | Diverse Exploits | Attempted invalid block-header update, caught by off-chain monitoring | event_log_manipulation | Out of scope |

Coverage levels: **Detected** = a detector targets the root-cause pattern; **Partial** = the vulnerability
class or adjacent hygiene is covered but not the exact root cause; **Out of scope** = not detectable by
static analysis of contract or relayer code.
