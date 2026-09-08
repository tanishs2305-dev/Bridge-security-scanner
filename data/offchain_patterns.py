"""
Off-Chain Bridge Infrastructure Vulnerability Patterns
This file contains patterns for relayer, validator, and oracle services
(typically written in Python or Go) that support cross-chain bridges.

Scope is intentionally narrow: these are NOT generic language linters.
Every pattern here targets a class of bug that has actually caused a
real bridge exploit (e.g. Ronin: compromised/undermonitored validator
keys; various bridges: leaked relayer keys via logging or bad storage).
"""

# Category 1: Key & Secret Exposure
KEY_EXPOSURE_PATTERNS = {
    "hardcoded_private_key": {
        "description": "Private key or mnemonic hardcoded directly in source",
        "patterns": [
            r"private_key\s*=\s*[\"'][0-9a-fA-Fx]{16,}[\"']",   # Python hardcoded hex key
            r"privateKey\s*:?=\s*[\"'][0-9a-fA-Fx]{16,}[\"']",   # Go hardcoded hex key
            r"mnemonic\s*=\s*[\"'](\w+\s+){5,}\w+[\"']",         # Hardcoded seed phrase
        ],
        "severity": "CRITICAL",
        "explanation": "Validator/relayer signing keys must never be committed to source. A leaked key allows an attacker to sign fraudulent withdrawals directly."
    },
    "secret_in_log": {
        "description": "Private key or secret written to logs/stdout",
        "patterns": [
            r"(print|log\.\w+|logger\.\w+|fmt\.Print\w*)\([^)]*(private_key|privateKey|secret|mnemonic)[^)]*\)",
        ],
        "severity": "CRITICAL",
        "explanation": "Logging systems (files, aggregators, crash reporters) are a common leak vector for signing keys and are rarely treated as secret storage."
    },
    "plaintext_key_file": {
        "description": "Reading a signing key from an unencrypted local file",
        "patterns": [
            r"open\([\"'].*key.*[\"']\s*,\s*[\"']r[\"']\)",       # Python plaintext key file read
            r"ioutil\.ReadFile\([\"'].*key.*[\"']\)",             # Go plaintext key file read
        ],
        "severity": "HIGH",
        "explanation": "Signing keys should be stored in an HSM, KMS, or encrypted vault, not read as plaintext from disk on the validator host."
    }
}

# Category 2: Signature & Threshold Validation
SIGNATURE_VALIDATION_PATTERNS = {
    "missing_signer_verification": {
        "description": "Signature count checked without verifying each signer is authorized",
        "patterns": [
            r"len\(signatures\)\s*>=\s*\w+(?!.*verify)(?!.*is_validator)",   # Python: count check, no per-signer check
            r"len\(sigs\)\s*>=\s*\w+(?!.*[Vv]erify)",
        ],
        "severity": "CRITICAL",
        "explanation": "Checking only the number of signatures (not who signed) allows an attacker to submit N signatures from non-validator or duplicate keys and still pass the threshold — the root cause of several real bridge hacks."
    },
    "hardcoded_threshold_one": {
        "description": "Multisig/validator threshold hardcoded to 1",
        "patterns": [
            r"required(_signatures|Signatures|_validators|Validators)?\s*[:=]\s*1\b",
            r"threshold\s*[:=]\s*1\b",
        ],
        "severity": "HIGH",
        "explanation": "A threshold of 1 defeats the purpose of a multi-validator design — compromise of a single key is enough to forge withdrawals."
    },
    "no_replay_protection_offchain": {
        "description": "Relayer submits transactions without tracking processed message IDs",
        "patterns": [
            r"def\s+relay\w*\([^)]*\):(?!.*(processed|seen|nonce))",
        ],
        "severity": "HIGH",
        "explanation": "Relayer logic should track already-processed message/withdrawal IDs to avoid rebroadcasting or replaying the same cross-chain message."
    }
}

# Category 3: Network & Service Exposure
NETWORK_EXPOSURE_PATTERNS = {
    "debug_mode_enabled": {
        "description": "Web framework running with debug mode enabled",
        "patterns": [
            r"debug\s*=\s*True",                     # Flask/Django debug mode
            r"app\.run\([^)]*debug\s*=\s*True",
        ],
        "severity": "HIGH",
        "explanation": "Debug mode can expose stack traces, source code, and in some frameworks a remote code execution console to anyone who can reach the service."
    },
    "bind_all_interfaces": {
        "description": "Service bound to all network interfaces",
        "patterns": [
            r"host\s*=\s*[\"']0\.0\.0\.0[\"']",
            r"ListenAndServe\([\"']:\d+[\"']",       # Go binding without explicit interface
        ],
        "severity": "MEDIUM",
        "explanation": "Binding validator/relayer admin or RPC endpoints to all interfaces can expose them beyond the intended private network."
    },
    "hardcoded_rpc_with_key": {
        "description": "RPC endpoint URL with embedded API key committed to source",
        "patterns": [
            r"https?://[^\"'\s]*(alchemy|infura|quicknode)[^\"'\s]*/v\d/[A-Za-z0-9]{20,}",
        ],
        "severity": "HIGH",
        "explanation": "Embedded API keys in RPC URLs are billing/rate-limit credentials that get exposed the same way any hardcoded secret does."
    }
}

# Category 4: Unsafe Execution
UNSAFE_EXECUTION_PATTERNS = {
    "shell_injection_risk": {
        "description": "Shell command built from external input",
        "patterns": [
            r"subprocess\.\w+\([^)]*shell\s*=\s*True",
            r"os\.system\([^)]*\+",                   # string concatenation into os.system
        ],
        "severity": "HIGH",
        "explanation": "Relayer/oracle services that shell out using unsanitized or concatenated input are vulnerable to command injection if any part of that input is externally influenced."
    },
    "insecure_deserialization": {
        "description": "Untrusted data deserialized unsafely",
        "patterns": [
            r"pickle\.loads?\(",
            r"yaml\.load\((?!.*Loader\s*=\s*yaml\.SafeLoader)",
        ],
        "severity": "HIGH",
        "explanation": "Deserializing untrusted data with pickle or unsafe YAML loaders can lead to arbitrary code execution if a validator/relayer processes attacker-influenced payloads."
    }
}

# Aggregate all off-chain patterns
ALL_OFFCHAIN_PATTERNS = {
    "key_exposure": KEY_EXPOSURE_PATTERNS,
    "signature_validation": SIGNATURE_VALIDATION_PATTERNS,
    "network_exposure": NETWORK_EXPOSURE_PATTERNS,
    "unsafe_execution": UNSAFE_EXECUTION_PATTERNS
}