"""
Slither integration for the Bridge Security Scanner.

Slither is Trail of Bits' open-source static analyzer for Solidity. Unlike
our regex-based VulnerabilityScanner, Slither parses code into an AST and
understands it structurally — so it correctly finds bugs like reentrancy
regardless of what a variable happens to be named (this is the exact class
of bug our regex scanner missed on the Ronin example, where the vulnerable
mapping was named `deposits` instead of `balances`).

This module runs Slither as a subprocess against submitted Solidity code
and maps its JSON output into the same finding format the rest of the app
already expects, so results from both engines can be merged/displayed
identically.
"""

import json
import subprocess
import tempfile
import os
import re
from typing import Dict, List, Optional

# Maps Slither's impact levels to this project's severity vocabulary
IMPACT_TO_SEVERITY = {
    "High": "CRITICAL",
    "Medium": "HIGH",
    "Low": "MEDIUM",
    "Informational": "LOW",
}

# Hard timeout so a pathological or huge contract can't hang the app.
# Slither compiles the contract via solc, which is far slower than regex,
# so this is more generous than the regex timeout used elsewhere.
SLITHER_TIMEOUT_SECONDS = 30


class SlitherUnavailableError(Exception):
    """Raised when Slither or solc isn't installed / usable in this environment."""
    pass


def _check_slither_available() -> bool:
    try:
        subprocess.run(
            ["slither", "--version"],
            capture_output=True, timeout=10, check=False
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _detect_pragma_version(contract_code: str) -> Optional[str]:
    """
    Extract a concrete solc version to use from a contract's pragma line.
    Handles common forms: ^0.8.0, >=0.7.0 <0.9.0, 0.8.19, etc.
    Returns something solc-select can install, e.g. "0.8.19", or None if
    no pragma is found (solc-select will then fall back to its default).
    """
    match = re.search(r"pragma\s+solidity\s+([^\;]+);", contract_code)
    if not match:
        return None

    version_spec = match.group(1).strip()
    version_match = re.search(r"(\d+\.\d+\.\d+)", version_spec)
    return version_match.group(1) if version_match else None


def _ensure_solc_version(version: str) -> None:
    """
    Make sure the requested solc version is installed and active via
    solc-select, installing it on first use if needed. No-op on failure —
    Slither will then just use whatever solc is currently active, and
    report a compilation error if that's incompatible.
    """
    try:
        subprocess.run(
            ["solc-select", "install", version],
            capture_output=True, timeout=60, check=False
        )
        subprocess.run(
            ["solc-select", "use", version],
            capture_output=True, timeout=10, check=False
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass


def scan_with_slither(contract_code: str) -> Dict:
    """
    Run Slither against the given Solidity source and return findings in
    the same shape as VulnerabilityScanner.scan_contract().

    Returns a dict with keys: vulnerabilities, risk_score, risk_level,
    summary, total_issues, language, language_info, engine_error (if any).
    """
    if not _check_slither_available():
        raise SlitherUnavailableError(
            "Slither is not installed or not on PATH. "
            "Install with: pip install slither-analyzer"
        )

    findings: List[Dict] = []
    engine_error = None

    # Auto-select the matching solc version based on the contract's pragma,
    # installing it via solc-select if it's not already available locally.
    detected_version = _detect_pragma_version(contract_code)
    if detected_version:
        _ensure_solc_version(detected_version)

    with tempfile.TemporaryDirectory() as tmpdir:
        contract_path = os.path.join(tmpdir, "Contract.sol")
        with open(contract_path, "w") as f:
            f.write(contract_code)

        json_output_path = os.path.join(tmpdir, "slither_output.json")

        try:
            result = subprocess.run(
                ["slither", contract_path, "--json", json_output_path],
                capture_output=True,
                text=True,
                timeout=SLITHER_TIMEOUT_SECONDS,
                check=False,  # Slither exits non-zero when it finds issues — that's expected, not a failure
                cwd=tmpdir,
            )

            if not os.path.exists(json_output_path):
                engine_error = (
                    "Slither could not analyze this contract (likely a compilation error — "
                    "check the Solidity version/pragma). Falling back to pattern-based results only."
                )
            else:
                with open(json_output_path) as f:
                    data = json.load(f)

                detectors = (data.get("results") or {}).get("detectors") or []

                for finding in detectors:
                    check_name = finding.get("check", "unknown")
                    impact = finding.get("impact", "Informational")
                    description = finding.get("description", "").strip()

                    elements = finding.get("elements", [])
                    line_number = None
                    if elements:
                        lines = elements[0].get("source_mapping", {}).get("lines", [])
                        line_number = lines[0] if lines else None

                    findings.append({
                        "category": "Slither: " + check_name.replace("-", " ").title(),
                        "vulnerability": check_name.replace("-", " ").title(),
                        "description": description.split("\n")[0][:200],
                        "severity": IMPACT_TO_SEVERITY.get(impact, "LOW"),
                        "explanation": description,
                        "line_number": line_number if line_number else 0,
                        "code_snippet": description,
                        "source": "slither"
                    })

        except subprocess.TimeoutExpired:
            engine_error = (
                f"Slither analysis exceeded {SLITHER_TIMEOUT_SECONDS}s and was aborted. "
                "Falling back to pattern-based results only."
            )

    # Reuse the same scoring logic as the rest of the app
    severity_weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2}
    total_score = sum(severity_weights.get(f["severity"], 0) for f in findings)
    risk_score = min(total_score, 100)

    if risk_score >= 81:
        risk_level = "CRITICAL"
    elif risk_score >= 51:
        risk_level = "HIGH"
    elif risk_score >= 21:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    summary = {
        "by_category": {},
        "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    }
    for f in findings:
        summary["by_category"][f["category"]] = summary["by_category"].get(f["category"], 0) + 1
        summary["by_severity"][f["severity"]] += 1

    return {
        "language": "solidity",
        "language_info": {
            "name": "Solidity (Slither AST analysis)",
            "description": "Structural analysis via Trail of Bits' Slither",
            "file_extension": ".sol",
            "icon": "🔬"
        },
        "vulnerabilities": findings,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "summary": summary,
        "total_issues": len(findings),
        "engine_error": engine_error
    }