"""
Bridge Security Scanner - Main Engine
Analyzes cross-chain bridge security across both halves of the stack:
  - On-chain: Solidity smart contracts
  - Off-chain: relayer/validator/oracle services (Python, Go)

Note: this scanner is deliberately scoped to bridge-relevant vulnerability
classes, not generic language linting. See README for rationale.
"""

import regex as re  # drop-in replacement for 're' with a timeout guard against
                     # catastrophic regex backtracking (ReDoS). See _scan_category.
from typing import Dict, List
from data.vulnerability_patterns import ALL_PATTERNS, SEVERITY_WEIGHTS
from data.offchain_patterns import ALL_OFFCHAIN_PATTERNS

# Hard ceiling (seconds) any single pattern is allowed to run against one
# input. If a pathological input causes a pattern to exceed this, that match
# attempt is abandoned and scanning continues with the next pattern rather
# than hanging the whole app.
REGEX_TIMEOUT_SECONDS = 2


class VulnerabilityScanner:
    """
    Scanner for on-chain Solidity bridge contracts.
    """

    def __init__(self):
        self.patterns = ALL_PATTERNS
        self.findings = []

    def scan_contract(self, contract_code: str) -> Dict:
        """
        Main function to scan a smart contract

        Args:
            contract_code (str): The Solidity source code to analyze

        Returns:
            Dict: Contains vulnerabilities found, risk score, and summary
        """
        self.findings = []

        # Clean the code (remove comments)
        cleaned_code = self._clean_code(contract_code)

        # Scan for each vulnerability category
        for category_name, category_patterns in self.patterns.items():
            category_findings = self._scan_category(cleaned_code, category_name, category_patterns)
            self.findings.extend(category_findings)

        # Calculate risk score
        risk_score = self._calculate_risk_score()

        # Generate summary
        summary = self._generate_summary()

        return {
            "language": "solidity",
            "language_info": {
                "name": "Solidity",
                "description": "Smart contract language for Ethereum bridges",
                "file_extension": ".sol",
                "icon": "⛓️"
            },
            "vulnerabilities": self.findings,
            "risk_score": risk_score,
            "risk_level": self._get_risk_level(risk_score),
            "summary": summary,
            "total_issues": len(self.findings)
        }

    def _clean_code(self, code: str) -> str:
        """
        Remove comments and extra whitespace from Solidity code
        """
        code = re.sub(r'//.*', '', code)
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        return code

    def _scan_category(self, code: str, category_name: str, category_patterns: Dict) -> List[Dict]:
        """
        Scan for vulnerabilities in a specific category
        """
        findings = []

        for vuln_name, vuln_data in category_patterns.items():
            for pattern in vuln_data["patterns"]:
                matches = re.finditer(pattern, code, re.MULTILINE | re.DOTALL)

                for match in matches:
                    line_number = code[:match.start()].count('\n') + 1
                    snippet = self._extract_snippet(code, match.start(), match.end())

                    finding = {
                        "category": category_name.replace("_", " ").title(),
                        "vulnerability": vuln_name.replace("_", " ").title(),
                        "description": vuln_data["description"],
                        "severity": vuln_data["severity"],
                        "explanation": vuln_data["explanation"],
                        "line_number": line_number,
                        "code_snippet": snippet
                    }

                    findings.append(finding)

        return findings

    def _extract_snippet(self, code: str, start: int, end: int, context_lines: int = 2) -> str:
        """
        Extract a code snippet with surrounding context
        """
        lines = code.split('\n')
        start_line = code[:start].count('\n')
        end_line = code[:end].count('\n')

        snippet_start = max(0, start_line - context_lines)
        snippet_end = min(len(lines), end_line + context_lines + 1)

        snippet_lines = lines[snippet_start:snippet_end]
        return '\n'.join(snippet_lines)

    def _calculate_risk_score(self) -> int:
        """
        Calculate overall risk score based on found vulnerabilities
        """
        total_score = 0

        for finding in self.findings:
            severity = finding["severity"]
            total_score += SEVERITY_WEIGHTS.get(severity, 0)

        return min(total_score, 100)

    def _get_risk_level(self, score: int) -> str:
        """
        Convert numeric risk score to risk level
        """
        if score >= 81:
            return "CRITICAL"
        elif score >= 51:
            return "HIGH"
        elif score >= 21:
            return "MEDIUM"
        else:
            return "LOW"

    def _generate_summary(self) -> Dict:
        """
        Generate a summary of findings by category and severity
        """
        summary = {
            "by_category": {},
            "by_severity": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0
            }
        }

        for finding in self.findings:
            category = finding["category"]
            if category not in summary["by_category"]:
                summary["by_category"][category] = 0
            summary["by_category"][category] += 1

            severity = finding["severity"]
            summary["by_severity"][severity] += 1

        return summary


class OffchainScanner(VulnerabilityScanner):
    """
    Scanner for off-chain bridge infrastructure code
    (relayers, validators, oracles) written in Python or Go.

    Reuses all the scoring/reporting logic from VulnerabilityScanner,
    but scans against ALL_OFFCHAIN_PATTERNS and strips comment styles
    used by Python (#) and Go (// and /* */).
    """

    def __init__(self):
        super().__init__()
        self.patterns = ALL_OFFCHAIN_PATTERNS

    def scan_contract(self, contract_code: str) -> Dict:
        results = super().scan_contract(contract_code)
        results["language"] = "offchain"
        results["language_info"] = {
            "name": "Off-Chain (Python / Go)",
            "description": "Relayer, validator, and oracle infrastructure code",
            "file_extension": ".py / .go",
            "icon": "🛰️"
        }
        return results

    def _clean_code(self, code: str) -> str:
        code = re.sub(r'#.*', '', code)
        code = re.sub(r'//.*', '', code)
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        return code


def format_report(scan_results: Dict) -> str:
    """
    Format scan results into a readable report
    """
    report = []
    report.append("=" * 70)

    lang_info = scan_results.get("language_info", {})
    lang_name = lang_info.get("name", "Unknown")
    lang_icon = lang_info.get("icon", "")

    report.append("BRIDGE SECURITY SCANNER - VULNERABILITY REPORT")
    report.append(f"Scope: {lang_icon} {lang_name}")
    report.append("=" * 70)
    report.append("")

    risk_score = scan_results["risk_score"]
    risk_level = scan_results["risk_level"]
    report.append(f"OVERALL RISK SCORE: {risk_score}/100 ({risk_level})")
    report.append(f"TOTAL ISSUES FOUND: {scan_results['total_issues']}")
    report.append("")

    report.append("ISSUES BY SEVERITY:")
    for severity, count in scan_results["summary"]["by_severity"].items():
        if count > 0:
            report.append(f"  {severity}: {count}")
    report.append("")

    if scan_results["summary"]["by_category"]:
        report.append("ISSUES BY CATEGORY:")
        for category, count in scan_results["summary"]["by_category"].items():
            report.append(f"  {category}: {count}")
        report.append("")

    if scan_results["vulnerabilities"]:
        report.append("=" * 70)
        report.append("DETAILED FINDINGS:")
        report.append("=" * 70)

        for i, vuln in enumerate(scan_results["vulnerabilities"], 1):
            report.append("")
            report.append(f"[{i}] {vuln['vulnerability']} ({vuln['severity']})")
            report.append(f"    Category: {vuln['category']}")
            report.append(f"    Line: {vuln['line_number']}")
            report.append(f"    Description: {vuln['description']}")
            report.append(f"    Explanation: {vuln['explanation']}")
            report.append(f"    Code:")
            for line in vuln['code_snippet'].split('\n'):
                report.append(f"        {line}")
    else:
        report.append("No vulnerabilities detected! ✓")

    report.append("")
    report.append("=" * 70)

    return '\n'.join(report)


# Test code - you can run this file directly to test
if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("TESTING BRIDGE SECURITY SCANNER")
    print("=" * 70 + "\n")

    print("TEST 1: On-Chain Solidity")
    print("-" * 70)
    solidity_code = """
    pragma solidity ^0.6.0;

    contract VulnerableBridge {
        mapping(address => uint256) public balances;

        function deposit() public payable {
            balances[msg.sender] += msg.value;
        }

        function withdraw(uint256 amount) public {
            msg.sender.call{value: amount}("");
            balances[msg.sender] -= amount;
        }
    }
    """
    scanner = VulnerabilityScanner()
    results = scanner.scan_contract(solidity_code)
    print(format_report(results))
    print("\n")

    print("TEST 2: Off-Chain Relayer (Python)")
    print("-" * 70)
    relayer_code = """
    private_key = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"

    def relay_withdrawal(data):
        signatures = data["signatures"]
        if len(signatures) >= required_validators:
            submit_to_chain(data)
    """
    offchain_scanner = OffchainScanner()
    results = offchain_scanner.scan_contract(relayer_code)
    print(format_report(results))