"""
Bridge Security Scanner - Main Engine (Multi-Language Support)
This module analyzes smart contracts and code for security vulnerabilities
"""

import re
from typing import Dict, List, Tuple
import sys
import os

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from utils.language_detector import LanguageDetector
from utils.multi_language_scanner import MultiLanguageScanner
from data.vulnerability_patterns import ALL_PATTERNS, SEVERITY_WEIGHTS


class VulnerabilityScanner:
    """
    Main scanner class that analyzes code for vulnerabilities
    Now supports: Solidity, C, Java, Python
    """
    
    def __init__(self):
        self.patterns = ALL_PATTERNS
        self.findings = []
        self.multi_scanner = MultiLanguageScanner()
        self.language_detector = LanguageDetector()
        
    def scan_contract(self, contract_code: str) -> Dict:
        """
        Main function to scan code (any supported language)
        
        Args:
            contract_code (str): The source code to analyze
            
        Returns:
            Dict: Contains vulnerabilities found, risk score, and summary
        """
        # Use multi-language scanner
        results = self.multi_scanner.scan_code(contract_code)
        
        # If unknown language, try legacy Solidity-only scan
        if results.get("language") == "unknown":
            return self._legacy_solidity_scan(contract_code)
        
        return results
    
    def _legacy_solidity_scan(self, contract_code: str) -> Dict:
        """
        Legacy Solidity-only scanning (backwards compatibility)
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
                "description": "Smart contract language for Ethereum",
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
        Remove comments and extra whitespace from code
        """
        # Remove single-line comments
        code = re.sub(r'//.*', '', code)
        # Remove multi-line comments
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        # Remove Python comments
        code = re.sub(r'#.*', '', code)
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
                    # Get line number
                    line_number = code[:match.start()].count('\n') + 1
                    
                    # Extract the vulnerable code snippet
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
        
        # Get context lines
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
        
        # Normalize to 0-100 scale (cap at 100)
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
            # Count by category
            category = finding["category"]
            if category not in summary["by_category"]:
                summary["by_category"][category] = 0
            summary["by_category"][category] += 1
            
            # Count by severity
            severity = finding["severity"]
            summary["by_severity"][severity] += 1
        
        return summary


def format_report(scan_results: Dict) -> str:
    """
    Format scan results into a readable report
    """
    report = []
    report.append("=" * 70)
    
    # Language info
    lang_info = scan_results.get("language_info", {})
    lang_name = lang_info.get("name", "Unknown")
    lang_icon = lang_info.get("icon", "")
    
    report.append(f"SECURITY SCANNER - VULNERABILITY REPORT")
    report.append(f"Language: {lang_icon} {lang_name}")
    report.append("=" * 70)
    report.append("")
    
    # Risk Score
    risk_score = scan_results["risk_score"]
    risk_level = scan_results["risk_level"]
    report.append(f"OVERALL RISK SCORE: {risk_score}/100 ({risk_level})")
    report.append(f"TOTAL ISSUES FOUND: {scan_results['total_issues']}")
    report.append("")
    
    # Summary by Severity
    report.append("ISSUES BY SEVERITY:")
    for severity, count in scan_results["summary"]["by_severity"].items():
        if count > 0:
            report.append(f"  {severity}: {count}")
    report.append("")
    
    # Summary by Category
    if scan_results["summary"]["by_category"]:
        report.append("ISSUES BY CATEGORY:")
        for category, count in scan_results["summary"]["by_category"].items():
            report.append(f"  {category}: {count}")
        report.append("")
    
    # Detailed Findings
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


# Example usage
if __name__ == "__main__":
    # Test with multiple languages
    
    print("\n" + "="*70)
    print("TESTING MULTI-LANGUAGE SCANNER")
    print("="*70 + "\n")
    
    # Test 1: Solidity
    print("TEST 1: Solidity Code")
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
    
    # Test 2: C Code
    print("TEST 2: C Code")
    print("-" * 70)
    c_code = """
    #include <stdio.h>
    #include <string.h>
    
    int main() {
        char buffer[10];
        gets(buffer);
        strcpy(buffer, "Hello");
        printf(buffer);
        return 0;
    }
    """
    
    results = scanner.scan_contract(c_code)
    print(format_report(results))
    print("\n")
    
    # Test 3: Python Code
    print("TEST 3: Python Code")
    print("-" * 70)
    python_code = """
    import pickle
    import os
    
    password = "admin123"
    
    def unsafe_function(user_input):
        eval(user_input)
        data = pickle.loads(user_input)
        os.system("ls " + user_input)
    """
    
    results = scanner.scan_contract(python_code)
    print(format_report(results))
    print("\n")
    
    # Test 4: Java Code
    print("TEST 4: Java Code")
    print("-" * 70)
    java_code = """
    import java.sql.*;
    import java.security.MessageDigest;
    
    public class Vulnerable {
        String password = "secret123";
        
        public void queryDatabase(String userInput) throws Exception {
            Statement stmt = connection.createStatement();
            String query = "SELECT * FROM users WHERE name = '" + userInput + "'";
            stmt.executeQuery(query);
            
            MessageDigest md = MessageDigest.getInstance("MD5");
        }
    }
    """
    
    results = scanner.scan_contract(java_code)
    print(format_report(results))