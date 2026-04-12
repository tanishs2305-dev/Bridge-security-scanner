"""
Multi-Language Vulnerability Scanner
Routes code to appropriate language-specific scanner
"""

import re
from typing import Dict, List
import sys
sys.path.append('..')

from utils.language_detector import LanguageDetector
from data.vulnerability_patterns import ALL_PATTERNS as SOLIDITY_PATTERNS, SEVERITY_WEIGHTS
from data.c_vulnerability_patterns import ALL_C_PATTERNS
from data.java_vulnerability_patterns import ALL_JAVA_PATTERNS
from data.python_vulnerability_patterns import ALL_PYTHON_PATTERNS


class MultiLanguageScanner:
    """
    Universal vulnerability scanner supporting multiple languages
    """
    
    def __init__(self):
        self.detector = LanguageDetector()
        self.patterns_map = {
            'solidity': SOLIDITY_PATTERNS,
            'c': ALL_C_PATTERNS,
            'java': ALL_JAVA_PATTERNS,
            'python': ALL_PYTHON_PATTERNS
        }
    
    def scan_code(self, code: str) -> Dict:
        """
        Scan code in any supported language
        
        Args:
            code (str): Source code to scan
            
        Returns:
            Dict: Scan results with language info
        """
        # Detect language
        language = self.detector.detect(code)
        
        if language == 'unknown':
            return {
                "language": "unknown",
                "language_info": self.detector.get_language_info('unknown'),
                "error": "Language not recognized. Supported: Solidity, C, Java, Python",
                "risk_score": 0,
                "vulnerabilities": []
            }
        
        # Get appropriate patterns
        patterns = self.patterns_map.get(language, {})
        
        # Scan with language-specific patterns
        findings = self._scan_with_patterns(code, patterns)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(findings)
        risk_level = self._get_risk_level(risk_score)
        
        # Generate summary
        summary = self._generate_summary(findings)
        
        return {
            "language": language,
            "language_info": self.detector.get_language_info(language),
            "vulnerabilities": findings,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "summary": summary,
            "total_issues": len(findings)
        }
    
    def _scan_with_patterns(self, code: str, patterns: Dict) -> List[Dict]:
        """
        Scan code with given patterns
        """
        findings = []
        
        # Clean code
        cleaned_code = self._clean_code(code)
        
        for category_name, category_patterns in patterns.items():
            for vuln_name, vuln_data in category_patterns.items():
                for pattern in vuln_data["patterns"]:
                    matches = re.finditer(pattern, cleaned_code, re.MULTILINE | re.DOTALL)
                    
                    for match in matches:
                        line_number = cleaned_code[:match.start()].count('\n') + 1
                        snippet = self._extract_snippet(cleaned_code, match.start(), match.end())
                        
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
    
    def _clean_code(self, code: str) -> str:
        """Remove comments"""
        # Remove C-style comments
        code = re.sub(r'//.*', '', code)
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        # Remove Python comments
        code = re.sub(r'#.*', '', code)
        return code
    
    def _extract_snippet(self, code: str, start: int, end: int, context_lines: int = 2) -> str:
        """Extract code snippet with context"""
        lines = code.split('\n')
        start_line = code[:start].count('\n')
        end_line = code[:end].count('\n')
        
        snippet_start = max(0, start_line - context_lines)
        snippet_end = min(len(lines), end_line + context_lines + 1)
        
        return '\n'.join(lines[snippet_start:snippet_end])
    
    def _calculate_risk_score(self, findings: List[Dict]) -> int:
        """Calculate risk score"""
        total = sum(SEVERITY_WEIGHTS.get(f["severity"], 0) for f in findings)
        return min(total, 100)
    
    def _get_risk_level(self, score: int) -> str:
        """Get risk level from score"""
        if score >= 81:
            return "CRITICAL"
        elif score >= 51:
            return "HIGH"
        elif score >= 21:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_summary(self, findings: List[Dict]) -> Dict:
        """Generate summary"""
        summary = {
            "by_category": {},
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        }
        
        for finding in findings:
            category = finding["category"]
            severity = finding["severity"]
            
            summary["by_category"][category] = summary["by_category"].get(category, 0) + 1
            summary["by_severity"][severity] += 1
        
        return summary