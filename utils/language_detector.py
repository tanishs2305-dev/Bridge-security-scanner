"""
Language Detection Module
Automatically detects programming language from code
"""

import re


class LanguageDetector:
    """
    Detects programming language based on syntax patterns
    """
    
    @staticmethod
    def detect(code: str) -> str:
        """
        Detect the programming language of the given code
        
        Args:
            code (str): Source code to analyze
            
        Returns:
            str: Detected language ('solidity', 'c', 'java', 'python', 'unknown')
        """
        code = code.strip()
        
        # Solidity detection (highest priority for our tool)
        if re.search(r'pragma\s+solidity', code, re.IGNORECASE):
            return 'solidity'
        if re.search(r'contract\s+\w+\s*\{', code):
            return 'solidity'
        
        # Python detection
        if re.search(r'def\s+\w+\s*\(', code):
            if not re.search(r'\bpublic\b|\bprivate\b|\bprotected\b', code):
                return 'python'
        if re.search(r'import\s+\w+|from\s+\w+\s+import', code):
            return 'python'
        if re.search(r'print\s*\(', code):
            return 'python'
        
        # Java detection
        if re.search(r'public\s+class\s+\w+', code):
            return 'java'
        if re.search(r'public\s+static\s+void\s+main', code):
            return 'java'
        if re.search(r'System\.out\.println', code):
            return 'java'
        
        # C detection
        if re.search(r'#include\s*<\w+\.h>', code):
            return 'c'
        if re.search(r'int\s+main\s*\(', code):
            if not re.search(r'public\s+static', code):  # Distinguish from Java
                return 'c'
        if re.search(r'printf\s*\(|scanf\s*\(', code):
            return 'c'
        
        return 'unknown'
    
    @staticmethod
    def get_language_info(language: str) -> dict:
        """
        Get information about a programming language
        
        Args:
            language (str): Language identifier
            
        Returns:
            dict: Language information
        """
        info = {
            'solidity': {
                'name': 'Solidity',
                'description': 'Smart contract language for Ethereum',
                'file_extension': '.sol',
                'icon': '⛓️'
            },
            'python': {
                'name': 'Python',
                'description': 'General-purpose programming language',
                'file_extension': '.py',
                'icon': '🐍'
            },
            'java': {
                'name': 'Java',
                'description': 'Object-oriented programming language',
                'file_extension': '.java',
                'icon': '☕'
            },
            'c': {
                'name': 'C',
                'description': 'Systems programming language',
                'file_extension': '.c',
                'icon': '⚙️'
            },
            'unknown': {
                'name': 'Unknown',
                'description': 'Language not recognized',
                'file_extension': '',
                'icon': '❓'
            }
        }
        
        return info.get(language, info['unknown'])


# Test the detector
if __name__ == "__main__":
    test_codes = {
        'solidity': 'pragma solidity ^0.8.0; contract Test {}',
        'python': 'def hello(): print("Hello")',
        'java': 'public class Test { public static void main(String[] args) {} }',
        'c': '#include <stdio.h>\nint main() { printf("Hello"); }'
    }
    
    detector = LanguageDetector()
    
    for expected, code in test_codes.items():
        detected = detector.detect(code)
        print(f"Expected: {expected}, Detected: {detected}, Match: {expected == detected}")