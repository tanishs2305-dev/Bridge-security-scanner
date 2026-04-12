"""
Bridge Security Scanner - Web Interface (Multi-Language Support)
Streamlit app for analyzing code in multiple languages
"""

import streamlit as st
from scanner import VulnerabilityScanner, format_report

# Page configuration
st.set_page_config(
    page_title="Bridge Security Scanner",
    page_icon="🔒",
    layout="wide"
)

# Initialize session state
if 'code_input' not in st.session_state:
    st.session_state['code_input'] = """// Paste your code here
// Supported languages: Solidity, C, Java, Python

pragma solidity ^0.8.0;

contract Example {
    // Your code here
}
"""

# Title and description
st.title(" Bridge Security Scanner")
st.markdown("""
Analyze code for security vulnerabilities in **Solidity, C, Java, and Python**.
Detects vulnerabilities that have caused **$1.92B in losses** in blockchain,
plus common security issues in other languages.
""")

# Sidebar with information
with st.sidebar:
    st.header("Supported Languages")
    st.info("""
    **⛓️ Solidity** - Smart contracts
    - Reentrancy attacks
    - Replay attacks
    - Bridge vulnerabilities

    **⚙️ C** - Systems programming
    - Buffer overflows
    - Memory leaks
    - Format string bugs

    **☕ Java** - Enterprise apps
    - SQL injection
    - Deserialization
    - Crypto issues

    **🐍 Python** - General purpose
    - Code injection
    - Unsafe deserialization
    - Hardcoded secrets
    """)

    st.header("Load Example Code")

    # Language selector
    lang_choice = st.radio(
        "Choose Language:",
        ["Solidity", "C", "Java", "Python"],
        key="lang_radio"
    )

    # Example selector
    example_choice = st.radio(
        "Choose Example:",
        ["Vulnerable", "Secure"],
        key="example_radio"
    )

    # Load button
    if st.button(" Load Example", use_container_width=True, type="primary"):

        # Solidity examples
        if lang_choice == "Solidity":
            if example_choice == "Vulnerable":
                st.session_state['code_input'] = """pragma solidity ^0.6.0;

contract VulnerableBridge {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }
}"""
            else:
                st.session_state['code_input'] = """pragma solidity ^0.8.0;

contract SecureBridge {
    mapping(address => uint256) public balances;
    mapping(uint256 => bool) public processedNonces;
    uint256 public nonce;

    function withdraw(uint256 amount, uint256 _nonce) public {
        require(!processedNonces[_nonce], "Already processed");
        require(balances[msg.sender] >= amount, "Insufficient");

        processedNonces[_nonce] = true;
        balances[msg.sender] -= amount;

        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Transfer failed");
    }
}"""

        # C examples
        elif lang_choice == "C":
            if example_choice == "Vulnerable":
                st.session_state['code_input'] = """#include 
#include 

int main() {
    char buffer[10];
    char password[] = "admin123";

    gets(buffer);
    strcpy(buffer, "Hello World!");
    sprintf(buffer, "User: %s", buffer);
    printf(buffer);

    return 0;
}"""
            else:
                st.session_state['code_input'] = """#include 
#include 

int main() {
    char buffer[100];

    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        snprintf(buffer, sizeof(buffer), "User: %s", buffer);
        printf("%s", buffer);
    }

    return 0;
}"""

        # Java examples
        elif lang_choice == "Java":
            if example_choice == "Vulnerable":
                st.session_state['code_input'] = """import java.sql.*;
import java.security.MessageDigest;

public class Vulnerable {
    String password = "secret123";

    public void query(String user) throws Exception {
        Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM users WHERE name = '" + user + "'";
        stmt.executeQuery(sql);

        MessageDigest md = MessageDigest.getInstance("MD5");
    }
}"""
            else:
                st.session_state['code_input'] = """import java.sql.*;
import java.security.MessageDigest;

public class Secure {
    public void query(String user) throws Exception {
        String sql = "SELECT * FROM users WHERE name = ?";
        PreparedStatement pstmt = conn.prepareStatement(sql);
        pstmt.setString(1, user);
        pstmt.executeQuery();

        MessageDigest md = MessageDigest.getInstance("SHA-256");
    }
}"""

        # Python examples
        else:
            if example_choice == "Vulnerable":
                st.session_state['code_input'] = """import pickle
import os

password = "admin123"
api_key = "sk-1234567890"

def unsafe(user_input):
    eval(user_input)
    data = pickle.loads(user_input)
    os.system("ls " + user_input)

    query = f"SELECT * FROM users WHERE name = '{user_input}'"
"""
            else:
                st.session_state['code_input'] = """import json
import subprocess
import hashlib

def safe(user_input):
    data = json.loads(user_input)
    subprocess.run(["ls", user_input], check=True)

    hashed = hashlib.sha256(user_input.encode()).hexdigest()
"""

        st.success(f"✅ Loaded {example_choice} {lang_choice} example!")

# Main content area
col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("📝 Source Code")

    # Code input - directly bound to session state
    contract_code = st.text_area(
        "Paste source code:",
        height=400,
        key="code_input"
    )

    # Scan button
    if st.button("🔍 Scan for Vulnerabilities", type="primary", use_container_width=True):
        if contract_code.strip():
            with st.spinner("Analyzing code..."):
                scanner = VulnerabilityScanner()
                results = st.session_state['results'] = scanner.scan_contract(contract_code)
                st.success("Scan complete!")
        else:
            st.warning("Please enter code first!")

with col2:
    st.subheader("📊 Scan Results")

    if 'results' in st.session_state:
        results = st.session_state['results']

        # Show detected language
        lang_info = results.get("language_info", {})
        if lang_info:
            st.info(f"{lang_info.get('icon', '')} **Detected Language:** {lang_info.get('name', 'Unknown')}")

        # Risk score display
        risk_score = results['risk_score']
        risk_level = results['risk_level']

        # Color based on risk level
        if risk_level == "CRITICAL":
            color = "🔴"
        elif risk_level == "HIGH":
            color = "🟠"
        elif risk_level == "MEDIUM":
            color = "🟡"
        else:
            color = "🟢"

        # Display metrics
        metric_col1, metric_col2, metric_col3 = st.columns(3)

        with metric_col1:
            st.metric("Risk Score", f"{risk_score}/100")

        with metric_col2:
            st.metric("Risk Level", f"{color} {risk_level}")

        with metric_col3:
            st.metric("Total Issues", results['total_issues'])

        # Severity breakdown
        st.markdown("### Issues by Severity")
        severity_cols = st.columns(4)

        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        colors = ["🔴", "🟠", "🟡", "🟢"]

        for col, sev, color_icon in zip(severity_cols, severities, colors):
            count = results['summary']['by_severity'][sev]
            col.metric(f"{color_icon} {sev}", count)

        # Category breakdown
        if results['summary']['by_category']:
            st.markdown("### Issues by Category")
            for category, count in results['summary']['by_category'].items():
                st.write(f"**{category}:** {count} issue(s)")

        # Detailed findings
        st.markdown("### 🔍 Detailed Findings")

        if results['vulnerabilities']:
            for i, vuln in enumerate(results['vulnerabilities'], 1):
                with st.expander(f"[{i}] {vuln['vulnerability']} - {vuln['severity']}", expanded=(i==1)):
                    st.markdown(f"**Category:** {vuln['category']}")
                    st.markdown(f"**Line:** {vuln['line_number']}")
                    st.markdown(f"**Description:** {vuln['description']}")
                    st.markdown(f"**Explanation:** {vuln['explanation']}")

                    lang = results.get('language', 'text')
                    if lang == 'solidity':
                        code_lang = 'solidity'
                    elif lang == 'c':
                        code_lang = 'c'
                    elif lang == 'java':
                        code_lang = 'java'
                    elif lang == 'python':
                        code_lang = 'python'
                    else:
                        code_lang = 'text'

                    st.code(vuln['code_snippet'], language=code_lang)
        else:
            st.success("✅ No vulnerabilities detected!")

        # Download report
        st.markdown("### 📥 Download Report")
        report_text = format_report(results)
        st.download_button(
            label="Download Text Report",
            data=report_text,
            file_name="vulnerability_report.txt",
            mime="text/plain"
        )
    else:
        st.info("👈 Enter code and click 'Scan' to see results")

# Footer
st.markdown("---")
st.markdown("""


    

Bridge Security Scanner - Multi-Language Support


    

🔒 Supports: Solidity, C, Java, Python




""", unsafe_allow_html=True)
