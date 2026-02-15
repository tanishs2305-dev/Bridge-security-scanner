"""
Bridge Security Scanner - Web Interface
Streamlit app for analyzing smart contracts
"""

import streamlit as st
from scanner import VulnerabilityScanner, format_report

# -------------------- PAGE CONFIG --------------------
st.set_page_config(
    page_title="Bridge Security Scanner",
    page_icon="🔒",
    layout="wide"
)

# -------------------- SESSION STATE INIT --------------------
if "contract_code" not in st.session_state:
    st.session_state.contract_code = """// Paste your Solidity contract here
pragma solidity ^0.8.0;

contract MyBridge {
    // Your code here
}
"""

if "results" not in st.session_state:
    st.session_state.results = None

# -------------------- TITLE --------------------
st.title("🔒 Bridge Security Scanner")

st.markdown("""
Analyze Solidity smart contracts for security vulnerabilities in cross-chain bridges.  
This tool detects 4 major categories of vulnerabilities that have caused **$1.92B in losses**.
""")

# -------------------- SIDEBAR --------------------
with st.sidebar:
    st.header("About")
    st.info("""
    **Vulnerability Categories:**
    - 🚨 Verification Bypass
    - ⚠️ Asymmetric Processing
    - 🔑 Key Theft
    - 💥 Diverse Exploits
    """)

    st.header("Example Contracts")

    if st.button("Load Vulnerable Example"):
        with open("examples/vulnerable_bridge.sol", "r") as f:
            st.session_state.contract_code = f.read()

    if st.button("Load Secure Example"):
        with open("examples/secure_bridge.sol", "r") as f:
            st.session_state.contract_code = f.read()

# -------------------- MAIN CONTENT --------------------
col1, col2 = st.columns([1, 1])

# -------------------- LEFT COLUMN (CODE INPUT) --------------------
with col1:
    st.subheader("📝 Smart Contract Code")

    contract_code = st.text_area(
        "Paste Solidity contract code:",
        height=400,
        key="contract_code"
    )

    if st.button("🔍 Scan for Vulnerabilities", type="primary", use_container_width=True):
        if contract_code.strip():
            with st.spinner("Analyzing contract..."):
                scanner = VulnerabilityScanner()
                st.session_state.results = scanner.scan_contract(contract_code)
            st.success("Scan complete!")
        else:
            st.warning("Please enter contract code first!")

# -------------------- RIGHT COLUMN (RESULTS) --------------------
with col2:
    st.subheader("📊 Scan Results")

    if st.session_state.results is not None:
        results = st.session_state.results

        # Risk score display
        risk_score = results["risk_score"]
        risk_level = results["risk_level"]

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
            st.metric("Total Issues", results["total_issues"])

        # Severity breakdown
        st.markdown("### Issues by Severity")

        severity_cols = st.columns(4)
        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        colors = ["🔴", "🟠", "🟡", "🟢"]

        for col, sev, colr in zip(severity_cols, severities, colors):
            count = results["summary"]["by_severity"][sev]
            col.metric(f"{colr} {sev}", count)

        # Category breakdown
        if results["summary"]["by_category"]:
            st.markdown("### Issues by Category")
            for category, count in results["summary"]["by_category"].items():
                st.write(f"**{category}:** {count} issue(s)")

        # Detailed findings
        st.markdown("### 🔍 Detailed Findings")

        if results["vulnerabilities"]:
            for i, vuln in enumerate(results["vulnerabilities"], 1):
                with st.expander(
                    f"[{i}] {vuln['vulnerability']} - {vuln['severity']}",
                    expanded=(i == 1)
                ):
                    st.markdown(f"**Category:** {vuln['category']}")
                    st.markdown(f"**Line:** {vuln['line_number']}")
                    st.markdown(f"**Description:** {vuln['description']}")
                    st.markdown(f"**Explanation:** {vuln['explanation']}")
                    st.code(vuln["code_snippet"], language="solidity")
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
        st.info("👈 Enter contract code and click 'Scan' to see results")

# -------------------- FOOTER --------------------
st.markdown("---")
st.markdown("""
<div style='text-align: center'>
    <p>Built to address the $1.92B cross-chain bridge security problem</p>
    <p>🔒 Bridge Security Scanner v1.0</p>
</div>
""", unsafe_allow_html=True)