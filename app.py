"""
Bridge Security Scanner - Web Interface
Streamlit app for analyzing cross-chain bridge security,
covering both on-chain (Solidity) and off-chain (relayer/validator) code.
"""

import streamlit as st
from scanner import VulnerabilityScanner, OffchainScanner, format_report

# -------------------- PAGE CONFIG --------------------
st.set_page_config(
    page_title="Bridge Security Scanner",
    page_icon="🔒",
    layout="wide"
)

# -------------------- SESSION STATE INIT --------------------
if "code_input" not in st.session_state:
    st.session_state["code_input"] = """// Paste your Solidity contract here
pragma solidity ^0.8.0;

contract MyBridge {
    // Your code here
}
"""

if "results" not in st.session_state:
    st.session_state["results"] = None

# -------------------- TITLE --------------------
st.title("🔒 Bridge Security Scanner")

st.markdown("""
Analyze cross-chain bridge security across **both halves of the stack**: on-chain Solidity
contracts and the off-chain relayer/validator services that support them.
This tool detects vulnerability categories that have caused **$1.92B in losses**.
""")

# -------------------- MODE SELECTOR --------------------
scan_mode = st.radio(
    "Scan mode:",
    ["On-Chain (Solidity)", "Off-Chain (Relayer / Validator — Python, Go)"],
    horizontal=True
)
is_offchain = scan_mode.startswith("Off-Chain")

# -------------------- SIDEBAR --------------------
with st.sidebar:
    st.header("About")

    if is_offchain:
        st.info("""
        **Off-Chain Vulnerability Categories:**
        - 🔑 Key & Secret Exposure
        - ✍️ Signature & Threshold Validation
        - 🌐 Network & Service Exposure
        - ⚙️ Unsafe Execution
        """)

        st.header("Example Scripts")
        if st.button("Load Vulnerable Relayer Example", use_container_width=True):
            with open("examples/offchain/vulnerable_relayer.py", "r") as f:
                st.session_state["code_input"] = f.read()
    else:
        st.info("""
        **On-Chain Vulnerability Categories:**
        - 🚨 Verification Bypass
        - ⚠️ Asymmetric Processing
        - 🔑 Key Theft
        - 💥 Diverse Exploits
        """)

        st.header("Example Contracts")

        if st.button("Load Vulnerable Example", use_container_width=True):
            with open("examples/vulnerable_bridge.sol", "r") as f:
                st.session_state["code_input"] = f.read()

        if st.button("Load Secure Example", use_container_width=True):
            with open("examples/secure_bridge.sol", "r") as f:
                st.session_state["code_input"] = f.read()

# -------------------- MAIN CONTENT --------------------
col1, col2 = st.columns([1, 1])

# -------------------- LEFT COLUMN (CODE INPUT) --------------------
with col1:
    label = "📝 Relayer / Validator Code" if is_offchain else "📝 Smart Contract Code"
    st.subheader(label)

    placeholder = "Paste relayer/validator source (Python or Go):" if is_offchain else "Paste Solidity contract code:"
    contract_code = st.text_area(
        placeholder,
        height=400,
        key="code_input"
    )

    # Cap input size to avoid pathological regex scan times on huge pastes
    MAX_CHARS = 100_000

    if st.button("🔍 Scan for Vulnerabilities", type="primary", use_container_width=True):
        if not contract_code.strip():
            st.warning("Please enter code first!")
        elif len(contract_code) > MAX_CHARS:
            st.error(f"Input too large ({len(contract_code):,} chars). Limit is {MAX_CHARS:,} chars.")
        else:
            with st.spinner("Analyzing code..."):
                scanner = OffchainScanner() if is_offchain else VulnerabilityScanner()
                st.session_state["results"] = scanner.scan_contract(contract_code)
            st.success("Scan complete!")

# -------------------- RIGHT COLUMN (RESULTS) --------------------
with col2:
    st.subheader("📊 Scan Results")

    if st.session_state["results"] is not None:
        results = st.session_state["results"]

        lang_info = results.get("language_info", {})
        if lang_info:
            st.info(f"{lang_info.get('icon', '')} **Scope:** {lang_info.get('name', 'Unknown')}")

        risk_score = results["risk_score"]
        risk_level = results["risk_level"]

        if risk_level == "CRITICAL":
            color = "🔴"
        elif risk_level == "HIGH":
            color = "🟠"
        elif risk_level == "MEDIUM":
            color = "🟡"
        else:
            color = "🟢"

        metric_col1, metric_col2, metric_col3 = st.columns(3)

        with metric_col1:
            st.metric("Risk Score", f"{risk_score}/100")

        with metric_col2:
            st.metric("Risk Level", f"{color} {risk_level}")

        with metric_col3:
            st.metric("Total Issues", results["total_issues"])

        st.markdown("### Issues by Severity")

        severity_cols = st.columns(4)
        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        colors = ["🔴", "🟠", "🟡", "🟢"]

        for col, sev, colr in zip(severity_cols, severities, colors):
            count = results["summary"]["by_severity"][sev]
            col.metric(f"{colr} {sev}", count)

        if results["summary"]["by_category"]:
            st.markdown("### Issues by Category")
            for category, count in results["summary"]["by_category"].items():
                st.write(f"**{category}:** {count} issue(s)")

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
                    st.code(vuln["code_snippet"], language="python" if is_offchain else "solidity")
        else:
            st.success("✅ No vulnerabilities detected!")

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

# -------------------- FOOTER --------------------
st.markdown("---")
st.markdown("""
<div style='text-align: center'>
    <p>Built to address the $1.92B cross-chain bridge security problem</p>
    <p>🔒 Bridge Security Scanner — On-Chain + Off-Chain Coverage</p>
</div>
""", unsafe_allow_html=True)