"""
Bridge Security Scanner - Web Interface
Streamlit app for analyzing cross-chain bridge security, covering both on-chain
(Solidity) and off-chain (relayer/validator) code, with an incident taxonomy and a
live benchmark.
"""

from pathlib import Path

import streamlit as st

from scanner import VulnerabilityScanner, OffchainScanner, merge_scan_results, format_report
from utils.slither_integration import scan_with_slither, SlitherUnavailableError
from data.incidents import INCIDENTS, CATEGORIES, coverage_summary
from evaluation.evaluate import run_evaluation

BASE_DIR = Path(__file__).resolve().parent
MAX_CHARS = 100_000

ONCHAIN_EXAMPLES = {
    "Vulnerable bridge": "examples/vulnerable_bridge.sol",
    "Secure bridge": "examples/secure_bridge.sol",
    "Ronin-style (vulnerable)": "examples/ronin_style_vulnerable.sol",
    "Ronin-style (secure)": "examples/ronin_style_secure.sol",
}
OFFCHAIN_EXAMPLES = {
    "Vulnerable relayer": "examples/offchain/vulnerable_relayer.py",
    "Secure relayer": "examples/offchain/secure_relayer.py",
}
SEVERITY_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
SOURCE_BADGE = {"pattern": "🧩 pattern engine", "slither": "🔬 Slither"}


def read_example(relative_path: str) -> str:
    return (BASE_DIR / relative_path).read_text(encoding="utf-8")


# -------------------- PAGE CONFIG --------------------
st.set_page_config(page_title="Bridge Security Scanner", page_icon="🔒", layout="wide")

if "code_input" not in st.session_state:
    st.session_state["code_input"] = (
        "// Paste your Solidity contract here\npragma solidity ^0.8.0;\n\ncontract MyBridge {\n    // Your code here\n}\n"
    )
if "results" not in st.session_state:
    st.session_state["results"] = None

# -------------------- HEADER --------------------
st.title("🔒 Bridge Security Scanner")
st.markdown(
    "Analyze cross-chain bridge security across **both halves of the stack**: on-chain Solidity "
    "contracts and the off-chain relayer/validator services that support them. "
    "Detects vulnerability classes behind **$1.92B** in bridge losses."
)

tab_scan, tab_taxonomy, tab_eval = st.tabs(["🔍 Scanner", "📚 Incident Taxonomy", "📊 Evaluation"])

# ======================================================================
# TAB 1 - SCANNER
# ======================================================================
with tab_scan:
    scan_mode = st.radio(
        "Scan mode:",
        ["On-Chain (Solidity)", "Off-Chain (Relayer / Validator — Python, Go)"],
        horizontal=True,
    )
    is_offchain = scan_mode.startswith("Off-Chain")

    with st.sidebar:
        st.header("About")
        if is_offchain:
            st.info(
                "**Off-chain categories**\n\n"
                "- 🔑 Key & Secret Exposure\n- ✍️ Signature & Threshold Validation\n"
                "- 🌐 Network & Service Exposure\n- ⚙️ Unsafe Execution"
            )
            examples = OFFCHAIN_EXAMPLES
        else:
            st.info(
                "**On-chain categories**\n\n"
                "- 🚨 Verification Bypass\n- ⚠️ Asymmetric Processing\n"
                "- 🔑 Key Theft\n- 💥 Diverse Exploits"
            )
            examples = ONCHAIN_EXAMPLES

        st.header("Examples")
        chosen = st.selectbox("Choose an example", list(examples.keys()))
        if st.button("Load example", width="stretch"):
            st.session_state["code_input"] = read_example(examples[chosen])

    col1, col2 = st.columns([1, 1])

    with col1:
        st.subheader("📝 Relayer / Validator Code" if is_offchain else "📝 Smart Contract Code")
        contract_code = st.text_area(
            "Paste relayer/validator source (Python or Go):" if is_offchain else "Paste Solidity contract code:",
            height=420,
            key="code_input",
        )

        if st.button("🔍 Scan for Vulnerabilities", type="primary", width="stretch"):
            if not contract_code.strip():
                st.warning("Please enter code first!")
            elif len(contract_code) > MAX_CHARS:
                st.error(f"Input too large ({len(contract_code):,} chars). Limit is {MAX_CHARS:,} chars.")
            else:
                with st.spinner("Analyzing code..."):
                    if is_offchain:
                        st.session_state["results"] = OffchainScanner().scan_contract(contract_code)
                    else:
                        pattern_result = VulnerabilityScanner().scan_contract(contract_code)
                        try:
                            slither_result = scan_with_slither(contract_code)
                            st.session_state["results"] = merge_scan_results(pattern_result, slither_result)
                        except SlitherUnavailableError:
                            pattern_result["engine_error"] = (
                                "Slither is not installed - showing pattern-engine results only."
                            )
                            st.session_state["results"] = pattern_result
                st.success("Scan complete!")

    with col2:
        st.subheader("📊 Scan Results")
        results = st.session_state["results"]

        if results is None:
            st.info("👈 Enter code and click 'Scan' to see results")
        else:
            lang_info = results.get("language_info", {})
            if lang_info:
                st.info(f"{lang_info.get('icon', '')} **Scope:** {lang_info.get('name', 'Unknown')}")
            if results.get("engine_error"):
                st.warning(results["engine_error"])

            level = results["risk_level"]
            m1, m2, m3 = st.columns(3)
            m1.metric("Risk Score", f"{results['risk_score']}/100")
            m2.metric("Risk Level", f"{SEVERITY_ICON.get(level, '')} {level}")
            m3.metric("Total Issues", results["total_issues"])
            st.progress(min(results["risk_score"], 100) / 100)

            st.markdown("### Issues by Severity")
            sev_cols = st.columns(4)
            for col, sev in zip(sev_cols, ["CRITICAL", "HIGH", "MEDIUM", "LOW"]):
                col.metric(f"{SEVERITY_ICON[sev]} {sev}", results["summary"]["by_severity"][sev])

            if results["summary"]["by_category"]:
                st.markdown("### Issues by Category")
                for category, count in results["summary"]["by_category"].items():
                    st.write(f"**{category}:** {count} issue(s)")

            st.markdown("### 🔍 Detailed Findings")
            if results["vulnerabilities"]:
                for i, vuln in enumerate(results["vulnerabilities"], 1):
                    header = f"[{i}] {SEVERITY_ICON.get(vuln['severity'], '')} {vuln['vulnerability']} - {vuln['severity']}"
                    with st.expander(header, expanded=(i == 1)):
                        st.markdown(f"**Category:** {vuln['category']}  |  **Line:** {vuln['line_number']}")
                        badge = SOURCE_BADGE.get(vuln.get("source", "pattern"), "pattern engine")
                        if vuln.get("confirmed_by") == "slither":
                            badge += " + 🔬 Slither (confirmed by both engines)"
                        st.markdown(f"**Detected by:** {badge}")
                        st.markdown(f"**Description:** {vuln['description']}")
                        st.markdown(f"**Why it matters:** {vuln['explanation']}")
                        if vuln.get("remediation"):
                            st.success(f"**How to fix:** {vuln['remediation']}")
                        st.code(vuln["code_snippet"], language="python" if is_offchain else "solidity")
            else:
                st.success("✅ No vulnerabilities detected!")

            st.markdown("### 📥 Download Report")
            st.download_button(
                label="Download Text Report",
                data=format_report(results),
                file_name="vulnerability_report.txt",
                mime="text/plain",
            )

# ======================================================================
# TAB 2 - INCIDENT TAXONOMY
# ======================================================================
with tab_taxonomy:
    summary = coverage_summary()
    st.subheader("Cross-chain bridge incident taxonomy")
    st.caption(
        "Each real incident is mapped to a vulnerability category and to the detectors in this tool. "
        "Loss figures are approximate; coverage levels are deliberately conservative."
    )
    t1, t2, t3, t4 = st.columns(4)
    t1.metric("Incidents mapped", summary["total"])
    t2.metric("Losses covered (approx.)", f"${summary['loss_total_m'] / 1000:.2f}B")
    t3.metric("Root cause detected", summary["by_coverage"].get("Detected", 0))
    t4.metric("Partial / out of scope", summary["by_coverage"].get("Partial", 0) + summary["by_coverage"].get("Out of scope", 0))

    pick = st.selectbox("Filter by category", ["All"] + CATEGORIES)
    rows = [
        {
            "Incident": inc["name"],
            "Year": inc["year"],
            "Loss ($M)": inc["loss_usd_m"],
            "Category": inc["category"],
            "Root cause": inc["root_cause"],
            "Detectors": ", ".join(inc["detectors"]) or "-",
            "Coverage": inc["coverage"],
        }
        for inc in INCIDENTS
        if pick == "All" or inc["category"] == pick
    ]
    st.dataframe(rows, width="stretch", hide_index=True)
    st.caption(
        "Detected = a detector targets the root-cause pattern. Partial = the vulnerability class or adjacent "
        "hygiene is covered, not the exact root cause (e.g. non-Solidity code, off-chain key compromise). "
        "Out of scope = not detectable by static analysis."
    )

# ======================================================================
# TAB 3 - EVALUATION
# ======================================================================
with tab_eval:
    st.subheader("Benchmark: precision, recall and speed")
    st.caption(
        "Runs the pattern + function-rule engine over a labeled set of vulnerable and safe contracts. "
        "The contracts were written by the project author, so treat this as a regression benchmark, "
        "not an independent accuracy claim."
    )
    if st.button("Run benchmark", type="primary"):
        st.session_state["benchmark"] = run_evaluation()

    bench = st.session_state.get("benchmark")
    if bench:
        b1, b2, b3, b4, b5 = st.columns(5)
        b1.metric("Contracts", bench["contracts"])
        b2.metric("Precision", bench["precision"])
        b3.metric("Recall", bench["recall"])
        b4.metric("F1", bench["f1"])
        b5.metric("Avg scan time", f"{bench['avg_ms']} ms")
        st.write(f"Confusion matrix: **{bench['confusion']}**  |  Expected-detector hit rate: **{bench['detector_hit_rate']}**")
        st.dataframe(
            [
                {
                    "Contract": r["contract"],
                    "Label": r["label"],
                    "Score": r["risk_score"],
                    "Detectors fired": ", ".join(r["findings"]) or "-",
                    "Correct": "✅" if r["correct"] else "❌",
                    "ms": r["ms"],
                }
                for r in bench["rows"]
            ],
            width="stretch",
            hide_index=True,
        )

# -------------------- FOOTER --------------------
st.markdown("---")
st.caption("Bridge Security Scanner — on-chain pattern + function-level analysis, Slither AST analysis, and off-chain relayer checks.")
