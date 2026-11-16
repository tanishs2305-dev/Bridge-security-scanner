"""
Write docs/TAXONOMY.md from data/incidents.py.

Run from the project root:   python -m evaluation.export_taxonomy
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data.incidents import INCIDENTS, coverage_summary


def build_markdown() -> str:
    summary = coverage_summary()
    lines = [
        "# Cross-chain bridge incident taxonomy",
        "",
        "Each incident is mapped to one of the four vulnerability categories and to the detectors in this",
        "project. Loss figures are approximate (USD millions) - verify against your cited sources.",
        "",
        f"**{summary['total']} incidents** | " + " | ".join(f"{k}: {v}" for k, v in summary["by_coverage"].items()),
        "",
        "| Incident | Year | Loss ($M) | Category | Root cause | Detectors | Coverage |",
        "|---|---|---|---|---|---|---|",
    ]
    for inc in INCIDENTS:
        loss = "n/a" if inc["loss_usd_m"] is None else inc["loss_usd_m"]
        det = ", ".join(inc["detectors"]) or "-"
        lines.append(
            f"| {inc['name']} | {inc['year']} | {loss} | {inc['category']} | {inc['root_cause']} | {det} | {inc['coverage']} |"
        )
    lines += [
        "",
        "Coverage levels: **Detected** = a detector targets the root-cause pattern; **Partial** = the vulnerability",
        "class or adjacent hygiene is covered but not the exact root cause; **Out of scope** = not detectable by",
        "static analysis of contract or relayer code.",
        "",
    ]
    return "\n".join(lines)


def main():
    os.makedirs("docs", exist_ok=True)
    with open(os.path.join("docs", "TAXONOMY.md"), "w", encoding="utf-8") as f:
        f.write(build_markdown())
    print("Wrote docs/TAXONOMY.md")


if __name__ == "__main__":
    main()
