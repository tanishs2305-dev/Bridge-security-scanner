"""
Benchmark for the Bridge Security Scanner.

Reports contract-level precision / recall / F1 / accuracy, detector-level hit rate
(did the EXPECTED detector fire?), and scan-time statistics.

Run from the project root:   python -m evaluation.evaluate
"""

import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import VulnerabilityScanner
from evaluation.dataset import CONTRACTS


def run_evaluation():
    rows = []
    timings_ms = []
    tp = fp = tn = fn = 0
    expected_total = expected_hit = 0

    for item in CONTRACTS:
        start = time.perf_counter()
        result = VulnerabilityScanner().scan_contract(item["code"])
        elapsed_ms = (time.perf_counter() - start) * 1000
        timings_ms.append(elapsed_ms)

        fired = {v["detector"] for v in result["vulnerabilities"]}
        predicted_vulnerable = result["total_issues"] > 0
        actually_vulnerable = item["label"] == "vulnerable"

        if actually_vulnerable and predicted_vulnerable:
            tp += 1
        elif actually_vulnerable and not predicted_vulnerable:
            fn += 1
        elif not actually_vulnerable and predicted_vulnerable:
            fp += 1
        else:
            tn += 1

        missed = set()
        if actually_vulnerable:
            missed = set(item["expected"]) - fired
            expected_total += len(item["expected"])
            expected_hit += len(item["expected"]) - len(missed)

        rows.append({
            "contract": item["name"],
            "label": item["label"],
            "risk_score": result["risk_score"],
            "findings": sorted(fired),
            "expected_missed": sorted(missed),
            "correct": (actually_vulnerable == predicted_vulnerable),
            "ms": round(elapsed_ms, 2),
        })

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    total = tp + fp + tn + fn

    return {
        "rows": rows,
        "confusion": {"TP": tp, "FP": fp, "TN": tn, "FN": fn},
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "accuracy": round((tp + tn) / total, 3) if total else 0.0,
        "detector_hit_rate": round(expected_hit / expected_total, 3) if expected_total else 0.0,
        "contracts": total,
        "avg_ms": round(statistics.mean(timings_ms), 2),
        "max_ms": round(max(timings_ms), 2),
    }


def main():
    r = run_evaluation()
    print(f"\nContracts evaluated : {r['contracts']}")
    print(f"Confusion matrix    : {r['confusion']}")
    print(f"Precision           : {r['precision']}")
    print(f"Recall              : {r['recall']}")
    print(f"F1                  : {r['f1']}")
    print(f"Accuracy            : {r['accuracy']}")
    print(f"Expected-detector hit rate: {r['detector_hit_rate']}")
    print(f"Scan time (ms)     : avg {r['avg_ms']}, max {r['max_ms']}\n")
    for row in r["rows"]:
        flag = "OK " if row["correct"] else "ERR"
        extra = f"  MISSED {row['expected_missed']}" if row["expected_missed"] else ""
        print(f"[{flag}] {row['label']:10} {row['contract']:32} score={row['risk_score']:>3} {row['findings']}{extra}")


if __name__ == "__main__":
    main()
