# 🔒 Bridge Security Scanner

A static-analysis tool for **cross-chain bridge security**. It checks both halves of a bridge:

- **On-chain** - Solidity smart contracts (lock/mint/release logic, signature verification)
- **Off-chain** - relayer / validator / oracle services written in Python or Go

Bridges lost over **$1.92B** in a single year. The biggest incidents were not all contract bugs: Wormhole
was a verification bypass, Nomad a trusted zero root, and Ronin compromised off-chain validator keys. A tool
that reads only Solidity would miss that last class, so this project scans both.

## How it works

| Engine | What it does | Why it exists |
|---|---|---|
| **Pattern engine** (`data/vulnerability_patterns.py`) | 11 syntax-level detectors | Fast, bridge-specific signatures |
| **Function-rule engine** (`data/function_rules.py`) | 13 structure-aware rules that split a contract into functions and reason about each body | Detection that does **not depend on variable names** (e.g. reentrancy on `deposits`, `userFunds` or `ledger`) |
| **Slither** (`utils/slither_integration.py`) | AST/IR analysis from Trail of Bits, compiler version auto-selected from the pragma | Independent second opinion; findings both engines agree on are counted once |
| **Off-chain scanner** (`data/offchain_patterns.py`) | 11 detectors for relayer/validator code | Key exposure, count-only signature checks, unsafe execution |

Every finding carries a severity, an explanation, a line number, the engine that found it, and a
**remediation** ("how to fix") message.

### Vulnerability categories

Verification Bypass - Asymmetric Processing - Key Theft - Diverse Exploits (on-chain);
Key & Secret Exposure - Signature & Threshold Validation - Network & Service Exposure - Unsafe Execution (off-chain).

### Scoring

Each finding adds a weight (CRITICAL 10, HIGH 7, MEDIUM 4, LOW 2). The risk score is the sum, capped at 100:
0-20 LOW, 21-50 MEDIUM, 51-80 HIGH, 81-100 CRITICAL. Severity is a fixed property of the detector (how directly
that bug class leads to loss of funds); it is not recalculated per line.

## Incident taxonomy

`data/incidents.py` maps **19 real bridge incidents** to the categories and detectors (also shown in the app's
*Incident Taxonomy* tab; export with `python -m evaluation.export_taxonomy` -> `docs/TAXONOMY.md`).
Coverage is reported conservatively as *Detected*, *Partial* or *Out of scope*.

## Evaluation

```
python -m evaluation.evaluate
```

Runs a labeled set of vulnerable and safe contracts and reports precision, recall, F1 and scan time. The set was
written by the project author, so it is a **regression benchmark, not an independent accuracy claim**.

## Setup

```
python -m venv venv
venv\Scripts\activate            # Windows PowerShell:  .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

Slither needs a Solidity compiler. `solc-select` (installed with Slither) downloads the version matching each
contract's pragma on first use; if Slither is unavailable the app falls back to the pattern engines and says so.

## Tests and security tooling

```
python -m pytest tests/ -v
```

CI (`.github/workflows/security.yml`) runs Bandit, pip-audit, Gitleaks and the test suite on every push.
Dependabot keeps dependencies and workflow actions current. The scanner itself guards against ReDoS (the `regex`
module with a per-pattern timeout) and caps input size.

## Project structure

```
app.py                      Streamlit UI (Scanner, Incident Taxonomy, Evaluation tabs)
scanner.py                  Scanners, scoring, report merge
data/                       Detector definitions, remediation text, incident taxonomy
utils/slither_integration.py
evaluation/                 Labeled benchmark and taxonomy exporter
examples/                   Vulnerable and secure sample contracts and relayers
tests/                      Regression tests
```

## Limitations

- Static analysis only; it can miss bugs and flag safe code. Use it as a first-pass triage aid, not a substitute for an audit.
- Some function rules use naming heuristics (e.g. a function called `setX` is treated as privileged).
- Non-Solidity chains (e.g. Solana programs) are out of scope.

## Not implemented (proposed as future work)

NFT-based cross-chain identity and trust evaluation, IPFS-based tracking, symbolic execution (Mythril),
runtime monitoring, and testnet deployment.

## License

MIT - see `LICENSE`.
