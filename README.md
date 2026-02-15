# Bridge Security Scanner 

## What This Tool Does
Analyzes smart contracts used in blockchain bridges and detects security vulnerabilities that could lead to hacks.

## Project Structure
```
bridge-security-scanner/
│
├── data/                  # Stores vulnerability patterns and training data
├── models/                # Machine learning models
├── utils/                 # Helper functions for vulnerability detection
├── examples/              # Sample vulnerable contracts for testing
│
├── scanner.py             # Main vulnerability detection engine
├── app.py                 # Streamlit web interface
└── README.md              # This file
```

## How It Works (Simplified)
1. **Input**: You paste a Solidity smart contract
2. **Analysis**: The tool checks for 4 types of vulnerabilities:
   - Verification Bypass (faulty validation logic)
   - Asymmetric Processing (cross-chain inconsistencies)
   - Key Theft vulnerabilities (weak key management)
   - Diverse Exploits (emerging patterns)
3. **Output**: Security report with risk score and identified issues

## Tech Stack
- Python 3.x
- Scikit-learn (Machine Learning)
- Streamlit (Web Interface)
- Regular Expressions (Pattern Matching)

## Installation
```bash
pip install streamlit scikit-learn numpy pandas
```

## Usage
```bash
streamlit run app.py
```

---
Built to address the $1.92B cross-chain bridge security problem