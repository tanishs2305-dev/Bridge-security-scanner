# How to Use the Bridge Security Scanner

## Installation

### Step 1: Install Python
Make sure you have Python 3.8 or higher installed.
Check by running:
```bash
python --version
```

### Step 2: Install Dependencies
Open terminal in the project folder and run:
```bash
pip install -r requirements.txt
```

## Running the Scanner

### Method 1: Web Interface (Recommended)
1. Open terminal in the project folder
2. Run:
```bash
streamlit run app.py
```
3. Your browser will open automatically at `http://localhost:8501`
4. Use the interface to scan contracts

### Method 2: Command Line
1. Open terminal in the project folder
2. Run:
```bash
python scanner.py
```
3. This will run a test scan and display results in the terminal

## Using the Web Interface

### Scanning a Contract
1. **Paste Code**: Enter your Solidity contract in the left text area
2. **Click Scan**: Press the "🔍 Scan for Vulnerabilities" button
3. **View Results**: See the analysis on the right side

### Loading Examples
- Click **"Load Vulnerable Example"** to see a contract with security issues
- Click **"Load Secure Example"** to see a properly secured contract
- Compare the risk scores!

### Understanding Results

**Risk Levels:**
- 🟢 **LOW (0-20)**: Minor issues, generally safe
- 🟡 **MEDIUM (21-50)**: Some vulnerabilities, needs attention
- 🟠 **HIGH (51-80)**: Serious security issues, risky to deploy
- 🔴 **CRITICAL (81-100)**: Severe vulnerabilities, do not deploy!

**Severity Types:**
- **CRITICAL**: Exploitable vulnerabilities that can lead to fund loss
- **HIGH**: Serious security flaws that should be fixed immediately
- **MEDIUM**: Issues that could become problems under certain conditions
- **LOW**: Best practice violations, low immediate risk

### Downloading Reports
Click the **"Download Text Report"** button to save a detailed analysis as a text file.

## Vulnerability Categories

### 1. Verification Bypass
- Phantom functions without proper validation
- Missing return value checks
- Weak access control

### 2. Asymmetric Processing
- Replay attack vulnerabilities
- False balance top-up issues
- Cross-chain mapping inconsistencies

### 3. Key Theft
- Weak key generation
- Exposed private data
- Signature malleability

### 4. Diverse Exploits
- Event log manipulation
- Merkle root fraud
- Reentrancy attacks
- Integer overflow/underflow

## Troubleshooting

### Port Already in Use
If you get "Port 8501 is already in use":
```bash
streamlit run app.py --server.port 8502
```

### Import Errors
Make sure all dependencies are installed:
```bash
pip install -r requirements.txt
```

### Module Not Found
Make sure you're running commands from the project root folder.

## Tips for Best Results

1. **Complete Contracts**: Scan the entire contract, not just snippets
2. **Include Dependencies**: If your contract imports other files, include them
3. **Check Line Numbers**: Use the line numbers to locate issues quickly
4. **Fix High Severity First**: Prioritize CRITICAL and HIGH severity issues
5. **Verify Fixes**: Re-scan after making changes to confirm fixes work

## Example Workflow

1. Load vulnerable example
2. Scan and note the issues (Risk Score: ~58/100)
3. Load secure example  
4. Scan and compare (Risk Score: much lower)
5. Learn from the differences!

---

For questions or issues, refer to the README.md file.