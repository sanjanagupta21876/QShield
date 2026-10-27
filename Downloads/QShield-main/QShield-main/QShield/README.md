# QShield — Quantum-Safe Migration Planner

**Cybersecurity Planning & Post-Quantum Cryptography Migration Platform**  
*A software-based planning tool to evaluate cryptographic exposure to future Cryptanalytically Relevant Quantum Computers (CRQCs) and prioritize post-quantum migration.*

---

## 📖 Problem Statement & Core Principles

The emergence of Cryptanalytically Relevant Quantum Computers (CRQCs) presents a fundamental challenge to modern public-key cryptography:

1. **Shor's Algorithm (Polynomial-Time Asymmetric Break):**
   - Classical public-key cryptography (RSA, ECDSA, ECDH, Diffie-Hellman, DSA) relies on integer factorization or discrete logarithm problems.
   - Shor's algorithm solves these problems in polynomial time on a CRQC, breaking the mathematical foundations of classical key exchange and digital signatures.
2. **Grover's Algorithm (Quadratic Symmetric Halving):**
   - Symmetric block ciphers (AES, 3DES, ChaCha20) and hash functions (SHA-256, SHA-512) are affected by Grover's algorithm, which provides a quadratic speedup for unstructured brute-force search.
   - This effectively halves key search complexity ($k \to k/2$). AES-256 retains 128 bits of quantum security (meeting the NIST post-quantum security floor), whereas AES-128 is reduced to 64 bits of effective security.
3. **Harvest Now, Decrypt Later (HNDL):**
   - Adversaries can intercept and archive encrypted communications today.
   - Once a CRQC is built, adversaries can decrypt stored ciphertext retroactively.
   - Primitives protecting data with extended confidentiality lifetimes ($X \ge 10$ years) face an immediate operational risk today.

### Mosca's Theorem Planning Margin Heuristic
QShield implements the timeline planning heuristic derived from Michele Mosca's Theorem:
$$\text{Planning Margin} = Z - (X + Y)$$
where:
- **$X$** = Required data confidentiality lifetime in years (shelf-life).
- **$Y$** = Estimated time in years required to complete post-quantum migration.
- **$Z$** = Hypothetical years until the quantum threat horizon emerges ($Z = \text{Target Year} - 2026$).

**Interpretation:**
- **Negative ($< 0$):** Combined timeline ($X + Y$) extends beyond assumed threat horizon ($Z$). Indicates urgent migration timeline pressure.
- **Zero ($= 0$):** Zero timeline buffer exists under the specified assumptions.
- **Positive ($> 0$):** A planning buffer cushion exists under the specified assumptions.

> **Important Planning Heuristic Disclaimer:**  
> The Planning Margin is a simplified decision-support planning heuristic, NOT an empirical prediction of when quantum computers will be constructed or a validated probability of compromise.

> **System Scope vs. Primitive Scope Disclaimer:**  
> Evaluating an individual cryptographic primitive as quantum-resilient does NOT certify an entire application or network channel as quantum-safe. End-to-end security requires that all pipeline components (key encapsulation, digital signatures, transport certificates, symmetric encryption, and hashes) are protected.

---

## 🏗️ Project Architecture

```
qshield/
│
├── app.py                     # Streamlit application entrypoint & multi-tab UI
├── demo.py                    # Standalone demonstration helper & summary CLI script
├── requirements.txt           # Project dependencies
├── README.md                  # Comprehensive documentation, setup guide & demo script
├── .gitignore                 # Exclusion rules for caches, virtualenvs, and local SQLite data
├── pytest.ini                 # Pytest pythonpath configuration
│
├── core/                      # Analytical and business logic engine package
│   ├── __init__.py            # Package metadata & version
│   ├── database.py            # SQLite schema initialization, parameterized CRUD, status updater
│   ├── risk_engine.py         # 7-dimension explainable quantum risk evaluation (Shor/Grover/PQC/Unknown)
│   ├── scenario_engine.py     # Mosca's Theorem timeline simulator (Z - (X + Y)) & multi-scenario comparison
│   ├── recommendations.py     # Role-aware NIST PQC migration targets (FIPS 203, 204, 205, SP 800-38D)
│   ├── validation.py          # Input validation, parameter boundaries, and role compatibility checks
│   ├── export.py              # RFC 4180 CSV export with formula injection sanitization (CWE-1236)
│   └── demo_data.py           # Curated 10-asset synthetic dataset & duplicate-safe loader
│
├── components/                # Modular Streamlit UI building blocks & Plotly visualizations
│   ├── __init__.py            # Package declaration
│   ├── charts.py              # Plotly chart generators (risk distribution, margin bars, comparison)
│   └── forms.py               # Streamlit intake and edit forms with role auto-suggestion
│
├── tests/                     # Automated test suite (79 Pytest unit & integration tests)
│   ├── __init__.py            # Package declaration
│   ├── test_integration_phase9.py # Complete 10-step workflow, edge cases, consistency, and CSV tests
│   ├── test_demo_data.py      # Synthetic demonstration dataset and duplicate-prevention tests
│   ├── test_database.py       # Persistence layer & schema migration tests
│   ├── test_risk_engine.py    # Algorithmic classification, explainability, and input bounds tests
│   ├── test_scenario_engine.py# Mosca margin calculations, overrides, and multi-scenario tests
│   ├── test_validation.py     # Parameter validation and role compatibility tests
│   └── test_recommendations.py# Role-aware migration guidance tests
│
└── data/                      # Local data directory for SQLite database storage
    └── .gitkeep               # Directory placeholder
```

---

## 🛠️ Technology Stack

- **Programming Language:** Python 3.11+
- **User Interface:** Streamlit
- **Data Manipulation:** Pandas
- **Interactive Visualizations:** Plotly Graph Objects
- **Storage Layer:** SQLite3 (standard library, local zero-configuration persistence)
- **Test Framework:** Pytest

---

## 🚀 Clean Installation & Setup

### Windows (PowerShell)
```powershell
# 1. Clone repository and navigate to root
cd C:\QShield

# 2. (Recommended) Create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Linux & macOS (Bash / Zsh)
```bash
# 1. Clone repository and navigate to root
cd /path/to/QShield

# 2. (Recommended) Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
python3 -m pip install --upgrade pip
pip install -r requirements.txt
```

---

## 🧪 Running Automated Tests

Run the full automated test suite (79 tests) from the project root:

```powershell
python -m pytest -q
```

**Expected output:**
```text
79 passed in ~4.5s
```

All tests run in isolated environments (using in-memory or temporary databases) and verify schema initialization, mathematical margin formulas, edge cases, unkeyed primitives, CSV exports, and the complete 10-step workflow.

---

## 🖥️ Launching the Application

Start the Streamlit application from the root directory:

```powershell
streamlit run QShield/app.py
```
*(Or navigate into `QShield` and run `streamlit run app.py`)*

Once launched, access the application in your browser at:  
👉 **`http://localhost:8501`**

---

## ✨ Loading Demonstration Data

QShield includes a curated, realistic synthetic demonstration dataset of 10 cryptographic assets representing various algorithm families, operational roles, confidentiality lifetimes, and migration statuses.

### Option A: From the Web UI (Recommended)
1. Open the application at `http://localhost:8501`.
2. In the left **Sidebar**, expand **"✨ Load Demonstration Dataset"**, or open **"✨ Demonstration Dataset Controls"** in the **Asset Inventory** tab.
3. Click **"🚀 Load Demo Assets"**.
   - *Duplicate Safety:* Clicking this repeatedly will skip existing items and will **never create duplicate records**.
   - *Reset Option:* Checking the box *"Purge existing inventory before loading demo data"* will wipe existing records and reload fresh demo data.

### Option B: From the Command Line
```powershell
# Populate demo assets safely (skipping duplicates)
python demo.py

# Or purge existing assets and reload demo data fresh
python demo.py --clear
```

---

## 🎬 Step-by-Step Demonstration Script

Follow this 10-step sequence to demonstrate the complete capabilities of QShield:

### Step 1: The Problem QShield Addresses
- **Action:** Open Tab 1 (`📋 Overview & Architecture`).
- **Talking Points:** Explain that classical asymmetric cryptography (RSA, ECC, DH) is mathematically vulnerable to Shor's algorithm on a future CRQC. Symmetric ciphers and hashes are affected by Grover's algorithm (effective key search halved). Point out the **Harvest Now, Decrypt Later (HNDL)** risk for long-lived data.

### Step 2: The Cryptographic Asset Inventory
- **Action:** Navigate to Tab 2 (`🗄️ Asset Inventory`). Load the synthetic demonstration dataset if empty.
- **Talking Points:** Show how assets are organized across systems, cryptographic algorithms, operational roles, key sizes, confidentiality lifetimes ($X$), and migration statuses. Demonstrate live substring search (e.g., search for `"Banking"` or `"Cloud"`) and filtering by operational role or algorithm.

### Step 3: Example Cryptographic Risk Assessment
- **Action:** In Tab 2, select asset `[DEMO] Synthetic Core Banking TLS Certificate` (RSA-2048, $X=12$).
- **Talking Points:** Show that the risk engine calculates qualitative risk (`CRITICAL`, score `9.5/10.0`), identifying it as an asymmetric key-establishment primitive vulnerable to Shor's algorithm.

### Step 4: Transparent Reasoning & Cryptanalysis Principles
- **Action:** Navigate to Tab 3 (`🛡️ Explainable Risk Assessment`). Review the executive summary cards:
  - Shor-Vulnerable Public-Key
  - Grover-Affected Symmetric/Hash
  - Standardized PQC
  - Unclassified / Audit Needed
- **Talking Points:** Note that every asset belongs to a clear, explainable cryptanalytic category. Explain the difference between Shor's factoring attack and Grover's search space halving.

### Step 5: The Harvest Now, Decrypt Later (HNDL) Threat
- **Action:** In Tab 3's Asset Inspector, compare:
  1. `[DEMO] Synthetic Core Banking TLS Certificate` (RSA, Key Establishment, $X=12$): Tagged as **CRITICAL HNDL Urgent** because intercepted ciphertext can be decrypted retroactively.
  2. `[DEMO] Synthetic Mobile App Auth Token Signer` (ECDSA, Digital Signature, $X=2$): While vulnerable to Shor's algorithm, historical signatures cannot be "harvested and decrypted".
- **Talking Points:** Emphasize that key exchange requires earlier migration than digital signatures for long-lived confidentiality.

### Step 6: Threat Horizon Scenario Modeling (Mosca's Heuristic)
- **Action:** Navigate to Tab 4 (`🔮 Threat Scenario Simulator`). Set:
  - Hypothetical CRQC Threat Horizon Year: `2033` ($Z = 7$ years).
  - Estimated Migration Duration ($Y$): `3` years.
- **Talking Points:** Review the top metric cards. Explain Mosca's Theorem formula: $\text{Planning Margin} = Z - (X + Y)$. Point out assets with negative planning margins (e.g., $7 - (12+3) = -8$ years).

### Step 7: Changing Migration Assumptions
- **Action:** Adjust the migration duration slider $Y$ from `3` to `6` years, or open "Optional Asset-Specific Migration Overrides" to give legacy mainframe systems a higher $Y$.
- **Talking Points:** Observe how increasing migration duration shifts positive buffer assets into the negative margin zone. Show the multi-scenario comparison bar chart comparing horizons `2029`, `2033`, and `2038`.

### Step 8: Role-Aware Migration Guidance & Status Tracking
- **Action:** Inspect migration recommendations across primitive types:
  - Key Establishment $\to$ NIST FIPS 203 **ML-KEM-768** (Immediate priority)
  - Digital Signatures $\to$ NIST FIPS 204 **ML-DSA-65** / FIPS 205 **SLH-DSA** (High priority)
  - Symmetric Ciphers $\to$ NIST SP 800-38D **AES-256-GCM** (Maintain $\ge 128$ bits)
- **Talking Points:** Return to Tab 2 and update an asset's migration status from `Not Started` to `In Progress` using the Quick Status Updater.

### Step 9: Audit Report Export
- **Action:** Click the **"📥 Export Inventory (CSV)"** button in Tab 2, **"📥 Export Risk Assessment Report (CSV)"** in Tab 3, or **"📥 Export Scenario Simulation Report (CSV)"** in Tab 4.
- **Talking Points:** Open the downloaded CSV in Excel or a text editor. Highlight that formulas (`=`, `+`, `-`, `@`) and special characters are safely escaped, ensuring compliance-ready, discrepancy-free export.

### Step 10: Limitations & Intended Use of the Application
- **Action:** Review the disclaimers on Tab 1 and in the assumptions panels.
- **Talking Points:** Conclude by reiterating that QShield is a decision-support heuristic planning tool, not a cryptographic oracle. Emphasize that evaluating a primitive does not replace end-to-end cryptographic architecture reviews.

---

## 📌 Features Actually Implemented

- [x] **Local SQLite Persistence Layer**: Fully parameterized queries, safe migrations, and ACID-compliant CRUD operations.
- [x] **Comprehensive Cryptographic Asset Inventory**: Search across names/systems/algorithms, exact filtering, and sorting.
- [x] **Role & Parameter Validation**: Input validation rejecting negative lifetimes, non-positive key sizes (when applicable), and algorithm-role mismatches.
- [x] **Safe Unknown Handling**: Unrecognized or proprietary mechanisms return explicit `UNKNOWN` / `INSUFFICIENT_INFORMATION` and are excluded from confirmed exposures.
- [x] **Explainable Quantum Risk Engine**: Transparent qualitative scoring distinguishing Shor's algorithm from Grover's algorithm.
- [x] **7-Dimension Asset Profiling**: Explains identity, risk level, threat relevance, HNDL impact, vulnerability vs. timeline distinction, assessment rigor, and next action.
- [x] **Interactive Threat Horizon Simulator**: Mosca's planning margin heuristic ($Z - (X + Y)$) with dynamic sliders, scope filtering, and per-asset overrides.
- [x] **Multi-Scenario Comparison**: Grouped Plotly visual comparisons across user-configured threat horizon target years.
- [x] **Role-Aware NIST PQC Recommendations**: Actionable targets aligned with FIPS 203, FIPS 204, FIPS 205, and SP 800-38D.
- [x] **Migration Status Management**: In-place form updates and atomic quick status transitions.
- [x] **Audit-Ready Report Generation**: RFC 4180 CSV export for inventory, risk assessments, and scenario models with formula injection sanitization (CWE-1236).
- [x] **Curated Synthetic Demonstration Dataset**: 10 pre-configured synthetic assets with duplicate-safe loading and optional clean resets.

---

## ⚠️ Known Limitations & Scope Boundaries

1. **Primitive-Level Scope:**  
   QShield assesses individual cryptographic primitives. A system evaluated with quantum-resilient primitives is not certified quantum-safe end-to-end unless all surrounding protocol handshakes, certificates, RNGs, and modes of operation are post-quantum secure.
2. **Simplified Timeline Heuristic:**  
   Mosca's formula $Z - (X + Y)$ is a decision-support planning model. It is not an empirical forecast of when quantum hardware will achieve fault tolerance or a statistical probability of compromise.
3. **Implementation Vulnerabilities Not Evaluated:**  
   QShield does not assess implementation flaws such as side-channel leakage, timing attacks, weak random number generation, or improper certificate validation.
4. **Report Formats:**  
   Audit export is currently implemented in RFC 4180 CSV. Direct PDF generation is not currently included.

---

## 🛡️ Security & Cryptographic Disclaimers

- **Non-Alarmist Framing:** High risk scores represent planning urgency for long-lived data under mathematical Shor vulnerability, not an indication that an asset has been compromised today.
- **Data Privacy:** QShield operates entirely offline against a local SQLite database (`data/qshield.db`). No telemetry, cryptographic keys, or proprietary data are transmitted over the network.
- **Decision-Support Only:** Recommendations should be validated by organizational cryptographic architects and aligned with relevant regulatory standards (NIST, BSI, ANSSI, CNSA 2.0).
