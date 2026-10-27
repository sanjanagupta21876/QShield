# QShield — Quantum-Safe Migration Planner

**IDEATHON 2026 Project**  
*A software-based cybersecurity planning tool to assess cryptographic exposure to future quantum computing threats and prioritize post-quantum migration.*

---

## 📖 Project Purpose & Core Principles

The advent of Cryptanalytically Relevant Quantum Computers (CRQCs) poses fundamental challenges to modern cryptography:
- **Asymmetric Public-Key Cryptography** (e.g., RSA, ECDSA, ECDH, classical Diffie–Hellman) is vulnerable to polynomial-time breaking via **Shor's algorithm**.
- **Symmetric Block Ciphers** (e.g., AES) and **Hash Functions** (e.g., SHA-256) are affected by **Grover's algorithm**, which quadratically speeds up brute-force searches (halving effective symmetric key bits), but they are not broken like public-key primitives.
- Organizations face immediate risks from **Harvest Now, Decrypt Later (HNDL)** attacks targeting data with high confidentiality shelf-lives.

### Planning Margin Heuristic
QShield uses a timeline evaluation heuristic derived from Mosca's Theorem:
$$\text{Planning Margin} = Z - (X + Y)$$
where:
- **$X$** = Required confidentiality duration in years (data shelf-life).
- **$Y$** = Estimated migration duration in years.
- **$Z$** = Hypothetical years until the quantum-threat horizon (CRQC emergence).

**Interpretation:**
- **Negative ($< 0$):** The combined confidentiality and migration timeline ($X + Y$) extends beyond the assumed threat horizon ($Z$).
- **Zero ($= 0$):** No planning buffer exists under these assumptions.
- **Positive ($> 0$):** A positive planning buffer exists under these assumptions.

> **Important Planning Heuristic Disclaimer:**  
> The Planning Margin is a simplified planning heuristic, not a validated statistical probability of compromise or a prediction of when quantum computers will break cryptography.

> **System Scope vs. Primitive Scope:**  
> Assessing an individual algorithm as quantum-resilient does not label an entire system quantum-safe. End-to-end security requires that all components across key establishment, signatures, transport certificates, and symmetric protection are post-quantum secure.

---

## 🏗️ Project Architecture

```
qshield/
│
├── app.py                     # Minimal working Streamlit application entrypoint
├── requirements.txt           # Project dependencies
├── README.md                  # Setup, architecture, and usage guide
├── .gitignore                 # Python, IDE, cache, and SQLite ignore rules
├── pytest.ini                 # Pytest configuration and pythonpath resolution
│
├── core/                      # Core analytical & business logic package
│   ├── __init__.py            # Package metadata & version
│   ├── database.py            # SQLite connection, schema initialization & CRUD
│   ├── risk_engine.py         # Quantum risk scoring (Shor / Grover / PQC / Unknown)
│   ├── scenario_engine.py     # Threat horizon simulation (Planning Margin: Z - (X + Y))
│   ├── recommendations.py     # Role-aware NIST PQC migration target guidance
│   └── validation.py          # Input validation for cryptographic assets & roles
│
├── components/                # Streamlit UI building blocks & visualizations
│   ├── __init__.py            # Package declaration
│   ├── charts.py              # Plotly chart generators (risk distribution, scenario breakdown)
│   └── forms.py               # Streamlit asset intake form with role selection & validation
│
├── tests/                     # Automated unit test suite (Pytest)
│   ├── __init__.py            # Package declaration
│   ├── test_database.py       # Persistence layer & isolated schema tests
│   ├── test_recommendations.py# Role-aware migration recommendation tests
│   ├── test_risk_engine.py    # Quantum risk classification & unknown-handling tests
│   ├── test_scenario_engine.py# Mosca's Theorem planning margin unit tests
│   └── test_validation.py     # Form, role, and input data validation tests
│
└── data/                      # Local data directory for SQLite database storage
    └── .gitkeep               # Directory placeholder
```

---

## 🛠️ Technology Stack

- **Language:** Python 3.11+
- **Frontend / UI:** Streamlit
- **Data Manipulation:** Pandas
- **Interactive Visualizations:** Plotly
- **Storage:** SQLite3 (standard library)
- **Testing:** Pytest

---

## 🚀 Installation & Setup (Windows)

Follow these exact steps in PowerShell:

### 1. Navigate to Repository Root
```powershell
cd C:\QShield
```

### 2. (Recommended) Create and Activate Virtual Environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install Dependencies
```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

---

## 🧪 Running Automated Tests

Run the full Pytest test suite from the project root:
```powershell
pytest
```
Expected output:
```text
============================= 62 passed in 0.69s ==============================
```

---

## 🖥️ Launching the Application

Run the Streamlit application with:
```powershell
streamlit run app.py
```

Once launched, access the application in your browser at:
`http://localhost:8501`

---

## 📌 Implementation Status: Implemented vs. Planned Features

### Currently Implemented (Phases 1, 2, 3, 4 & 5 Baseline)
- [x] **Modular Architecture**: Decoupled `core/` backend and `components/` UI layer.
- [x] **Interactive Quantum-Threat Scenario Simulator (Phase 5)**:
  - **Dynamic Timeline Modeling**: User controls for hypothetical CRQC emergence year ($Z = \text{Target Year} - 2026$) and estimated organizational migration duration ($Y$).
  - **Flexible Inventory Scoping & Custom Overrides**: Assess all registered assets, filter by system, select custom asset subsets, and apply asset-specific migration duration overrides for high-complexity legacy cryptosystems.
  - **Rigorous Exposure Categorization**: Confirmed quantum exposure strictly requires both mathematical vulnerability (e.g. Shor's algorithm) AND a negative planning margin ($Z - (X + Y) < 0$). Unrecognized mechanisms are tracked under `requires_assessment` and never counted as confirmed exposures.
  - **Plotly Visualizations**:
    1. Distribution of planning margins (Negative, Zero, Positive).
    2. Scenario exposure breakdown donut chart (Confirmed Exposed, Requires Assessment, Buffer Maintained).
    3. Asset-level planning margin comparison horizontal bar chart with $x=0$ reference line.
    4. Multi-scenario grouped bar chart comparing exposure shifts across hypothetical CRQC emergence years.
  - **Multi-Scenario Comparison Dashboard**: Real-time side-by-side comparison across user-configured threat horizons (e.g., 2029 [Aggressive], 2033 [Moderate], 2038 [Conservative]).
  - **Decision-Support Planning Disclaimer**: Explicitly framed as a decision-support heuristic, not a calendar prediction or probability-of-compromise model.
- [x] **Explainable Quantum Risk Assessment (Phase 4)**:
  - **7-Dimension Asset Explainability Profile**:
    1. Algorithm and cryptographic role.
    2. Classification, quantum vulnerability status, and heuristic risk score.
    3. Quantum threat relevance (polynomial-time Shor's factoring/discrete log vs. Grover's quadratic key search halving).
    4. Scientific assumptions and heuristic limitations.
    5. Confidentiality lifetime implications and Harvest Now, Decrypt Later (HNDL) exposure for key establishment.
    6. Assessment rigor categorization (`Confirmed`, `Heuristic`, or `Requires Additional Information`).
    7. Clear, actionable next planning or migration recommendations (ML-KEM, ML-DSA, SLH-DSA, AES-256).
  - **Vulnerability vs. Timeline Exposure Distinction**: Explicitly decouples intrinsic mathematical vulnerability from timeline planning margins ($Z - (X + Y)$), noting that positive margins do not guarantee safety and negative margins do not imply empirical compromise today.
  - **Non-Alarming, Objective Language**: Avoids apocalyptic framing, arbitrary compromise probabilities, and unexplained risk numbers.
  - **Explainable Assessment UI View**: Dedicated `🛡️ Explainable Risk Assessment` tab providing executive-level inventory metrics, core cryptanalytic educational cards, and an interactive asset-level inspector.
- [x] **Database & Inventory Management Layer (Phase 3)**:
  - SQLite schema initialized under `data/qshield.db` with complete parameterized CRUD operations.
  - Key size applicability handling: safely handles unkeyed primitives (hashes like SHA-256) where key size is not applicable without failing constraints.
  - Search, filter, and sorting engine (`search_assets`) supporting text search across names/systems/algorithms, exact filtering by role, algorithm, and migration status, and multi-attribute sorting.
  - Safe schema migrations preserving existing asset data when updating columns.
- [x] **Asset Inspection, Editing & Destruction Safety (Phase 3)**:
  - Interactive asset detail inspection cards displaying cryptographic metadata, quantum risk ratings, and migration recommendations.
  - In-place asset record editing with full form validation.
  - Confirmed destructive deletion preventing accidental asset removal.
- [x] **Robust Cryptographic Classification (Phase 2)**:
  - Supports and distinctly classifies 15 canonical algorithm families: RSA, ECDSA, ECDH, Classical Diffie-Hellman, DSA, AES, 3DES, ChaCha20, SHA-256, SHA-384, SHA-512, SHA-3, ML-KEM, ML-DSA, and SLH-DSA.
  - Robust name normalization handling spacing, hyphens, underscores, and casing without unsafe substring collisions.
  - Distinguishes mechanism categories: Public-key Key Establishment, Public-key Digital Signatures, Symmetric Encryption, Cryptographic Hashes, and Standardized PQC.
  - Distinguishes operational roles for PQC: ML-KEM (Key Establishment / KEM) vs. ML-DSA & SLH-DSA (Digital Signatures).
- [x] **Explainable Risk Engine & Heuristic Index (Phases 2 & 4)**:
  - Transparent threat differentiation: Shor's algorithm for public-key vs. Grover's algorithm for symmetric ciphers and hashes.
  - Evaluates Harvest Now, Decrypt Later (HNDL) exposure for key establishment with extended data confidentiality shelf-life ($X \ge 10$).
  - Evaluates symmetric security margins against the NIST 128-bit quantum security floor under Grover's algorithm.
  - Includes explicit documentation of scoring methodology, scientific assumptions, and heuristic limitations in structured output.
- [x] **Validation & Safety Enforcement (Phases 2, 3 & 5)**:
  - Algorithm-role compatibility validation rejecting mismatched combinations (e.g., AES used for signatures or ML-KEM used for signing).
  - Strict parameter validation rejecting non-positive key sizes (when applicable), negative shelf-lives, past target years, negative migration durations, and invalid types.
- [x] **Safe Unknown Handling**: Unrecognized algorithms return an explicit `UNKNOWN` / `INSUFFICIENT_INFORMATION` classification with manual audit recommendation rather than assuming vulnerability or safety.
- [x] **Planning Margin Heuristic**: $Z - (X + Y)$ implemented and tested in `core/scenario_engine.py`.
- [x] **Role-Aware Recommendations**: Tailors targets to key establishment (ML-KEM), digital signatures (ML-DSA, SLH-DSA), symmetric encryption (AES-256), and hashing (SHA-256).
- [x] **Interactive Streamlit Interface**:
  - System status panel verifying module health.
  - Complete asset inventory management tab with live search, filters, sorting, Plotly risk distribution chart, and edit/delete workflows.
  - Dedicated Explainable Quantum Risk Assessment dashboard with overall summary metrics and 7-dimension asset inspector.
  - Interactive Threat Scenario Simulator tab with dynamic sliders, scope filtering, per-asset overrides, Plotly margin distribution, exposure breakdown, horizontal margin comparison, and multi-scenario comparison.
  - Interactive risk & recommendation calculator with algorithm-role defaults, compatibility warnings, and expandable assumptions/limitations viewer.
- [x] **Isolated Unit Tests**: 62 comprehensive unit tests covering all core modules, database operations, classifications, explainability dimensions, and scenario engine simulations.

### Planned for Subsequent Development Phases (Not Yet in UI)
- [ ] **End-to-End Migration Timeline Planner**: Interactive scheduling tools for managing organizational migration milestones.
- [ ] **Automated Cryptographic Discovery**: Connectors/parsers to discover certificates and cipher suites from network endpoints or source repositories.
- [ ] **Report Generation**: Exporting compliance and migration audit reports to CSV and PDF formats.


