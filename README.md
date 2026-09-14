# IPsecGuard AI

> **AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework**  
> *Developed for the Smart India Hackathon (SIH) Prototype Demonstration*

![Version](https://img.shields.io/badge/Version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)
![Node](https://img.shields.io/badge/Node.js-18%2B-green.svg)
![React](https://img.shields.io/badge/React-18-cyan.svg)
![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)
![Security-Standard](https://img.shields.io/badge/Standards-NIST%20SP%20800--77%20%7C%20RFC%204301-orange.svg)

---

## Executive Overview

**IPsecGuard AI** is an enterprise-grade defensive protocol analyzer and automated security assessment framework for IPsec VPNs. It provides cybersecurity operations center (SOC) analysts and network security engineers with instant visibility into cryptographic configurations, packet capture traces, and security association (SA) states.

The platform combines a **dual-engine architecture**:
1. **AI-Assisted Protocol Classification Engine**: Derives explainable confidence scores for protocol parameters while explicitly segregating empirically **DETECTED** metrics from heuristic **INFERRED** attributes to prevent hallucinated conclusions.
2. **Mathematical Security Assessment Engine**: Employs a 100-point deduction model rooted in **NIST SP 800-77 Rev. 1**, **RFC 4301**, **RFC 7296 (IKEv2)**, and **RFC 8221** to quantify security postures into LOW, MEDIUM, HIGH, and CRITICAL risk tiers with prioritized remediations.

---

## Key Features

- **Dual Analysis Modes**:
  - **Mode 1 — Demo Dataset (One-Click Evaluation)**: 5 built-in ground-truth scenarios (*Strong Enterprise VPN*, *Legacy VPN*, *Modern Next-Gen IPv6 VPN*, *Transport Mode*, and *Misconfigured High-Risk VPN*) allowing judges to evaluate the full platform without external VPN hardware.
  - **Mode 2 — Upload Capture (.pcap / .pcapng)**: Safe defensive header parser extracting Ethernet, IPv4/IPv6, ISAKMP (UDP 500), NAT-T (UDP 4500), ESP (Protocol 50), SPIs, sequence numbers, and packet MTU size distributions.
- **Explainable AI Confidence Calibration**: Generates realistic confidence metrics (e.g., Protocol ID: 99%, IKE: 96%, VPN Mode: 94%, Cipher: 98%, Traffic classification: 78%) based on evidence markers.
- **Dynamic Threat Matrix**: Interactive threat breakdown highlighting Sweet32 block collisions, Logjam DH weaknesses, IKEv1 Aggressive Mode PSK cracking, replay window vulnerabilities, and retroactive decryption exposure.
- **Side-by-Side Configuration Differential Engine**: Compare two VPN policies simultaneously (e.g., Legacy vs. Modern) with differential scorecards and AI rationale explaining why one suite is superior.
- **Metadata Exposure Vector Analysis**: Evaluates cleartext leakage vectors across Tunnel vs. Transport mode (endpoint visibility, packet timing side-channels, MTU distributions).
- **Automated Report Generation**: Exports instant executive summaries and deep technical audits as standalone, printable HTML reports.

---

## Project Structure

```
IPsecGuard-AI/
├── backend/
│   ├── main.py                  # FastAPI server with REST endpoints & CORS
│   ├── analyzer.py              # Protocol parser & AI classification engine
│   ├── security_engine.py       # 100-point NIST/RFC scoring & threat matrix
│   ├── report_generator.py      # Executive & technical HTML/PDF report engine
│   ├── sample_data.py           # 5 built-in datasets & binary PCAP generator
│   ├── requirements.txt         # Python backend dependencies
│   └── uploads/                 # Local directory for PCAP uploads & samples
│
├── frontend/
│   ├── package.json             # React, Vite, Lucide-React dependencies
│   ├── vite.config.js           # Vite dev configuration & API reverse proxy
│   ├── index.html               # Web application entrypoint
│   └── src/
│       ├── main.jsx             # React DOM root
│       ├── App.jsx              # Main dashboard coordinator & navigation
│       ├── api.js               # REST API client connecting to FastAPI
│       ├── styles.css           # Modern SOC dark cybersecurity stylesheet
│       └── components/
│           ├── Dashboard.jsx            # Scorecard overview & key metrics
│           ├── ConfigurationPanel.jsx   # Interactive VPN parameters & PCAP dropzone
│           ├── AnalysisResult.jsx       # AI breakdown & SA parameter registry
│           ├── RiskMatrix.jsx           # Categorized findings & Threat Matrix
│           ├── TrafficAnalysis.jsx      # Telemetry & MTU size charts
│           ├── ComparePanel.jsx         # Side-by-side configuration diff tool
│           ├── ReportPanel.jsx          # Executive report & HTML report download
│           └── ArchitectureView.jsx     # Visual 9-stage dataflow pipeline
│
└── README.md                    # Installation & Hackathon demonstration guide
```

---

## Prerequisites

- **Python**: 3.10 or higher
- **Node.js**: 18.0 or higher
- **npm**: 9.0 or higher
- **VS Code** (recommended editor)

---

## Quick Start (Run Locally in VS Code)

### Step 1: Open Project in VS Code
Open VS Code and navigate to the project directory:
```bash
cd C:\Users\TARUN\.gemini\antigravity\scratch\IPsecGuard-AI
```

---

### Step 2: Start the FastAPI Backend
Open a new VS Code terminal (`Ctrl + Shift + \``):

```powershell
# Navigate to backend directory
cd backend

# Create a virtual environment (optional but recommended)
python -m venv venv

# Activate virtual environment:
# Windows PowerShell:
.\venv\Scripts\Activate.ps1
# (or Command Prompt: venv\Scripts\activate.bat)

# Install required packages
pip install -r requirements.txt

# Start FastAPI server on port 8000
uvicorn main:app --reload --port 8000
```

> **Verification**: Open [http://localhost:8000/api/health](http://localhost:8000/api/health) in your browser. It should return:
> `{"status": "online", "service": "IPsecGuard AI", "version": "1.0.0"}`

---

### Step 3: Start the React Frontend
Open a **second** terminal tab in VS Code (`Ctrl + Shift + 5` or click `+`):

```powershell
# Navigate to frontend directory
cd frontend

# Install Node dependencies
npm install
# (Note: On Windows PowerShell if scripts are restricted, run: npm.cmd install)

# Start Vite development server
npm run dev
# (or: npm.cmd run dev)
```

> **Application URL**: Open **[http://localhost:5173](http://localhost:5173)** in your browser!  
> The dashboard will immediately load, connect to the backend, and display the baseline analysis.

---

### Alternative: Single-Port Production Mode (FastAPI Only)
If you prefer running everything from a **single terminal** without launching the Vite dev server:
```powershell
# In frontend directory, build the production bundle:
cd frontend
npm.cmd run build

# In backend directory, run FastAPI:
cd ../backend
uvicorn main:app --reload --port 8000
```
FastAPI automatically serves the built React web UI at **[http://localhost:8000/](http://localhost:8000/)**!

---

## 2–3 Minute Hackathon Demonstration Flow

Here is the exact sequence to demonstrate to judges:

1. **Initial Showcase (Dashboard)**:
   - Point out the dark SOC dashboard, live backend status indicator, **Security Score (100/100)**, **LOW RISK** badge, and **94% AI Confidence**.
   - Show the 8 cryptographic metric cards (IKEv2, Tunnel Mode, AES-256, HMAC-SHA256, DH Group 20, PFS Enabled).

2. **The Contrast Demo (Legacy VPN Vulnerability Exposure)**:
   - At the top bar, click the **"Legacy VPN"** demo dataset button and click **"Run Live Analysis"** (or select it in the VPN Analyzer tab).
   - Watch the Security Score drop dramatically from **100/100 down to 5/100 (CRITICAL RISK)**!
   - Navigate to **"Security Assessment"**: Show how the framework flagged:
     - *Deprecated Cipher (AES-128-CBC)* & Sweet32 / padding oracle vulnerability.
     - *Deprecated Integrity (HMAC-SHA1)* with collision warnings.
     - *Weak Diffie-Hellman Group 2 (1024-bit)* susceptible to Logjam precomputations.
     - *PFS Disabled* risking retroactive session decryption.
     - *Replay Protection Disabled* exposing packet injection vectors.

3. **Explore the AI Confidence Engine**:
   - Navigate to **"Protocol & SA Inspection"**.
   - Show the table differentiating **DETECTED** from **INFERRED** attributes. Highlight that our AI does *not* hallucinate secret keys; it marks payload ciphers as inferred while validating framing headers empirically.

4. **Compare Configurations (Side-by-Side Diff)**:
   - Click **"Compare Configurations"**.
   - Run the comparison between *Legacy VPN* vs *Strong Enterprise VPN*.
   - Point out the **+95 Score Delta** and component-by-component cryptographic advantages.

5. **Mode 2 — Packet Capture Upload (.pcap)**:
   - Click **"VPN Analyzer"** and scroll to the upload area.
   - Click the download link for `Enterprise.pcap` or `Legacy.pcap` (or use any custom capture).
   - Drag and drop the `.pcap` file.
   - Show that the backend immediately parses the wire frames, extracts SPIs (`0x8F3C92A1`), detects ESP protocol 50, and updates the Traffic Analysis charts.

6. **Executive Report Generation**:
   - Navigate to **"Reports & Export"**.
   - Toggle between **Executive Summary** and **Technical Audit**.
   - Click **"Download Report (HTML/PDF)"** to download a self-contained security audit certificate ready for executive review.

---

## SIH Problem Statement Alignment

| SIH Requirement | How IPsecGuard AI Satisfies It | Implementation File |
| :--- | :--- | :--- |
| **1. VS Code Execution** | Standard dual-directory structure with zero custom path requirements; runs with standard terminal commands. | `backend/`, `frontend/` |
| **2. Real Backend-Frontend Connection** | Full REST API communication over FastAPI + Axios/Fetch with CORS middleware. | `frontend/src/api.js`, `backend/main.py` |
| **3. Runs on Normal Laptop** | Pure Python & standard React. No GPU or external database required. | Entire repository |
| **4. Not Just a Mockup** | Real mathematical scoring, actual binary PCAP parsing, dynamic comparison, and live report downloads. | `security_engine.py`, `analyzer.py` |
| **5. Zero Paid APIs** | Fully local explainable heuristic AI and RFC rule engine. No OpenAI, AWS, or cloud bills. | `analyzer.py`, `security_engine.py` |
| **6. Demo Dataset Mode** | 5 built-in ground-truth datasets for instant demonstration without live VPN hardware. | `backend/sample_data.py` |
| **7. Upload Capture Mode** | Supports `.pcap` and `.pcapng` uploads with pure Python binary fallback parser. | `backend/analyzer.py` |
| **8. Detected vs Inferred Distinction** | Clearly tags each parameter and explains evidence to prevent security hallucinations. | `backend/analyzer.py`, `AnalysisResult.jsx` |
| **9. Interactive Threat Matrix** | Dynamic attack vector matrix with severity, likelihood, impact, and mitigation status. | `RiskMatrix.jsx`, `security_engine.py` |
| **10. Downloadable Reports** | Generates standalone, self-contained HTML audit reports for offline distribution. | `backend/report_generator.py` |

---

## Real Analysis vs. Simulated/Demo Features

In defensive protocol analysis, certain fields are physically inaccessible over the wire without the secret pre-shared key or private keys. Here is our transparent disclosure:

### Real Analysis Features:
- **Binary PCAP & PCAPNG Header Parsing**: Reads actual Libpcap binary records, Ethernet headers, IPv4/IPv6 headers, UDP ports, and protocol numbers.
- **Protocol & Encapsulation Detection**: Identifies ESP (protocol 50), AH (protocol 51), ISAKMP (port 500), and NAT-Traversal (port 4500) directly from packet headers.
- **SPI & Sequence Inspection**: Extracts raw 32-bit Security Parameter Indexes (SPIs) and sequence numbers from packet data.
- **Packet Sizing & Distribution**: Analyzes wire length to build MTU size histograms and compute encrypted traffic ratios.
- **100-Point Security Deductions**: Evaluates cryptographic parameters against NIST SP 800-77, CVE databases (Sweet32, Logjam), and RFC standards.
- **Report Generation**: Dynamically compiles standalone HTML audit reports with CSS styling.

### Inferred / Simulated Features:
- **Payload Cipher Identification in PCAPs**: Because ESP payloads are cryptographically secure, the exact inner cipher (e.g., AES-256 vs AES-128) cannot be known from ciphertext alone without keys; our AI engine tags this as **INFERRED** based on block padding length and declared SA policies.
- **Synthetic Packet Generator**: The `sample_data.py` module creates valid binary PCAP files on the fly so students and judges can test PCAP uploading even if they don't have Wireshark installed.

---

## Troubleshooting Guide

### 1. "python: command not recognized"
Ensure Python 3.10+ is added to your Windows PATH:
```powershell
# Check if python is accessible
py --version
# If py works, use `py -m pip install -r requirements.txt` and `py -m uvicorn main:app --reload`
```

### 2. "npm.ps1 cannot be loaded because running scripts is disabled"
Windows PowerShell restricts `.ps1` scripts by default. Either run the `.cmd` version or adjust execution policy:
```powershell
# Option A (Easiest):
npm.cmd install
npm.cmd run dev

# Option B (Change policy for current session):
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
npm run dev
```

### 3. "Port 8000 or 5173 already in use"
To run on alternate ports:
```powershell
# Backend on port 8080:
uvicorn main:app --reload --port 8080

# Frontend on port 3000:
npm run dev -- --port 3000
```

### 4. CORS Error in Browser Console
The FastAPI backend includes `CORSMiddleware` with `allow_origins=["*"]`. Ensure the backend server is running and reachable on `http://localhost:8000`.

---

## Standards & References

- **NIST SP 800-77 Rev. 1**: *Guide to IPsec VPNs*
- **RFC 4301**: *Security Architecture for the Internet Protocol*
- **RFC 7296**: *Internet Key Exchange Protocol Version 2 (IKEv2)*
- **RFC 8221**: *Cryptographic Algorithm Implementation Requirements for ESP and AH*
- **CVE-2016-2183**: *Sweet32 Birthday Attack on 64-bit Block Ciphers*
- **Logjam Research**: *Imperfect Forward Secrecy: How Diffie-Hellman Fails in Practice*

---

*Built with precision for the Smart India Hackathon &bull; Defensive Cyber Assurance Framework*
