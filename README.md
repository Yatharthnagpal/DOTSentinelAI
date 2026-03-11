# DOT Sentinel AI 🛡️
### Autonomous Network Intrusion Detection & Security Posture Intelligence

[![Live Demo](https://img.shields.io/badge/Live%20Dashboard-dot--sentinel--ai.vercel.app-009dff?style=for-the-badge&logo=vercel)](https://dot-sentinel-ai.vercel.app/)

> **🌐 Live Deployment:** [https://dot-sentinel-ai.vercel.app/](https://dot-sentinel-ai.vercel.app/)

DOT Sentinel AI is a next-generation cybersecurity platform designed to bridge the gap between raw network telemetry and actionable SOC intelligence. It autonomously parses network packet captures (PCAP), detects zero-day anomalies using unsupervised machine learning, audits defensive posture across 4 security pillars, and translates complex security telemetry into executive threat advisories using Agentic AI and the MITRE ATT&CK framework.

---

## 📌 Core Capabilities

1. **Autonomous Network Intrusion Detection:**
   - Ingests raw PCAP and PCAPNG traffic captures.
   - Extracts flow-level statistical features with high-throughput aggregation.
   - Identifies zero-day anomalies and multi-flow attack campaigns via **Isolation Forest** and supervised classifiers.
   - Synthesizes incident analyses using **Google Gemini (Agentic AI)**.
   - Maps detected attack techniques directly to the **MITRE ATT&CK Enterprise Matrix**.

2. **Full-Spectrum Vulnerability & Posture Scanner:**
   - **⚙️ System & Software Configuration:** Detects End-of-Life (EOL) operating systems, evaluates application CVE patch status (Log4Shell, Heartbleed, EternalBlue, Spring4Shell), identifies factory default credentials, flags 20+ legacy cleartext services, and audits data-in-transit (TLS 1.2/1.3) and data-at-rest encryption.
   - **🔑 Identity & Access Controls:** Audits global MFA enforcement, validates password policies against **NIST SP 800-63B**, flags excessive administrative accounts, and identifies dormant/orphaned accounts.
   - **🌐 Network & Border Defenses:** Audits firewall ACL rules for overly permissive Any-to-Any entries, identifies public exposure of admin ports, verifies 6 critical HTTP security headers (CSP, HSTS, X-Frame-Options, nosniff), and detects server banner information leakage.
   - **📝 Monitoring & Resilience:** Audits centralized SIEM telemetry across 4 critical event streams, evaluates log retention policies ($\ge 365$ days), and validates 3-2-1 backup architecture with ransomware-resistant immutable (WORM) storage.

---

## 🧰 Technology Stack

| Layer | Technologies |
|---|---|
| **Data Ingestion & Parsing** | PCAP / PCAPNG, Scapy, Tshark, Wireshark |
| **Feature Engineering & ML** | Python 3, Pandas, NumPy, Scikit-learn (Isolation Forest) |
| **Agentic AI Layer** | Google AI Studio (Gemini), Custom Prompt Engineering, MITRE ATT&CK |
| **Backend Core** | FastAPI, Uvicorn, SQLite, Aiofiles, Pydantic v2 |
| **Frontend & UI** | React 19, Vite, GSAP Animations, Chart.js, Custom Cyber Aesthetics |

---

## 🔄 End-to-End Workflow

```
[ Upload PCAP / Posture Config ]
              │
              ▼
    [ Flow & Feature Extraction ]
              │
              ▼
   [ Unsupervised Anomaly Detection ] ──► [ 4-Pillar Vulnerability Audit ]
              │                                      │
              └───────────────┬──────────────────────┘
                              │
                              ▼
           [ Agentic AI Threat Synthesis (Gemini) ]
                              │
                              ▼
           [ MITRE ATT&CK Mapping & SOC Dashboard ]
```

---

## 🚀 Quick Start Guide

### Prerequisites
* Python 3.10+
* Node.js 18+ & npm

### 1. Backend Setup
```bash
# Navigate to project root
cd Dot-Sentinel

# Install Python dependencies
pip install -r requirements.txt

# Start FastAPI server
python -m uvicorn parser.main:app --host 0.0.0.0 --port 8000 --reload
```
API Documentation will be available at `http://localhost:8000/docs`.

### 2. Frontend Setup
```bash
# Navigate to Frontend directory
cd Front-End

# Install dependencies
npm install

# Start Vite dev server
npm run dev
```
Access the interactive dashboard at `http://localhost:5173`.

---

## 🛡️ Security Operations (SOC) Value

* **Zero-Day Resilience:** Isolation Forest anomaly scoring flags deviations without requiring historical attack signatures.
* **Explainable AI:** Converts low-level packet metrics into plain-English root-cause explanations and prioritized 72-hour remediation playbooks.
* **Standardized Taxonomy:** Every anomaly and posture deficiency is tagged with standard MITRE ATT&CK technique IDs for seamless SIEM/SOAR integration.

---

## 📄 License & Attribution

This project is licensed under the MIT License — see the LICENSE file for details.
