# ForensiQ AI: An Open-Source AI-Assisted Digital Forensics Investigation Platform

[![Hacktoberfest 2026](https://img.shields.io/badge/Hacktoberfest-2026%20Candidate-blueviolet)](https://hacktoberfest.com/)
[![Standard: ISO/IEC 27037](https://img.shields.io/badge/Forensic%20Standard-ISO%2FIEC%2027037-blue)](https://www.iso.org/standard/44381.html)
[![Standard: NIST SP 800-86](https://img.shields.io/badge/NIST-SP%20800--86-green)](https://csrc.nist.gov/pubs/sp/800/86/final)
[![Evidence Admissibility](https://img.shields.io/badge/Legal%20Standard-FRE%20Rule%20901-darkred)](https://www.rulesofevidence.org/article-ix/rule-901/)
[![Tests](https://img.shields.io/badge/Tests-100%25%20Passing-success)](tests/test_forensics.py)

---

## 1. Project Overview & Mission

**ForensiQ AI** is an open-source, evidence-aware digital forensics and incident response (DFIR) workstation. Developed for **Hacktoberfest 2026 (Best Open-Source AI Project)**, it bridges academic digital forensics principles with transparent, explainable AI assistance.

### Core Philosophy: Evidence Before Conclusions
Unlike generic LLM chatbots that hallucinate or provide unverified advice, ForensiQ AI adheres to strict forensic science tenets:
1. **Preserve Bitstream Integrity:** Computes and verifies SHA-256 and MD5 cryptographic hashes on ingest (ISO/IEC 27037).
2. **Explainable Findings:** Explicitly segregates `[OBSERVED FACTS]`, `[DETERMINISTIC RULES]`, `[AI INTERPRETATIONS]`, and `[UNVERIFIED HYPOTHESES]`.
3. **No Cloud or Paid API Dependency:** 100% operational offline using local Ollama open-weight models (`llama3.2`, `mistral`, `deepseek-r1`) or deterministic rule heuristics.
4. **Human Investigator Oversight:** Digital signatures, examiner attestation notes, and tamper-evident custody seals.

---

## 2. Architecture & File Structure

```text
├── forensiq/                       # Core Python Forensic Library
│   ├── hasher.py                   # SHA-256 / MD5 hashing & ISO 27037 custody seals
│   ├── db.py                       # SQLite case, evidence, and audit ledger persistence
│   ├── ioc_extractor.py            # Deterministic IOC parser (IPs, LOLBins, CVEs, Hashes)
│   ├── timeline.py                 # Multi-format log parser with anomaly classification
│   ├── mitre.py                    # Enterprise MITRE ATT&CK Matrix mapping (TA0001 - TA0040)
│   ├── ollama_client.py            # Local Ollama connector + deterministic fallback engine
│   └── report_generator.py         # NIST SP 800-86 compliant Markdown & PDF generator
├── tests/
│   └── test_forensics.py           # Automated test suite (compatible with pytest & unittest)
├── app.py                          # Streamlit web application frontend
├── forensiq_cli.py                 # Standalone terminal investigation CLI
├── requirements.txt                # Pinned Python dependencies
├── src/                            # High-Performance Interactive Web Applet (Port 3000)
│   ├── App.tsx                     # Analyst workstation UI (Dark DFIR palette)
│   ├── components/                 # Evidence Locker, Timeline, MITRE Matrix, Hex Inspector
│   └── forensics/                  # TypeScript forensic verification modules
├── server.ts                       # Full-stack backend proxy with Gemini 3.8 Flash
└── README.md                       # Complete documentation
```

---

## 3. Quickstart & Testing Instructions

### A. Run Automated Unit Tests (0 Dependencies Required)
The core forensic verification suite runs out-of-the-box using Python's built-in `unittest` runner:
```bash
python3 -m unittest tests/test_forensics.py
```
Or via `pytest`:
```bash
pytest tests/
```

### B. Use the Command-Line Forensics Utility
Compute file hashes, verify bitstreams, or triage logs directly from the terminal:
```bash
# 1. Compute SHA-256 and MD5 cryptographic hashes
python3 forensiq_cli.py hash "Suspicious payload sample"

# 2. Extract IOCs from a log file
python3 forensiq_cli.py extract-iocs path/to/logs.evtx

# 3. Triage an incident and detect anti-forensic anomalies
python3 forensiq_cli.py triage path/to/logs.evtx --case CAS-2026-0891

# 4. Generate court-admissible report
python3 forensiq_cli.py report CAS-2026-0891 path/to/logs.evtx --out case_report.md
```

### C. Launch the Streamlit Web Application
Install requirements and launch the browser interface:
```bash
pip install -r requirements.txt
streamlit run app.py
```

### D. Run with Local Ollama (Optional)
If you have Ollama installed on your machine:
```bash
ollama run llama3.2
```
ForensiQ AI will automatically detect the local daemon at `http://localhost:11434` and use it for local open-weight inference. If Ollama is offline, ForensiQ seamlessly activates its deterministic rule engine with zero disruption!

---

## 4. Digital Forensics Standards Compliance

- **ISO/IEC 27037:** Enforces write-blocker tracking and bitstream verification at every stage of the evidence lifecycle.
- **RFC 3227 Order of Volatility:** Prioritizes volatile memory (RAM, active network sockets) before non-volatile disk artifacts.
- **NIST SP 800-86:** Structures forensic reporting across Collection, Examination, Analysis, and Reporting phases.
- **Federal Rules of Evidence Rule 901:** Authenticates electronic evidence via unbroken Chain of Custody hashes to ensure court admissibility.
