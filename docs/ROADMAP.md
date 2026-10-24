# ForensiQ AI: Project Roadmap

Planned improvements and community milestones for **Hacktoberfest 2026** and beyond:

---

## Phase 1: Core Foundation (Current Release v2.4) :white_check_mark:
- [x] ISO/IEC 27037 compliant bitstream SHA-256 and MD5 hashing.
- [x] Chain of Custody audit ledger with tamper-evident seals.
- [x] Multi-source log normalization (EVTX, Syslog, JSON, CSV).
- [x] Deterministic suspicious activity detection rules (Volume Shadow deletion, Event 1102 log clearing, Memory RWX, LOLBins).
- [x] Chronological timeline reconstruction and anomaly classification.
- [x] Dual interface: High-density Web Workstation (Port 3000) + Streamlit Python UI (`app.py`).
- [x] Local Ollama integration with 100% deterministic offline fallback.
- [x] Automated test suite (Pytest & Python Unittest, 100% passing).
- [x] Anti-CSV formula injection (DDE) protection.

---

## Phase 2: Enhanced Artifact Parsing (Q4 2026)
- [ ] **Native EVTX Binary Parser:** Pure Python parser for binary Windows Event Log chunk headers without external dependencies.
- [ ] **Volatility 3 Framework Bridge:** Direct API connector for Volatility 3 `windows.malfind`, `windows.pslist`, and `windows.netscan` outputs.
- [ ] **Windows Registry Hive Inspection:** Extract Shimcache, Amcache, Shellbags, and USBSTOR keys directly into timeline events.
- [ ] **PCAP / Packet Stream Dissector:** Scapy / PyShark integration for passive DNS tunnel and TLS SNI exfiltration analysis.

---

## Phase 3: Detection Engineering & Threat Intel (Q1 2027)
- [ ] **Sigma-to-Splunk/Elastic Transpiler:** Automatically convert discovered case rules into Splunk SPL and Elasticsearch KQL queries.
- [ ] **STIX / TAXII 2.1 Exporter:** Export extracted IOCs in standardized JSON bundles for MISP or ThreatConnect platforms.
- [ ] **YARA Compiler Validation:** In-app syntax validation using `yara-python`.

---

## Phase 4: Academic & Courtroom Reporting (Q2 2027)
- [ ] **Cryptographic PDF Signatures:** Integrate X.509 examiner certificates for digitally sealed PDF reports.
- [ ] **Daubert Hearing Export Pack:** Automatically generate technical methodology briefs detailing error rates and verification manifests for expert witness testimony.
