# Contributing to ForensiQ AI

Thank you for your interest in contributing to **ForensiQ AI**! We are participating in **Hacktoberfest 2026** and welcome contributors of all skill levels, especially students and practitioners in Cyber Security, Digital Forensics, and Machine Learning.

---

## 1. Code of Conduct

All contributors are expected to uphold our [Code of Conduct](CODE_OF_CONDUCT.md). Please treat all members of the community with empathy, respect, and constructive collaboration.

---

## 2. Hacktoberfest 2026 Participation

ForensiQ AI is a community-first open-source initiative. To make your PRs count toward Hacktoberfest:
- Look for issues labeled `hacktoberfest`, `good first issue`, or `help wanted`.
- Focus on quality over quantity: we do not accept spam, automated bot PRs, or minor cosmetic churn.
- All contributions must pass the automated test suite (`python3 -m unittest tests/test_forensics.py`).

---

## 3. High-Priority Contribution Areas

1. **New Artifact Parsers:** Parsers for macOS Unified Logs, Linux `auditd`, Apache/Nginx web access logs, and Windows Registry hives (`NTUSER.DAT`).
2. **Detection Rules:** Deterministic rules mapped to MITRE ATT&CK techniques (TA0001 - TA0040) in `forensiq/rules_engine.py`.
3. **Local LLM Models:** Connectors and prompt templates for open-weight models via Ollama (`llama3.2`, `mistral`, `deepseek-r1`, `phi-3`).
4. **Forensic Reporting Formats:** Enhancing court-admissible PDF output with ReportLab or FPDF2.
5. **Academic Case Scenarios:** Adding synthetic, sanitized forensic incident packages in `samples/` for student lab exercises.

---

## 4. Development Workflow

### A. Fork and Clone
```bash
git clone https://github.com/your-username/forensiq-ai.git
cd forensiq-ai
```

### B. Environment Setup
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### C. Run the Test Suite
Ensure all unit and security tests pass:
```bash
python3 -m unittest tests/test_forensics.py
```
Or via `pytest`:
```bash
pytest tests/ -v
```

### D. Coding Guidelines
- **Evidence before conclusions:** Detection rules and parsers must strictly cite verifiable records; never invent or extrapolate timestamps or confidence scores.
- **DDE Injection Defense:** Any exported tabular data must sanitize cells with `sanitize_csv_cell()` to prevent spreadsheet formula injection.
- **SQL Injection Prevention:** Use parameterized queries (`?`) for all SQLite database interactions.
- **Type Hints:** Use standard Python type annotations (`typing.List`, `typing.Dict`, `typing.Optional`).

---

## 5. Submitting a Pull Request

1. Create a feature branch: `git checkout -b feature/new-parser`
2. Commit changes with clear, descriptive messages.
3. Push to your fork: `git push origin feature/new-parser`
4. Open a Pull Request referencing the related issue ID.
5. Ensure CI tests pass and address review comments proactively.
