# Security Policy for ForensiQ AI

## 1. Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x     | :white_check_mark: |
| 1.x     | :x:                |

---

## 2. Security Boundaries & Architecture

ForensiQ AI is designed as a **read-only digital forensics analysis tool**. It operates under strict security boundaries:

- **No Remote Code Execution:** ForensiQ AI parses text, logs, JSON, and memory dumps as passive data. It will **never** execute uploaded files or binary blobs.
- **Untrusted Evidence Treatment:** All imported log messages, command strings, and metadata are treated as untrusted data. When analyzed by local LLMs (Ollama) or server proxies, evidence is enclosed within strict data delimiters to prevent prompt-injection attacks.
- **No Autonomous Network Scanning:** ForensiQ AI does not perform port scans, ping sweeps, or active network discovery. It processes forensic telemetry passively.
- **CSV Formula Injection (DDE) Defense:** All exported tabular files sanitize cell values starting with `=, +, -, @, \t, \r` with leading quotes to prevent spreadsheet execution vulnerabilities.
- **Local Storage Confidentiality:** SQLite metadata operations use parameterized SQL queries (`?`) to guarantee immunity to SQL injection.

---

## 3. Synthetic Data Policy

- All sample logs and default datasets in this repository are **100% synthetic**.
- **Do not commit real victim telemetry, private credentials, unredacted corporate logs, or live malware binaries** to issues, PRs, or test files.

---

## 4. Reporting a Vulnerability

If you discover a potential security vulnerability in ForensiQ AI, please report it privately:

1. **Email:** Send details to `security@forensiq-ai.org` or open a GitHub Private Security Advisory.
2. **Details:** Include a description of the issue, affected files/modules, and a reproducible Proof-of-Concept (PoC).
3. **Response:** Maintainers will acknowledge receipt within 48 hours and provide remediation updates before public disclosure.
