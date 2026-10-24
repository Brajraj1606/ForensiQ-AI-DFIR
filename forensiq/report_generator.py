"""
ForensiQ AI - Forensic Report Generation Engine
Generates court-admissible markdown and PDF investigation reports conforming to NIST SP 800-86.
"""

from typing import Dict, Any, List
from datetime import datetime
import csv
import io
from .hasher import generate_custody_seal


def sanitize_csv_cell(value: Any) -> str:
    """
    Protects against CSV Formula Injection (Dynamic Data Exchange / DDE attacks).
    Prepends a single quote if string begins with =, +, -, @, tab, or carriage return.
    """
    val_str = str(value or "")
    if val_str.startswith(('=', '+', '-', '@', '\t', '\r')):
        return f"'{val_str}"
    return val_str


def export_timeline_csv(timeline_events: List[Dict[str, Any]]) -> str:
    """Exports normalized timeline events to sanitized CSV format."""
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
    writer.writerow([
        "Event_ID",
        "Timestamp_UTC",
        "Event_Type",
        "Severity",
        "MITRE_ID",
        "Summary",
        "Process_Name",
        "Source_Artifact"
    ])

    for e in timeline_events:
        writer.writerow([
            sanitize_csv_cell(e.get('id', '')),
            sanitize_csv_cell(e.get('timestamp', '')),
            sanitize_csv_cell(e.get('event_type', '')),
            sanitize_csv_cell(e.get('severity', '')),
            sanitize_csv_cell(e.get('mitre_id', '')),
            sanitize_csv_cell(e.get('summary', '')),
            sanitize_csv_cell(e.get('process_name', '')),
            sanitize_csv_cell(e.get('source_artifact', ''))
        ])
    return output.getvalue()


def generate_markdown_report(
    case_data: Dict[str, Any],
    evidence_items: List[Dict[str, Any]],
    timeline_events: List[Dict[str, Any]],
    iocs: List[Dict[str, Any]],
    findings_text: str,
    examiner_notes: str = ""
) -> str:
    """Compiles a complete court-admissible investigation report."""
    report_date = datetime.utcnow().strftime("%Y-%m-%d")
    hashes = [e['sha256'] for e in evidence_items]
    seal = generate_custody_seal(case_data.get('case_id', 'CAS-001'), hashes, report_date)
    criticals = [e for e in timeline_events if e.get('severity') == 'CRITICAL' or e.get('is_anomaly')]

    evidence_section = "\n".join([
        f"- **{e['filename']}** ({e['file_type']}): SHA-256 `{e['sha256']}` | Device: {e.get('write_blocker_model', 'N/A')}"
        for e in evidence_items
    ])

    timeline_section = "\n".join([
        f"- `[{e['timestamp']}]` **{e['event_type']}** ({e['severity']}): {e['summary']} (MITRE: {e['mitre_id']})"
        for e in criticals[:8]
    ])

    iocs_section = "\n".join([
        f"- `{i['type']}`: `{i['value']}` ({i.get('threat_level', 'SUSPICIOUS')}) — {i.get('context', '')}"
        for i in iocs[:10]
    ])

    return f"""# OFFICIAL DIGITAL FORENSICS INVESTIGATION REPORT
**Case Reference:** {case_data.get('case_id', 'CAS-2026-0891')}
**Classification:** {case_data.get('classification', 'TLP:AMBER+STRICT')}
**Agency:** {case_data.get('agency', 'Cyber Incident Response Unit')}
**Lead Examiner:** {case_data.get('examiner_name', 'Lead Examiner')}
**Date of Report:** {report_date}
**Cryptographic Custody Seal:** `{seal}`

---

## 1. EXECUTIVE SUMMARY & SCOPE
{case_data.get('case_summary', 'Digital forensic triage of compromised hosts.')}

## 2. EVIDENCE CHAIN OF CUSTODY (ISO/IEC 27037)
All evidence was acquired with hardware write-blocking verification:
{evidence_section}

## 3. CHRONOLOGICAL ATTACK TIMELINE HIGHLIGHTS
{timeline_section}

## 4. DETECTED INDICATORS OF COMPROMISE (IOCs)
{iocs_section}

## 5. TECHNICAL FORENSIC FINDINGS & ROOT CAUSE ANALYSIS
{findings_text}

## 6. EXAMINER DECLARATION & SIGN-OFF
{examiner_notes or 'All findings conform to the Federal Rules of Evidence Rule 901.'}

**Signed by Examiner:** {case_data.get('examiner_name')}
**Attestation Seal:** `{seal}`
"""
