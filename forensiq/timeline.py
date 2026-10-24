"""
ForensiQ AI - Chronological Timeline Parsing & Anomaly Reconstruction
Normalizes multi-source logs into structured event objects.
"""

import re
from datetime import datetime
from typing import List, Dict, Any


def parse_timeline(raw_text: str, artifact_name: str, id_prefix: str = "EVT") -> List[Dict[str, Any]]:
    """Extracts chronological events with severity and MITRE ATT&CK technique classifications."""
    lines = [l.strip() for l in raw_text.splitlines() if l.strip() and not l.strip().startswith(('#', '//'))]
    events: List[Dict[str, Any]] = []

    for idx, line in enumerate(lines, start=1):
        iso_match = re.search(r'\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{3})?(?:Z|[+-]\d{2}:?\d{2})?)\b', line)
        if iso_match:
            ts = iso_match.group(1).replace(' ', 'T')
            if not ts.endswith('Z') and '+' not in ts:
                ts += 'Z'
        else:
            ts = datetime.utcnow().isoformat() + "Z"

        lower = line.lower()
        severity = "LOW"
        event_type = "System Event"
        summary = line[:100]
        mitre_tactic = "TA0007 Discovery"
        mitre_tech = "System Information Discovery"
        mitre_id = "T1082"
        is_anomaly = False

        if 'vssadmin' in lower and 'delete' in lower:
            event_type = "Shadow Copy Invalidation"
            summary = "Adversary executed vssadmin to delete volume shadow copies"
            severity = "CRITICAL"
            mitre_tactic = "TA0040 Impact"
            mitre_tech = "Inhibit System Recovery"
            mitre_id = "T1490"
            is_anomaly = True
        elif '1102' in lower or 'wevtutil cl' in lower or ('audit log' in lower and 'clear' in lower):
            event_type = "Forensic Log Cleared"
            summary = "Security Event Log was purposefully cleared (Event ID 1102)"
            severity = "CRITICAL"
            mitre_tactic = "TA0005 Defense Evasion"
            mitre_tech = "Indicator Removal: Clear Event Logs"
            mitre_id = "T1070.001"
            is_anomaly = True
        elif 'page_execute_readwrite' in lower or 'malfind' in lower:
            event_type = "Memory Injection (RWX)"
            summary = "VAD allocation with PAGE_EXECUTE_READWRITE permissions detected"
            severity = "CRITICAL"
            mitre_tactic = "TA0004 Privilege Escalation"
            mitre_tech = "Process Injection: Dynamic-link Library Injection"
            mitre_id = "T1055.001"
            is_anomaly = True
        elif '7045' in lower or 'new service was installed' in lower:
            event_type = "Service Installation"
            summary = "New system service created (Windows Event 7045)"
            severity = "HIGH"
            mitre_tactic = "TA0003 Persistence"
            mitre_tech = "Create or Modify System Process: Windows Service"
            mitre_id = "T1543.003"
        elif '4625' in lower or 'logon failure' in lower:
            event_type = "Failed Authentication"
            summary = "Account logon failure detected (Windows Event 4625)"
            severity = "MEDIUM"
            mitre_tactic = "TA0006 Credential Access"
            mitre_tech = "Brute Force: Password Guessing"
            mitre_id = "T1110.001"
        elif '4624' in lower or 'successfully logged on' in lower:
            event_type = "Logon Succeeded"
            summary = "Successful authentication session established (Event 4624)"
            severity = "LOW"
            mitre_tactic = "TA0001 Initial Access"
            mitre_tech = "Valid Accounts"
            mitre_id = "T1078"
        elif '4688' in lower or 'new process has been created' in lower:
            event_type = "Process Execution"
            summary = "New process spawned (Windows Event 4688)"
            severity = "MEDIUM"
            mitre_tactic = "TA0002 Execution"
            mitre_tech = "Command and Scripting Interpreter"
            mitre_id = "T1059"

        proc_match = re.search(r'\b([a-zA-Z0-9_\-\.]+\.(?:exe|dll|sys|sh|py))\b', line, re.IGNORECASE)
        process_name = proc_match.group(1) if proc_match else None

        events.append({
            'id': f"{id_prefix}-{idx:04d}",
            'timestamp': ts,
            'source_artifact': artifact_name,
            'event_type': event_type,
            'summary': summary,
            'raw_details': line,
            'process_name': process_name,
            'mitre_tactic': mitre_tactic,
            'mitre_technique': mitre_tech,
            'mitre_id': mitre_id,
            'severity': severity,
            'is_anomaly': is_anomaly
        })

    return events
