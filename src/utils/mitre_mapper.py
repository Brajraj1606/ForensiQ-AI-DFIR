"""
ForensiQ AI - MITRE ATT&CK Enterprise Matrix Correlation
Maps normalized events to tactics and technique IDs.
"""

from typing import List, Dict, Any

TACTIC_MAP = [
    {"id": "TA0001", "name": "Initial Access"},
    {"id": "TA0002", "name": "Execution"},
    {"id": "TA0003", "name": "Persistence"},
    {"id": "TA0004", "name": "Privilege Escalation"},
    {"id": "TA0005", "name": "Defense Evasion"},
    {"id": "TA0006", "name": "Credential Access"},
    {"id": "TA0007", "name": "Discovery"},
    {"id": "TA0008", "name": "Lateral Movement"},
    {"id": "TA0011", "name": "Command and Control"},
    {"id": "TA0040", "name": "Impact"},
]


def map_events_to_mitre(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Aggregates forensic events into MITRE ATT&CK Enterprise tactics and techniques."""
    results = []

    for tactic in TACTIC_MAP:
        t_id = tactic["id"]
        techniques = []

        if t_id == "TA0040":  # Impact
            vss_evts = [e for e in events if "vssadmin" in str(e).lower()]
            if vss_evts:
                techniques.append({
                    "id": "T1490",
                    "name": "Inhibit System Recovery",
                    "count": len(vss_evts),
                    "severity": "CRITICAL",
                })

        elif t_id == "TA0005":  # Defense Evasion
            clear_evts = [e for e in events if "1102" in str(e).lower() or "audit log" in str(e).lower() or "wevtutil" in str(e).lower()]
            if clear_evts:
                techniques.append({
                    "id": "T1070.001",
                    "name": "Indicator Removal: Clear Event Logs",
                    "count": len(clear_evts),
                    "severity": "CRITICAL",
                })

        elif t_id == "TA0002":  # Execution
            ps_evts = [e for e in events if "powershell" in str(e).lower() or "cmd.exe" in str(e).lower()]
            if ps_evts:
                techniques.append({
                    "id": "T1059.001",
                    "name": "Command and Scripting Interpreter: PowerShell",
                    "count": len(ps_evts),
                    "severity": "HIGH",
                })

        elif t_id == "TA0006":  # Credential Access
            fail_evts = [e for e in events if "4625" in str(e).lower() or "failed to log on" in str(e).lower()]
            if fail_evts:
                techniques.append({
                    "id": "T1110",
                    "name": "Brute Force / Password Guessing",
                    "count": len(fail_evts),
                    "severity": "MEDIUM",
                })

        results.append({
            "id": tactic["id"],
            "name": tactic["name"],
            "techniques": techniques,
        })

    return results
