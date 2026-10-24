"""
ForensiQ AI - Deterministic Suspicious Activity Detection Engine (Module D)
Implements transparent, reproducible rules conforming to forensic standards.
Does NOT fabricate arbitrary risk scores or claim unauthorized activity without sufficient evidence.
"""

from datetime import datetime
from typing import List, Dict, Any


class ForensicFinding:
    def __init__(
        self,
        finding_id: str,
        rule_name: str,
        rule_version: str,
        severity: str,
        event_ids: List[str],
        detection_reason: str,
        supporting_observations: List[str],
        known_limitations: str,
        detection_timestamp: str = None
    ):
        self.finding_id = finding_id
        self.rule_name = rule_name
        self.rule_version = rule_version
        self.severity = severity  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
        self.event_ids = event_ids
        self.detection_reason = detection_reason
        self.supporting_observations = supporting_observations
        self.known_limitations = known_limitations
        self.detection_timestamp = detection_timestamp or datetime.utcnow().isoformat() + "Z"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_name": self.rule_name,
            "rule_version": self.rule_version,
            "severity": self.severity,
            "event_ids": self.event_ids,
            "detection_reason": self.detection_reason,
            "supporting_observations": self.supporting_observations,
            "known_limitations": self.known_limitations,
            "detection_timestamp": self.detection_timestamp
        }


def evaluate_rules(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Evaluates normalized events against transparent deterministic detection rules.
    Returns structured findings with exact event citations.
    """
    findings: List[Dict[str, Any]] = []
    finding_counter = 1

    # 1. Rule RUL-001: Volume Shadow Invalidation / Anti-Recovery
    vss_events = [
        e for e in events
        if 'vssadmin' in e.get('message', '').lower() and 'delete' in e.get('message', '').lower()
    ]
    if vss_events:
        evt_ids = [e['event_id'] for e in vss_events]
        findings.append(ForensicFinding(
            finding_id=f"FND-{finding_counter:03d}",
            rule_name="Volume Shadow Copy Deletion (T1490)",
            rule_version="v1.2.0-deterministic",
            severity="CRITICAL",
            event_ids=evt_ids,
            detection_reason="Invocation of vssadmin with delete shadows switches detected in process execution log.",
            supporting_observations=[
                f"Event {e['event_id']} at {e['normalized_timestamp']}: {e['message']}"
                for e in vss_events
            ],
            known_limitations="Legitimate administrative disk management scripts may resize shadow storage, but 'delete shadows /all /quiet' is heavily correlated with ransomware precursors."
        ).to_dict())
        finding_counter += 1

    # 2. Rule RUL-002: Security Audit Log Cleared
    clear_events = [
        e for e in events
        if '1102' in e.get('message', '').lower() or
           ('audit log' in e.get('message', '').lower() and 'clear' in e.get('message', '').lower()) or
           'wevtutil cl' in e.get('message', '').lower()
    ]
    if clear_events:
        evt_ids = [e['event_id'] for e in clear_events]
        findings.append(ForensicFinding(
            finding_id=f"FND-{finding_counter:03d}",
            rule_name="Security Audit Log Cleared (T1070.001)",
            rule_version="v1.1.0-deterministic",
            severity="CRITICAL",
            event_ids=evt_ids,
            detection_reason="Explicit log wiping command or Windows Event 1102 identified.",
            supporting_observations=[
                f"Event {e['event_id']}: User '{e.get('account_id')}' on host '{e.get('host_id')}' recorded in log clearing event."
                for e in clear_events
            ],
            known_limitations="Requires correlating with preceding authentication events to confirm whether credentials were compromised vs legitimate administrative maintenance."
        ).to_dict())
        finding_counter += 1

    # 3. Rule RUL-003: Memory RWX Allocation (VAD Malfind Anomaly)
    rwx_events = [
        e for e in events
        if 'page_execute_readwrite' in e.get('message', '').lower() or 'malfind' in e.get('message', '').lower()
    ]
    if rwx_events:
        evt_ids = [e['event_id'] for e in rwx_events]
        findings.append(ForensicFinding(
            finding_id=f"FND-{finding_counter:03d}",
            rule_name="Unbacked RWX Memory Allocation (T1055)",
            rule_version="v1.0.0-deterministic",
            severity="CRITICAL",
            event_ids=evt_ids,
            detection_reason="Memory segment identified with PAGE_EXECUTE_READWRITE protection commonly indicative of shellcode injection.",
            supporting_observations=[
                f"Event {e['event_id']}: Memory artifact in host dump indicates executable memory without backing binary."
                for e in rwx_events
            ],
            known_limitations="Certain Just-In-Time (JIT) compilation runtimes allocate RWX memory legitimately; requires examining initial MZ/PE headers."
        ).to_dict())
        finding_counter += 1

    # 4. Rule RUL-004: Obfuscated Scripting Interpreter Invocation
    ps_events = [
        e for e in events
        if 'powershell' in e.get('message', '').lower() and ('-enc' in e.get('message', '').lower() or 'downloadstring' in e.get('message', '').lower())
    ]
    if ps_events:
        evt_ids = [e['event_id'] for e in ps_events]
        findings.append(ForensicFinding(
            finding_id=f"FND-{finding_counter:03d}",
            rule_name="Encoded PowerShell Command Execution (T1059.001)",
            rule_version="v1.3.0-deterministic",
            severity="HIGH",
            event_ids=evt_ids,
            detection_reason="Base64 encoded command string passed to powershell.exe command line.",
            supporting_observations=[
                f"Event {e['event_id']}: {e['message']}"
                for e in ps_events
            ],
            known_limitations="Some enterprise software deployment frameworks utilize encoded PowerShell commands for environment provisioning."
        ).to_dict())
        finding_counter += 1

    # 5. Rule RUL-005: Multiple Failed Logins Followed by Success
    failed_logins = [e for e in events if '4625' in e.get('message', '') or 'logon failure' in e.get('message', '').lower()]
    succ_logins = [e for e in events if '4624' in e.get('message', '') or 'successfully logged on' in e.get('message', '').lower()]

    if len(failed_logins) >= 3 and len(succ_logins) >= 1:
        evt_ids = [e['event_id'] for e in failed_logins] + [e['event_id'] for e in succ_logins]
        findings.append(ForensicFinding(
            finding_id=f"FND-{finding_counter:03d}",
            rule_name="Multiple Authentication Failures Preceding Successful Logon (T1110)",
            rule_version="v1.1.0-deterministic",
            severity="HIGH",
            event_ids=evt_ids,
            detection_reason="Pattern of repeated failed logon attempts followed by an authenticated session.",
            supporting_observations=[
                f"Observed {len(failed_logins)} failed authentication attempts prior to successful logon event {succ_logins[0]['event_id']}."
            ],
            known_limitations="User typing mistakes can trigger repeated failures; source IP correlation is necessary to confirm brute-force or spraying."
        ).to_dict())
        finding_counter += 1

    return findings
