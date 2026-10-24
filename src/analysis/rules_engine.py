"""
ForensiQ AI - Transparent Rule-Based Detection Engine (Module D)
Conforms to scientific forensic principles:
- Transparent, deterministic, and fully reproducible rules.
- Discloses finding ID, rule name, severity, relevant event IDs, detection reason,
  supporting observations, detection timestamp, rule version, and known limitations.
- Does not label activity malicious purely because it is unusual.
- Does not claim logins were unauthorized without supporting evidence.
"""

from datetime import datetime, timezone
from typing import List, Dict, Any, TypedDict


class ForensicFinding(TypedDict):
    finding_id: str
    rule_name: str
    rule_version: str
    severity: str
    event_ids: List[str]
    detection_reason: str
    supporting_observations: List[str]
    detection_timestamp: str
    known_limitations: str


def evaluate_rules(events: List[Dict[str, Any]]) -> List[ForensicFinding]:
    """
    Evaluates normalized events against transparent, reproducible heuristic rules.
    Returns structured forensic findings with full provenance citations and limitations.
    """
    findings: List[ForensicFinding] = []
    finding_counter = 1
    now_utc = datetime.now(timezone.utc).isoformat()

    # Rule RUL-001 & RUL-002: Failed Login Sequence & Success After Repeated Failures
    failed_logons = [
        e for e in events
        if "4625" in e.get("event_type", "") or "failed to log on" in e.get("message", "").lower()
    ]
    successful_logons = [
        e for e in events
        if "4624" in e.get("event_type", "") or "successfully logged on" in e.get("message", "").lower()
    ]

    if len(failed_logons) >= 3:
        associated_ids = [e["event_id"] for e in failed_logons]
        obs = [f"Failed authentication event {e['event_id']} at {e.get('normalized_timestamp') or e.get('original_timestamp')}" for e in failed_logons]

        # Check for subsequent successful login (RUL-002: Possible Password Guessing / Brute Force Success)
        if successful_logons:
            first_success = successful_logons[0]
            associated_ids.append(first_success["event_id"])
            obs.append(f"Subsequent successful authentication {first_success['event_id']} by account '{first_success.get('account_id')}' at {first_success.get('normalized_timestamp') or first_success.get('original_timestamp')}")

            findings.append({
                "finding_id": f"FND-{finding_counter:03d}",
                "rule_name": "Multiple Authentication Failures Followed by Success (T1110)",
                "rule_version": "v1.3.0-deterministic",
                "severity": "HIGH",
                "event_ids": associated_ids,
                "detection_reason": (
                    f"Observed {len(failed_logons)} rapid authentication failures preceding a successful "
                    f"logon session for account '{first_success.get('account_id')}'. Suggests credential guessing, "
                    f"password spraying, or user password confusion."
                ),
                "supporting_observations": obs,
                "detection_timestamp": now_utc,
                "known_limitations": (
                    "Legitimate users may enter an incorrect password multiple times before entering "
                    "the correct one. Correlation with source IP and geographic location is necessary before "
                    "drawing conclusions of an external adversary."
                ),
            })
            finding_counter += 1
        else:
            findings.append({
                "finding_id": f"FND-{finding_counter:03d}",
                "rule_name": "Repeated Authentication Failures (T1110.001)",
                "rule_version": "v1.2.0-deterministic",
                "severity": "MEDIUM",
                "event_ids": associated_ids,
                "detection_reason": f"Observed {len(failed_logons)} failed logon events.",
                "supporting_observations": obs,
                "detection_timestamp": now_utc,
                "known_limitations": "May represent an automated misconfigured service account with expired credentials or brute force.",
            })
            finding_counter += 1

    # Rule RUL-003: Volume Shadow Invalidation / Anti-Recovery
    vss_events = [
        e for e in events
        if "vssadmin" in e.get("message", "").lower() and "delete" in e.get("message", "").lower()
    ]
    if vss_events:
        findings.append({
            "finding_id": f"FND-{finding_counter:03d}",
            "rule_name": "Volume Shadow Copy Invalidation (T1490)",
            "rule_version": "v1.2.0-deterministic",
            "severity": "CRITICAL",
            "event_ids": [e["event_id"] for e in vss_events],
            "detection_reason": "Execution of vssadmin with delete shadows command line identified in telemetry stream.",
            "supporting_observations": [
                f"Event {e['event_id']} [{e.get('normalized_timestamp') or e.get('original_timestamp')}]: {e.get('message')}"
                for e in vss_events
            ],
            "detection_timestamp": now_utc,
            "known_limitations": (
                "Administrative storage maintenance scripts occasionally resize shadow storage, "
                "but 'delete shadows /all /quiet' strongly correlates with pre-encryption ransomware staging."
            ),
        })
        finding_counter += 1

    # Rule RUL-004: Security Audit Log Cleared (Event 1102 / wevtutil cl)
    clear_events = [
        e for e in events
        if "1102" in e.get("message", "").lower()
        or ("audit log" in e.get("message", "").lower() and "clear" in e.get("message", "").lower())
        or "wevtutil cl" in e.get("message", "").lower()
    ]
    if clear_events:
        findings.append({
            "finding_id": f"FND-{finding_counter:03d}",
            "rule_name": "Security Audit Log Purged (T1070.001)",
            "rule_version": "v1.1.0-deterministic",
            "severity": "CRITICAL",
            "event_ids": [e["event_id"] for e in clear_events],
            "detection_reason": "Security Event Log was purposefully cleared (Event ID 1102 or wevtutil cl).",
            "supporting_observations": [
                f"Event {e['event_id']} by '{e.get('account_id', 'Unknown')}': {e.get('message')}"
                for e in clear_events
            ],
            "detection_timestamp": now_utc,
            "known_limitations": "Requires corroboration with active logon session tokens to determine whether credentials belonged to compromised user vs IT administrator.",
        })
        finding_counter += 1

    # Rule RUL-005: Unbacked RWX Memory Allocation (T1055)
    rwx_events = [
        e for e in events
        if "page_execute_readwrite" in e.get("message", "").lower() or "malfind" in e.get("message", "").lower()
    ]
    if rwx_events:
        findings.append({
            "finding_id": f"FND-{finding_counter:03d}",
            "rule_name": "Unbacked Memory RWX Allocation (T1055)",
            "rule_version": "v1.0.0-deterministic",
            "severity": "CRITICAL",
            "event_ids": [e["event_id"] for e in rwx_events],
            "detection_reason": "Virtual Address Descriptor allocated with PAGE_EXECUTE_READWRITE permissions without a backing executable file on disk.",
            "supporting_observations": [
                f"Event {e['event_id']}: Volatility malfind reported RWX page in process: {e.get('message')}"
                for e in rwx_events
            ],
            "detection_timestamp": now_utc,
            "known_limitations": "JIT compilers (Node.js, .NET CLR) allocate RWX memory; manual MZ header analysis is recommended to verify shellcode.",
        })
        finding_counter += 1

    # Rule RUL-006: Obfuscated PowerShell Command
    ps_events = [
        e for e in events
        if "powershell" in e.get("message", "").lower()
        and ("-enc" in e.get("message", "").lower() or "downloadstring" in e.get("message", "").lower())
    ]
    if ps_events:
        findings.append({
            "finding_id": f"FND-{finding_counter:03d}",
            "rule_name": "Encoded PowerShell Command Execution (T1059.001)",
            "rule_version": "v1.3.0-deterministic",
            "severity": "HIGH",
            "event_ids": [e["event_id"] for e in ps_events],
            "detection_reason": "Base64 encoded payload passed to powershell.exe interpreter.",
            "supporting_observations": [
                f"Event {e['event_id']}: {e.get('message')}"
                for e in ps_events
            ],
            "detection_timestamp": now_utc,
            "known_limitations": "Enterprise deployment software occasionally encodes deployment commands; payload base64 decoding is required to evaluate intent.",
        })
        finding_counter += 1

    return findings
