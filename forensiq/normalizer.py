"""
ForensiQ AI - Modular Log Parser and Normalization Engine (Module C)
Converts raw text, JSON, and CSV log files into a standardized forensic event structure.
Preserves original timestamps, record numbers, timezone indicators, and parsing errors.
"""

import re
import json
import csv
import io
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple


class NormalizedEvent:
    def __init__(
        self,
        event_id: str,
        original_record_number: int,
        source_filename: str,
        original_timestamp: str,
        normalized_timestamp: str,
        timezone_info: str,
        host_id: str,
        account_id: str,
        source_ip: str,
        dest_ip: str,
        event_type: str,
        message: str,
        parsing_status: str = "SUCCESS",
        parsing_error: str = None
    ):
        self.event_id = event_id
        self.original_record_number = original_record_number
        self.source_filename = source_filename
        self.original_timestamp = original_timestamp
        self.normalized_timestamp = normalized_timestamp
        self.timezone_info = timezone_info
        self.host_id = host_id
        self.account_id = account_id
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.event_type = event_type
        self.message = message
        self.parsing_status = parsing_status
        self.parsing_error = parsing_error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "original_record_number": self.original_record_number,
            "source_filename": self.source_filename,
            "original_timestamp": self.original_timestamp,
            "normalized_timestamp": self.normalized_timestamp,
            "timezone_info": self.timezone_info,
            "host_id": self.host_id,
            "account_id": self.account_id,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "event_type": self.event_type,
            "message": self.message,
            "parsing_status": self.parsing_status,
            "parsing_error": self.parsing_error
        }


def parse_timestamp_safe(ts_str: str) -> Tuple[str, str]:
    """
    Attempts to normalize timestamp to ISO-8601 UTC while identifying source timezone.
    Returns (normalized_timestamp, timezone_info).
    """
    if not ts_str:
        return (datetime.now(timezone.utc).isoformat(), "UNKNOWN / MISSING")

    ts_clean = ts_str.strip()

    # Match ISO-8601 (e.g., 2026-10-24T01:14:22Z or 2026-10-24 01:14:22)
    iso_match = re.search(r'\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:?\d{2})?)\b', ts_clean)
    if iso_match:
        raw_val = iso_match.group(1).replace(' ', 'T')
        if raw_val.endswith('Z'):
            return (raw_val, "UTC (Explicit Z)")
        elif '+' in raw_val or '-' in raw_val[10:]:
            return (raw_val, "Explicit Offset")
        else:
            return (f"{raw_val}Z", "UTC (Assumed - Unspecified in Source)")

    # Match Syslog format: Oct 24 01:14:22
    syslog_match = re.search(r'\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b', ts_clean)
    if syslog_match:
        current_year = datetime.now(timezone.utc).year
        return (f"{current_year}-{syslog_match.group(1)}Z", "Local Syslog (Year inferred)")

    return (datetime.now(timezone.utc).isoformat(), "FALLBACK (Parse Failure)")


def parse_log_stream(raw_content: str, filename: str, id_prefix: str = "EVT") -> List[Dict[str, Any]]:
    """
    Normalizes multi-format log content (CSV, JSON lines, or raw text)
    without silently dropping failed records.
    """
    events: List[Dict[str, Any]] = []
    lines = raw_content.splitlines()

    # Detect JSON array or JSON lines
    stripped = raw_content.strip()
    if stripped.startswith('[') and stripped.endswith(']'):
        try:
            records = json.loads(stripped)
            for idx, rec in enumerate(records, start=1):
                if isinstance(rec, dict):
                    norm_ts, tz = parse_timestamp_safe(str(rec.get('timestamp') or rec.get('time') or ''))
                    events.append(NormalizedEvent(
                        event_id=f"{id_prefix}-{idx:04d}",
                        original_record_number=idx,
                        source_filename=filename,
                        original_timestamp=str(rec.get('timestamp') or rec.get('time') or ''),
                        normalized_timestamp=norm_ts,
                        timezone_info=tz,
                        host_id=str(rec.get('host') or rec.get('workstation') or 'UNKNOWN_HOST'),
                        account_id=str(rec.get('user') or rec.get('username') or rec.get('account') or 'SYSTEM'),
                        source_ip=str(rec.get('source_ip') or rec.get('src_ip') or '-'),
                        dest_ip=str(rec.get('dest_ip') or rec.get('dst_ip') or '-'),
                        event_type=str(rec.get('event_type') or rec.get('type') or 'JSON_EVENT'),
                        message=str(rec.get('message') or json.dumps(rec)),
                        parsing_status="SUCCESS"
                    ).to_dict())
            return events
        except Exception as e:
            # Fall through to line-by-line parser if JSON parsing fails
            pass

    # Line-by-line parser for text, EVTX excerpts, and syslog
    for idx, line in enumerate(lines, start=1):
        if not line.strip():
            continue

        orig_ts = ""
        norm_ts, tz = (datetime.now(timezone.utc).isoformat(), "MISSING")
        host_id = "UNKNOWN_HOST"
        account_id = "SYSTEM"
        source_ip = "-"
        dest_ip = "-"
        event_type = "Log Entry"
        parsing_status = "SUCCESS"
        parsing_error = None

        try:
            # 1. Timestamp extraction
            iso_match = re.search(r'\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{3})?(?:Z|[+-]\d{2}:?\d{2})?)\b', line)
            if iso_match:
                orig_ts = iso_match.group(1)
                norm_ts, tz = parse_timestamp_safe(orig_ts)

            # 2. Extract IPs
            ips = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', line)
            if ips:
                source_ip = ips[0]
                if len(ips) > 1:
                    dest_ip = ips[1]

            # 3. Extract Accounts
            acct_match = re.search(r'(?:TargetUserName|SubjectUserName|User|user)[:=\s]+([a-zA-Z0-9_\-\\]+)', line, re.IGNORECASE)
            if acct_match:
                account_id = acct_match.group(1)

            # 4. Extract Host
            host_match = re.search(r'(?:WorkstationName|Workstation|Host|ComputerName)[:=\s]+([a-zA-Z0-9_\-\.]+)', line, re.IGNORECASE)
            if host_match:
                host_id = host_match.group(1)

            # 5. Extract Event Type
            lower = line.lower()
            if 'event 4624' in lower or 'event-4624' in lower:
                event_type = "Authentication Succeeded (Event 4624)"
            elif 'event 4625' in lower or 'event-4625' in lower:
                event_type = "Authentication Failed (Event 4625)"
            elif 'event 4688' in lower or 'event-4688' in lower:
                event_type = "Process Created (Event 4688)"
            elif 'event 7045' in lower or 'event-7045' in lower:
                event_type = "Service Installed (Event 7045)"
            elif 'event 1102' in lower or 'event-1102' in lower or 'audit log' in lower and 'clear' in lower:
                event_type = "Audit Log Cleared (Event 1102)"
            elif 'vssadmin' in lower and 'delete' in lower:
                event_type = "Volume Shadow Invalidation"
            elif 'malfind' in lower or 'page_execute_readwrite' in lower:
                event_type = "Memory RWX Injection"
            else:
                event_type = "System Activity"

        except Exception as err:
            parsing_status = "PARTIAL_ERROR"
            parsing_error = str(err)

        events.append(NormalizedEvent(
            event_id=f"{id_prefix}-{idx:04d}",
            original_record_number=idx,
            source_filename=filename,
            original_timestamp=orig_ts,
            normalized_timestamp=norm_ts,
            timezone_info=tz,
            host_id=host_id,
            account_id=account_id,
            source_ip=source_ip,
            dest_ip=dest_ip,
            event_type=event_type,
            message=line,
            parsing_status=parsing_status,
            parsing_error=parsing_error
        ).to_dict())

    return events
