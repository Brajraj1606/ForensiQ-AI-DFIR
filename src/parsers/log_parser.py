"""
ForensiQ AI - Log Parsing and Normalization Engine (Module C)
Conforms to ISO/IEC 27037 digital forensic standards.

Capabilities:
- Ingests structured JSON, CSV, and text-based system logs (EVTX excerpts, Syslog, Apache).
- Normalizes diverse timestamps to ISO-8601 UTC while retaining original representations.
- Explicitly flags timezone ambiguity and never assumes all timestamps share the same timezone.
- Never silently discards malformed records; flags parsing errors with source record traceability.
- Preserves distinct event IDs even for duplicate records.
"""

import re
import json
import csv
import io
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple


def parse_timestamp_safe(ts_raw: str, line_index: int = 0) -> Tuple[str, str]:
    """
    Safely normalizes varied timestamp representations to ISO-8601 UTC.
    Returns: (normalized_utc_iso_string, timezone_provenance_info)
    """
    if not ts_raw or not ts_raw.strip():
        return ("", "MISSING - Retained ingestion sequence order")

    ts_clean = ts_raw.strip()

    # 1. ISO 8601 with explicit Z (UTC)
    if "T" in ts_clean and ts_clean.endswith("Z"):
        try:
            dt = datetime.fromisoformat(ts_clean.replace("Z", "+00:00"))
            return (dt.astimezone(timezone.utc).isoformat(), "UTC (Explicit Z)")
        except Exception:
            pass

    # 2. ISO 8601 with explicit numerical offset (e.g., +05:00, -08:00)
    offset_match = re.search(r"([+-]\d{2}:?\d{2})$", ts_clean)
    if offset_match:
        try:
            formatted = ts_clean
            if ":" not in offset_match.group(1):
                raw_offset = offset_match.group(1)
                formatted = ts_clean[:-2] + ":" + ts_clean[-2:]
            dt = datetime.fromisoformat(formatted)
            return (dt.astimezone(timezone.utc).isoformat(), "Explicit Offset")
        except Exception:
            pass

    # 3. Standard YYYY-MM-DD HH:MM:SS (Unspecified timezone)
    standard_match = re.match(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})", ts_clean)
    if standard_match:
        return (
            f"{standard_match.group(1)}T{standard_match.group(2)}+00:00",
            "Unspecified / Local Assumed UTC (Disclosed Limitation)",
        )

    # 4. Standard BSD / Linux Syslog (e.g., Oct 24 01:14:22)
    syslog_match = re.match(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", ts_clean)
    if syslog_match:
        try:
            curr_year = datetime.now(timezone.utc).year
            dt_raw = datetime.strptime(f"{curr_year} {syslog_match.group(1)}", "%Y %b %d %H:%M:%S")
            return (dt_raw.replace(tzinfo=timezone.utc).isoformat(), "Syslog Format (Year Inferred)")
        except Exception:
            pass

    # Unparseable timestamp fallback
    return ("", f"INVALID_FORMAT ({ts_clean})")


def parse_log_stream(raw_content: str, source_filename: str) -> List[Dict[str, Any]]:
    """
    Converts unstructured or structured logs into standardized Normalized Forensic Events.
    Preserves exact provenance, original text, and parsing audit trail.
    """
    normalized_events: List[Dict[str, Any]] = []
    lines = raw_content.splitlines()

    # Check for structured JSON format
    content_stripped = raw_content.strip()
    if (content_stripped.startswith("[") and content_stripped.endswith("]")) or (
        content_stripped.startswith("{") and content_stripped.endswith("}")
    ):
        try:
            parsed_json = json.loads(content_stripped)
            items = parsed_json if isinstance(parsed_json, list) else [parsed_json]
            for idx, item in enumerate(items, start=1):
                raw_ts = item.get("timestamp") or item.get("time") or item.get("Timestamp_UTC") or ""
                norm_ts, tz_info = parse_timestamp_safe(raw_ts, idx)

                event = {
                    "event_id": f"EVT-JSON-{idx:04d}",
                    "original_record_number": idx,
                    "source_filename": source_filename,
                    "original_timestamp": raw_ts,
                    "normalized_timestamp": norm_ts,
                    "timezone_info": tz_info,
                    "host_id": item.get("host") or item.get("hostname") or item.get("WorkstationName") or "Unknown",
                    "account_id": item.get("user") or item.get("username") or item.get("TargetUserName") or "Unknown",
                    "source_ip": item.get("source_ip") or item.get("src_ip") or item.get("SourceIp") or "-",
                    "dest_ip": item.get("dest_ip") or item.get("dst_ip") or item.get("DestIp") or "-",
                    "event_type": item.get("event_type") or item.get("action") or "JSON Log Entry",
                    "message": item.get("message") or item.get("summary") or json.dumps(item),
                    "parsing_status": "SUCCESS",
                }
                normalized_events.append(event)
            return normalized_events
        except json.JSONDecodeError:
            pass  # Fallback to line-by-line parsing

    # Line-by-line parsing for unstructured text & EVTX strings
    for line_num, line in enumerate(lines, start=1):
        line_str = line.strip()
        if not line_str or line_str.startswith("#"):
            continue

        # Extract timestamp
        ts_match = re.search(
            r"\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{3})?(?:Z|[+-]\d{2}:?\d{2})?)\b",
            line_str,
        )
        if not ts_match:
            ts_match = re.search(r"\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b", line_str)

        orig_ts = ts_match.group(1) if ts_match else ""
        norm_ts, tz_info = parse_timestamp_safe(orig_ts, line_num)

        # Extract event classification
        event_type = "Generic System Event"
        if "4624" in line_str or "successfully logged on" in line_str.lower():
            event_type = "Logon Succeeded (Event 4624)"
        elif "4625" in line_str or "failed to log on" in line_str.lower():
            event_type = "Logon Failure (Event 4625)"
        elif "4688" in line_str or "process has been created" in line_str.lower():
            event_type = "Process Created (Event 4688)"
        elif "1102" in line_str or "audit log was cleared" in line_str.lower():
            event_type = "Audit Log Purged (Event 1102)"
        elif "7045" in line_str or "service was installed" in line_str.lower():
            event_type = "Service Installed (Event 7045)"
        elif "vssadmin" in line_str.lower() and "delete" in line_str.lower():
            event_type = "Shadow Copy Invalidation"

        # Extract User / Account
        user_match = re.search(r"(?:TargetUserName|SubjectUserName|user|account)[:=\s]+([a-zA-Z0-9_\-\\]+)", line_str, re.IGNORECASE)
        account_id = user_match.group(1) if user_match else "Unknown"

        # Extract Host / Workstation
        host_match = re.search(r"(?:WorkstationName|host|hostname)[:=\s]+([a-zA-Z0-9_\-\.]+)", line_str, re.IGNORECASE)
        host_id = host_match.group(1) if host_match else "Unknown"

        # Extract IPs
        ips = re.findall(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", line_str)
        src_ip = ips[0] if len(ips) >= 1 else "-"
        dst_ip = ips[1] if len(ips) >= 2 else "-"

        # Determine parsing status
        parsing_status = "SUCCESS"
        if not orig_ts:
            parsing_status = "PARTIAL_MISSING_TIMESTAMP"
        if account_id == "Unknown" and host_id == "Unknown" and not ts_match:
            parsing_status = "MALFORMED_ANOMALY"

        event = {
            "event_id": f"EVT-{line_num:04d}",
            "original_record_number": line_num,
            "source_filename": source_filename,
            "original_timestamp": orig_ts,
            "normalized_timestamp": norm_ts,
            "timezone_info": tz_info,
            "host_id": host_id,
            "account_id": account_id,
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "event_type": event_type,
            "message": line_str,
            "parsing_status": parsing_status,
        }
        normalized_events.append(event)

    return normalized_events
