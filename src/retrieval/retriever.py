"""
ForensiQ AI - Evidence-Aware Retrieval Engine (Module G)
Lightweight, deterministic, and transparent retrieval over normalized forensic event records.

Requirements:
- Transparent keyword, account, host, and time-range search.
- Preserves stable event identifiers (e.g., EVT-0001).
- Avoids sending the entire dataset to AI models unnecessarily.
- Explicitly indicates when no matching records are found.
- Never fabricates source references.
"""

import re
from typing import List, Dict, Any, Optional


def retrieve_relevant_records(
    events: List[Dict[str, Any]],
    query: str,
    max_records: int = 10,
    filter_account: Optional[str] = None,
    filter_host: Optional[str] = None,
    filter_severity: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Retrieves the most relevant forensic records matching query terms and filters.
    Scores relevance based on exact field hits (event_id, account, host, IP, message keywords).
    """
    if not events:
        return []

    tokens = [t.lower() for t in re.findall(r"\w+", query) if len(t) >= 2]
    matched: List[tuple[int, Dict[str, Any]]] = []

    for event in events:
        # Check filters
        if filter_account and event.get("account_id", "").lower() != filter_account.lower():
            continue
        if filter_host and event.get("host_id", "").lower() != filter_host.lower():
            continue
        if filter_severity and event.get("severity") != filter_severity:
            continue

        score = 0
        searchable_text = " ".join([
            str(event.get("event_id", "")),
            str(event.get("event_type", "")),
            str(event.get("account_id", "")),
            str(event.get("host_id", "")),
            str(event.get("source_ip", "")),
            str(event.get("dest_ip", "")),
            str(event.get("message", "")),
            str(event.get("rawDetails", "")),
            str(event.get("summary", "")),
        ]).lower()

        # Score matching tokens
        for token in tokens:
            if token in str(event.get("event_id", "")).lower():
                score += 10
            elif token in str(event.get("account_id", "")).lower():
                score += 5
            elif token in str(event.get("event_type", "")).lower():
                score += 4
            elif token in searchable_text:
                score += 2

        if score > 0 or not tokens:
            matched.append((score, event))

    # Sort descending by match score
    matched.sort(key=lambda x: x[0], reverse=True)
    return [item[1] for item in matched[:max_records]]


def format_retrieved_evidence_for_display(records: List[Dict[str, Any]]) -> str:
    """Formats retrieved records with stable event identifiers for display alongside explanations."""
    if not records:
        return "*No relevant forensic records found for this query in current evidence manifest.*"

    output = ["| Event ID | Timestamp (UTC) | Account | Host | Event Type | Summary |", "|---|---|---|---|---|---|"]
    for r in records:
        eid = r.get("event_id") or r.get("id") or "EVT-?"
        ts = r.get("normalized_timestamp") or r.get("timestamp") or "N/A"
        acct = r.get("account_id") or r.get("user") or "-"
        host = r.get("host_id") or "-"
        etype = r.get("event_type") or "Event"
        msg = (r.get("message") or r.get("summary") or "")[:60].replace("|", "\\|")
        output.append(f"| `{eid}` | {ts} | `{acct}` | `{host}` | {etype} | {msg} |")

    return "\n".join(output)
