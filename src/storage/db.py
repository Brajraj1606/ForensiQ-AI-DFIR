"""
ForensiQ AI - Database & Evidence Storage (Module B & Security Requirements)
Enforces strictly parameterized queries to eliminate SQL injection vulnerabilities.
Provides audit-compliant persistence for cases, evidence items, custody logs, and normalized events.
"""

import sqlite3
from typing import Dict, Any, List, Optional


def init_db(db_path: str = "forensiq_cases.db") -> sqlite3.Connection:
    """Initializes the forensic case database schema with parameterized constraints."""
    conn = sqlite3.connect(db_path, check_same_thread=False)
    cur = conn.cursor()

    # Cases Table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            incident_type TEXT NOT NULL,
            examiner_name TEXT NOT NULL,
            examiner_title TEXT,
            agency TEXT NOT NULL,
            date_created TEXT NOT NULL,
            status TEXT NOT NULL,
            classification TEXT NOT NULL,
            case_summary TEXT
        )
    """)

    # Evidence Inventory Table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            filename TEXT NOT NULL,
            file_type TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            md5 TEXT NOT NULL,
            acquired_at TEXT NOT NULL,
            acquired_by TEXT NOT NULL,
            write_blocker_model TEXT,
            raw_content TEXT,
            FOREIGN KEY(case_id) REFERENCES cases(case_id)
        )
    """)

    # Chain of Custody Audit Ledger
    cur.execute("""
        CREATE TABLE IF NOT EXISTS custody_ledger (
            id TEXT PRIMARY KEY,
            evidence_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            actor TEXT NOT NULL,
            location TEXT,
            notes TEXT,
            hash_match INTEGER NOT NULL,
            seal_hash TEXT,
            FOREIGN KEY(evidence_id) REFERENCES evidence(id)
        )
    """)

    # Normalized Events Table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS normalized_events (
            event_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            original_record_number INTEGER,
            source_filename TEXT,
            original_timestamp TEXT,
            normalized_timestamp TEXT,
            timezone_info TEXT,
            host_id TEXT,
            account_id TEXT,
            source_ip TEXT,
            dest_ip TEXT,
            event_type TEXT,
            message TEXT,
            parsing_status TEXT,
            FOREIGN KEY(case_id) REFERENCES cases(case_id)
        )
    """)

    conn.commit()
    return conn


def save_case(conn: sqlite3.Connection, case_data: Dict[str, Any]) -> None:
    """Persists case metadata using parameterized SQL queries."""
    cur = conn.cursor()
    cur.execute("""
        INSERT OR REPLACE INTO cases (
            case_id, title, incident_type, examiner_name, examiner_title,
            agency, date_created, status, classification, case_summary
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        case_data.get("case_id"),
        case_data.get("title", "Untitled Investigation"),
        case_data.get("incident_type", "General"),
        case_data.get("examiner_name", "Investigator"),
        case_data.get("examiner_title", "Examiner"),
        case_data.get("agency", "CIRU"),
        case_data.get("date_created", ""),
        case_data.get("status", "ACTIVE_INVESTIGATION"),
        case_data.get("classification", "TLP:AMBER+STRICT"),
        case_data.get("case_summary", "")
    ))
    conn.commit()


def save_evidence(conn: sqlite3.Connection, case_id: str, item: Dict[str, Any]) -> None:
    """Stores evidence item with bitstream hash manifest using parameterized SQL."""
    cur = conn.cursor()
    cur.execute("""
        INSERT OR REPLACE INTO evidence (
            id, case_id, filename, file_type, size_bytes,
            sha256, md5, acquired_at, acquired_by, write_blocker_model, raw_content
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        item.get("id"),
        case_id,
        item.get("filename", "unknown.log"),
        item.get("file_type", "raw_logs"),
        item.get("size_bytes", 0),
        item.get("sha256", ""),
        item.get("md5", ""),
        item.get("acquired_at", ""),
        item.get("acquired_by", ""),
        item.get("write_blocker_model", ""),
        item.get("raw_content", "")
    ))
    conn.commit()


def log_custody_action(conn: sqlite3.Connection, evidence_id: str, entry: Dict[str, Any]) -> None:
    """Appends an immutable custody audit entry with verification match indicator."""
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO custody_ledger (
            id, evidence_id, timestamp, action, actor, location, notes, hash_match, seal_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        entry.get("id"),
        evidence_id,
        entry.get("timestamp"),
        entry.get("action"),
        entry.get("actor"),
        entry.get("location", "Forensic Lab"),
        entry.get("notes", ""),
        1 if entry.get("hash_match") else 0,
        entry.get("seal_hash", "")
    ))
    conn.commit()


def save_normalized_events(conn: sqlite3.Connection, case_id: str, events: List[Dict[str, Any]]) -> None:
    """Batch-inserts normalized events safely."""
    cur = conn.cursor()
    records = [
        (
            e.get("event_id"),
            case_id,
            e.get("original_record_number"),
            e.get("source_filename"),
            e.get("original_timestamp"),
            e.get("normalized_timestamp"),
            e.get("timezone_info"),
            e.get("host_id"),
            e.get("account_id"),
            e.get("source_ip"),
            e.get("dest_ip"),
            e.get("event_type"),
            e.get("message"),
            e.get("parsing_status"),
        )
        for e in events
    ]
    cur.executemany("""
        INSERT OR REPLACE INTO normalized_events (
            event_id, case_id, original_record_number, source_filename,
            original_timestamp, normalized_timestamp, timezone_info,
            host_id, account_id, source_ip, dest_ip, event_type, message, parsing_status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, records)
    conn.commit()


def query_events(conn: sqlite3.Connection, case_id: str, search_keyword: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves events using parameterized filtering."""
    cur = conn.cursor()
    if search_keyword:
        wildcard = f"%{search_keyword}%"
        cur.execute("""
            SELECT event_id, normalized_timestamp, host_id, account_id, event_type, message, severity
            FROM normalized_events
            WHERE case_id = ? AND (message LIKE ? OR account_id LIKE ? OR host_id LIKE ?)
            ORDER BY normalized_timestamp ASC
        """, (case_id, wildcard, wildcard, wildcard))
    else:
        cur.execute("""
            SELECT event_id, normalized_timestamp, host_id, account_id, event_type, message, parsing_status
            FROM normalized_events
            WHERE case_id = ?
            ORDER BY normalized_timestamp ASC
        """, (case_id,))

    rows = cur.fetchall()
    return [
        {
            "event_id": r[0],
            "normalized_timestamp": r[1],
            "host_id": r[2],
            "account_id": r[3],
            "event_type": r[4],
            "message": r[5],
            "parsing_status": r[6],
        }
        for r in rows
    ]
