"""
ForensiQ AI - SQLite Forensic Case Database Management
Stores investigation metadata, evidence manifests, and chain of custody ledgers.
"""

import sqlite3
import os
from typing import List, Dict, Any, Optional

DEFAULT_DB_PATH = "forensiq_cases.db"


def init_db(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Initializes schema for forensic cases, evidence, custody audit trails, and IOCs."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS cases (
        case_id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        incident_type TEXT NOT NULL,
        examiner_name TEXT NOT NULL,
        examiner_title TEXT NOT NULL,
        agency TEXT NOT NULL,
        date_created TEXT NOT NULL,
        status TEXT NOT NULL,
        classification TEXT NOT NULL,
        case_summary TEXT,
        lead_suspect TEXT
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS evidence_items (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        name TEXT NOT NULL,
        filename TEXT NOT NULL,
        file_type TEXT NOT NULL,
        size_bytes INTEGER NOT NULL,
        sha256 TEXT NOT NULL,
        md5 TEXT NOT NULL,
        acquired_at TEXT NOT NULL,
        acquired_by TEXT NOT NULL,
        write_blocker_model TEXT,
        raw_content TEXT,
        FOREIGN KEY (case_id) REFERENCES cases(case_id)
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS custody_ledger (
        id TEXT PRIMARY KEY,
        evidence_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        action TEXT NOT NULL,
        actor TEXT NOT NULL,
        location TEXT NOT NULL,
        notes TEXT NOT NULL,
        hash_match INTEGER NOT NULL,
        algorithm TEXT NOT NULL,
        hash_value TEXT NOT NULL,
        FOREIGN KEY (evidence_id) REFERENCES evidence_items(id)
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS iocs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT NOT NULL,
        ioc_type TEXT NOT NULL,
        value TEXT NOT NULL,
        threat_level TEXT NOT NULL,
        context TEXT,
        mitre_tactic TEXT,
        first_seen TEXT,
        FOREIGN KEY (case_id) REFERENCES cases(case_id)
    );
    """)

    conn.commit()
    return conn


def save_case(conn: sqlite3.Connection, case_data: Dict[str, Any]):
    cur = conn.cursor()
    cur.execute("""
    INSERT OR REPLACE INTO cases (case_id, title, incident_type, examiner_name, examiner_title, agency, date_created, status, classification, case_summary, lead_suspect)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        case_data['case_id'],
        case_data['title'],
        case_data['incident_type'],
        case_data['examiner_name'],
        case_data['examiner_title'],
        case_data['agency'],
        case_data['date_created'],
        case_data['status'],
        case_data['classification'],
        case_data.get('case_summary', ''),
        case_data.get('lead_suspect', '')
    ))
    conn.commit()


def save_evidence(conn: sqlite3.Connection, evidence: Dict[str, Any]):
    cur = conn.cursor()
    cur.execute("""
    INSERT OR REPLACE INTO evidence_items (id, case_id, name, filename, file_type, size_bytes, sha256, md5, acquired_at, acquired_by, write_blocker_model, raw_content)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        evidence['id'],
        evidence['case_id'],
        evidence['name'],
        evidence['filename'],
        evidence['file_type'],
        evidence['size_bytes'],
        evidence['sha256'],
        evidence['md5'],
        evidence['acquired_at'],
        evidence['acquired_by'],
        evidence['write_blocker_model'],
        evidence.get('raw_content', '')
    ))
    conn.commit()


def log_custody_action(conn: sqlite3.Connection, entry: Dict[str, Any]):
    cur = conn.cursor()
    cur.execute("""
    INSERT OR REPLACE INTO custody_ledger (id, evidence_id, timestamp, action, actor, location, notes, hash_match, algorithm, hash_value)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        entry['id'],
        entry['evidence_id'],
        entry['timestamp'],
        entry['action'],
        entry['actor'],
        entry['location'],
        entry['notes'],
        1 if entry.get('hash_match', True) else 0,
        entry.get('algorithm', 'SHA-256'),
        entry['hash_value']
    ))
    conn.commit()
