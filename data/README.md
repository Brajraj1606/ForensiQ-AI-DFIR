# ForensiQ AI Data Store

This directory stores local SQLite database files, case manifests, and local session caches.

## Privacy & Security Guarantees
- **Zero External Transmission:** All case evidence, event logs, and forensic artifacts remain entirely on the investigator's local workstation.
- **Parameterized SQL:** All database interactions are strictly executed via parameterized queries, preventing SQL injection.
- **Read-Only Preservation:** Ingested evidence bytes are hashed at intake and preserved unmodified. Working representations are decoupled from raw source streams.

## SQLite Database Schema (`forensiq_cases.db`)
- `cases`: Case reference metadata (`case_id`, `title`, `examiner_name`, `agency`, `status`, `classification`).
- `evidence`: Inventory of forensic artifacts (`id`, `case_id`, `filename`, `size_bytes`, `sha256`, `md5`, `write_blocker_model`).
- `custody_ledger`: Immutable audit trail (`id`, `evidence_id`, `timestamp`, `action`, `actor`, `hash_match`, `seal_hash`).
- `normalized_events`: Normalized event stream (`event_id`, `case_id`, `normalized_timestamp`, `host_id`, `account_id`, `event_type`, `message`, `severity`).
