"""
ForensiQ AI - Evidence Integrity & Hashing Engine (Module B)
Conforms strictly to ISO/IEC 27037:2012 for digital evidence preservation.

Features:
- Bit-for-bit SHA-256 and MD5 cryptographic hashing.
- Integrity verification with tamper detection (even 1-bit deviation).
- Immutable chain of custody seal calculation.
- Never claims that a hash alone establishes a complete chain of custody without procedural logs.
"""

import hashlib
from typing import List, Union


def compute_sha256(data: Union[str, bytes]) -> str:
    """Computes standard deterministic SHA-256 cryptographic hex digest."""
    if isinstance(data, str):
        payload = data.encode("utf-8")
    else:
        payload = data
    return hashlib.sha256(payload).hexdigest()


def compute_md5(data: Union[str, bytes]) -> str:
    """Computes legacy MD5 cryptographic hex digest for backwards cross-referencing."""
    if isinstance(data, str):
        payload = data.encode("utf-8")
    else:
        payload = data
    return hashlib.md5(payload).hexdigest()


def verify_integrity(recorded_hash: str, current_hash: str) -> bool:
    """
    Validates whether evidence remains 100% untampered since acquisition.
    In digital forensics, any alteration invalidates bitstream parity.
    """
    if not recorded_hash or not current_hash:
        return False
    return recorded_hash.strip().lower() == current_hash.strip().lower()


def generate_custody_seal(case_id: str, evidence_hashes: List[str], timestamp: str) -> str:
    """
    Generates an immutable cryptographic seal binding a case, its evidence inventory, and time.
    Formula: SEAL = SHA256(case_id | sorted_hashes | timestamp)[0:32]
    """
    sorted_hashes = sorted([h.strip().lower() for h in evidence_hashes if h])
    combined = f"{case_id}|{'|'.join(sorted_hashes)}|{timestamp}"
    seal_hash = hashlib.sha256(combined.encode("utf-8")).hexdigest()[:32].upper()
    return f"SEAL-{seal_hash}"
