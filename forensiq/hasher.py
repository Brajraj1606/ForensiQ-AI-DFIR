"""
ForensiQ AI - Cryptographic Hashing & Chain of Custody Verification
Compliant with ISO/IEC 27037 and Federal Rules of Evidence Rule 901.
"""

import hashlib
from typing import List


def compute_sha256(data: str | bytes) -> str:
    """Computes bitstream SHA-256 hexadecimal hash."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def compute_md5(data: str | bytes) -> str:
    """Computes legacy MD5 hexadecimal hash."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.md5(data).hexdigest()


def verify_integrity(expected_hash: str, current_hash: str) -> bool:
    """
    Validates whether two cryptographic signatures match bit-for-bit.
    In forensic science, even a 1-bit difference indicates evidence tampering.
    """
    if not expected_hash or not current_hash:
        return False
    return expected_hash.strip().lower() == current_hash.strip().lower()


def generate_custody_seal(case_id: str, evidence_hashes: List[str], timestamp: str) -> str:
    """
    Computes an immutable custody seal representing the combined state of evidence items.
    """
    combined = f"{case_id}|{'|'.join(sorted(evidence_hashes))}|{timestamp}"
    seal_hash = hashlib.sha256(combined.encode('utf-8')).hexdigest()[:32].upper()
    return f"SEAL-{seal_hash}"
