"""
ForensiQ AI - IOC & Observable Extraction Engine
Detects IPv4, CVE identifiers, cryptographic hashes, LOLBins, and PowerShell commands.
"""

import re
from typing import List, Dict, Any

LOLBIN_LIST = [
    "certutil.exe",
    "vssadmin.exe",
    "vssadmin",
    "bcdedit.exe",
    "bcdedit",
    "bitsadmin.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "mshta.exe",
    "wmic.exe",
    "powershell.exe",
    "cmd.exe",
    "psexec.exe",
    "wevtutil.exe",
    "wevtutil",
]


def extract_iocs(text: str) -> List[Dict[str, Any]]:
    """Extracts forensic observables from unstructured or structured log texts."""
    iocs: List[Dict[str, Any]] = []
    seen: set = set()

    # 1. IPv4 Addresses
    ip_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    for ip in re.findall(ip_pattern, text):
        if ip in ("127.0.0.1", "0.0.0.0", "255.255.255.255"):
            continue
        key = f"ipv4:{ip}"
        if key not in seen:
            seen.add(key)
            is_internal = ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.")
            iocs.append({
                "type": "ipv4",
                "value": ip,
                "threat_level": "SUSPICIOUS" if is_internal else "MALICIOUS",
                "context": "Internal host telemetry" if is_internal else "Remote external communication",
                "mitre_tactic": "TA0011 Command & Control" if not is_internal else "TA0008 Lateral Movement",
                "count": text.count(ip),
            })

    # 2. CVE Identifiers
    cve_pattern = r"\bCVE-\d{4}-\d{4,7}\b"
    for cve in set(re.findall(cve_pattern, text, re.IGNORECASE)):
        iocs.append({
            "type": "cve",
            "value": cve.upper(),
            "threat_level": "MALICIOUS",
            "context": "Exploit identifier cited in evidence",
            "mitre_tactic": "TA0001 Initial Access",
            "count": text.count(cve),
        })

    # 3. Cryptographic Hashes (SHA-256)
    sha256_pattern = r"\b[a-fA-F0-9]{64}\b"
    for sha in set(re.findall(sha256_pattern, text)):
        iocs.append({
            "type": "sha256",
            "value": sha.lower(),
            "threat_level": "SUSPICIOUS",
            "context": "Cryptographic file hash",
            "mitre_tactic": "TA0002 Execution",
            "count": text.count(sha),
        })

    # 4. Living-off-the-Land Binaries (LOLBins)
    lower_text = text.lower()
    for bin_name in LOLBIN_LIST:
        if bin_name in lower_text:
            key = f"lolbin:{bin_name}"
            if key not in seen:
                seen.add(key)
                threat = "MALICIOUS" if bin_name in ("vssadmin", "vssadmin.exe", "wevtutil", "bcdedit") else "SUSPICIOUS"
                iocs.append({
                    "type": "lolbin",
                    "value": bin_name,
                    "threat_level": threat,
                    "context": "Native administrative utility execution",
                    "mitre_tactic": "TA0005 Defense Evasion" if "wevtutil" in bin_name or "vssadmin" in bin_name else "TA0002 Execution",
                    "count": lower_text.count(bin_name),
                })

    return iocs
