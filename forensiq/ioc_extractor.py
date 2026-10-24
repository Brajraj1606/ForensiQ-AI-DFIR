"""
ForensiQ AI - Automated IOC & Pattern Extraction
Extracts IPv4, Domains, Hashes, LOLBins, CVEs, and Suspicious Shell Commands.
"""

import re
from datetime import datetime
from typing import List, Dict, Any

LOLBINS = [
    'powershell.exe', 'powershell',
    'cmd.exe',
    'certutil.exe', 'certutil',
    'bitsadmin.exe', 'bitsadmin',
    'mshta.exe', 'mshta',
    'vssadmin.exe', 'vssadmin',
    'regsvr32.exe', 'regsvr32',
    'rundll32.exe', 'rundll32',
    'wmic.exe', 'wmic',
    'schtasks.exe', 'schtasks',
    'whoami.exe', 'whoami',
    'nltest.exe', 'nltest',
    'procdump.exe', 'procdump',
    'net.exe',
    'mimikatz.exe', 'mimikatz',
    'cobaltstrike'
]

SUSPICIOUS_PATTERNS = [
    (re.compile(r'vssadmin\s+(?:delete\s+shadows|resize\s+shadowstorage)', re.IGNORECASE),
     'vssadmin delete shadows (Ransomware Inhibitor)', 'TA0040 Impact'),
    (re.compile(r'powershell(?:\.exe)?\s+-(?:enc|encodedcommand)\s+[a-zA-Z0-9+/=]+', re.IGNORECASE),
     'Encoded PowerShell Payload', 'TA0002 Execution'),
    (re.compile(r'wevtutil\s+cl\s+', re.IGNORECASE),
     'wevtutil clear log (Anti-Forensics Event Purge)', 'TA0005 Defense Evasion'),
    (re.compile(r'comsvcs\.dll[,\s]+#24|minidump', re.IGNORECASE),
     'LSASS Memory Dumping via comsvcs.dll', 'TA0006 Credential Access'),
    (re.compile(r'PAGE_EXECUTE_READWRITE', re.IGNORECASE),
     'RWX Memory Protection (Code Injection / Malfind)', 'TA0004 Privilege Escalation'),
]


def extract_iocs(text: str, timestamp: str = None) -> List[Dict[str, Any]]:
    """Extracts forensic observables and threat indicators from text streams."""
    iocs: Dict[str, Dict[str, Any]] = {}
    seen_time = timestamp or datetime.utcnow().isoformat() + "Z"

    # 1. IPv4 Regex
    ip_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
    for match in ip_pattern.finditer(text):
        ip = match.group(0)
        if ip in ('127.0.0.1', '0.0.0.0'):
            continue
        is_private = (
            ip.startswith('10.') or
            ip.startswith('192.168.') or
            bool(re.match(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', ip))
        )
        key = f"ip:{ip}"
        if key not in iocs:
            iocs[key] = {
                'type': 'ipv4',
                'value': ip,
                'count': 1,
                'first_seen': seen_time,
                'context': 'Internal Network (RFC 1918)' if is_private else 'External / Potential C2 Destination',
                'threat_level': 'BENIGN' if is_private else 'MALICIOUS',
                'mitre_tactic': 'TA0008 Lateral Movement' if is_private else 'TA0011 Command and Control'
            }
        else:
            iocs[key]['count'] += 1

    # 2. SHA-256 Hashes
    sha256_pattern = re.compile(r'\b[A-Fa-f0-9]{64}\b')
    for match in sha256_pattern.finditer(text):
        h = match.group(0).lower()
        key = f"sha256:{h}"
        if key not in iocs:
            iocs[key] = {
                'type': 'sha256',
                'value': h,
                'count': 1,
                'first_seen': seen_time,
                'context': 'Cryptographic Payload Hash',
                'threat_level': 'SUSPICIOUS',
                'mitre_tactic': 'TA0002 Execution'
            }
        else:
            iocs[key]['count'] += 1

    # 3. CVEs
    cve_pattern = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
    for match in cve_pattern.finditer(text):
        cve = match.group(0).upper()
        key = f"cve:{cve}"
        if key not in iocs:
            iocs[key] = {
                'type': 'cve',
                'value': cve,
                'count': 1,
                'first_seen': seen_time,
                'context': 'Exploited Vulnerability Identifier',
                'threat_level': 'MALICIOUS',
                'mitre_tactic': 'TA0001 Initial Access'
            }
        else:
            iocs[key]['count'] += 1

    # 4. LOLBins
    lower_text = text.lower()
    for bin_name in LOLBINS:
        if bin_name in lower_text:
            key = f"lolbin:{bin_name}"
            if key not in iocs:
                is_mal = 'mimikatz' in bin_name or 'cobalt' in bin_name
                iocs[key] = {
                    'type': 'lolbin',
                    'value': bin_name,
                    'count': 1,
                    'first_seen': seen_time,
                    'context': 'Living-Off-The-Land Binary Invocation',
                    'threat_level': 'MALICIOUS' if is_mal else 'SUSPICIOUS',
                    'mitre_tactic': 'TA0005 Defense Evasion'
                }
            else:
                iocs[key]['count'] += 1

    # 5. Suspicious Command Patterns
    for regex, name, tactic in SUSPICIOUS_PATTERNS:
        if regex.search(text):
            key = f"cmd:{name}"
            if key not in iocs:
                iocs[key] = {
                    'type': 'powershell_cmd',
                    'value': name,
                    'count': 1,
                    'first_seen': seen_time,
                    'context': 'High-Risk Adversarial Command Pattern',
                    'threat_level': 'MALICIOUS',
                    'mitre_tactic': tactic
                }

    return list(iocs.values())
