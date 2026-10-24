import { ExtractedIOC } from './types';

// Known LOLBins frequently abused in attacks
const LOLBINS = [
  'powershell.exe',
  'powershell',
  'cmd.exe',
  'certutil.exe',
  'certutil',
  'bitsadmin.exe',
  'bitsadmin',
  'mshta.exe',
  'mshta',
  'vssadmin.exe',
  'vssadmin',
  'regsvr32.exe',
  'regsvr32',
  'rundll32.exe',
  'rundll32',
  'wmic.exe',
  'wmic',
  'schtasks.exe',
  'schtasks',
  'whoami.exe',
  'whoami',
  'nltest.exe',
  'nltest',
  'procdump.exe',
  'procdump',
  'net.exe',
  'curl.exe',
  'wget',
  'bash',
  'sh',
  'mimikatz.exe',
  'mimikatz',
  'cobaltstrike',
];

export function extractIOCsFromText(text: string, timestamp?: string): ExtractedIOC[] {
  const iocs: Map<string, ExtractedIOC> = new Map();
  const seenTime = timestamp || new Date().toISOString();

  // 1. IPv4 Regex (strict octets)
  const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  let match: RegExpExecArray | null;

  while ((match = ipRegex.exec(text)) !== null) {
    const ip = match[0];
    // Ignore common loopback and zero nets unless relevant
    if (ip === '127.0.0.1' || ip === '0.0.0.0') continue;

    // Check if private RFC 1918 or public
    const isPrivate =
      ip.startsWith('10.') ||
      ip.startsWith('192.168.') ||
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip);

    const key = `ip:${ip}`;
    if (!iocs.has(key)) {
      iocs.set(key, {
        type: 'ipv4',
        value: ip,
        count: 1,
        firstSeen: seenTime,
        context: isPrivate ? 'Internal Network (RFC 1918)' : 'External / Potential C2 Destination',
        threatLevel: isPrivate ? 'BENIGN' : 'MALICIOUS',
        mitreTacticRef: isPrivate ? 'TA0008 Lateral Movement' : 'TA0011 Command and Control',
      });
    } else {
      iocs.get(key)!.count++;
    }
  }

  // 2. SHA-256 Hashes (64 hex characters)
  const sha256Regex = /\b[A-Fa-f0-9]{64}\b/g;
  while ((match = sha256Regex.exec(text)) !== null) {
    const hash = match[0].toLowerCase();
    const key = `sha256:${hash}`;
    if (!iocs.has(key)) {
      iocs.set(key, {
        type: 'sha256',
        value: hash,
        count: 1,
        firstSeen: seenTime,
        context: 'File / Payload Cryptographic Signature',
        threatLevel: 'SUSPICIOUS',
        mitreTacticRef: 'TA0002 Execution',
      });
    } else {
      iocs.get(key)!.count++;
    }
  }

  // 3. MD5 Hashes (32 hex characters)
  const md5Regex = /\b[A-Fa-f0-9]{32}\b/g;
  while ((match = md5Regex.exec(text)) !== null) {
    const hash = match[0].toLowerCase();
    // Exclude if already part of a sha256 or simple numbers
    const key = `md5:${hash}`;
    if (!iocs.has(key)) {
      iocs.set(key, {
        type: 'md5',
        value: hash,
        count: 1,
        firstSeen: seenTime,
        context: 'Legacy Hash Indicator',
        threatLevel: 'SUSPICIOUS',
        mitreTacticRef: 'TA0002 Execution',
      });
    } else {
      iocs.get(key)!.count++;
    }
  }

  // 4. Domains & FQDNs
  const domainRegex = /\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|xyz|top|cc|onion|biz|info)\b/gi;
  while ((match = domainRegex.exec(text)) !== null) {
    const domain = match[0].toLowerCase();
    if (domain === 'microsoft.com' || domain === 'google.com' || domain === 'github.com') continue;

    const key = `domain:${domain}`;
    if (!iocs.has(key)) {
      iocs.set(key, {
        type: 'domain',
        value: domain,
        count: 1,
        firstSeen: seenTime,
        context: 'External Domain / C2 Infrastructure',
        threatLevel: 'SUSPICIOUS',
        mitreTacticRef: 'TA0011 Command and Control',
      });
    } else {
      iocs.get(key)!.count++;
    }
  }

  // 5. CVE Identifiers
  const cveRegex = /\bCVE-\d{4}-\d{4,7}\b/gi;
  while ((match = cveRegex.exec(text)) !== null) {
    const cve = match[0].toUpperCase();
    const key = `cve:${cve}`;
    if (!iocs.has(key)) {
      iocs.set(key, {
        type: 'cve',
        value: cve,
        count: 1,
        firstSeen: seenTime,
        context: 'Exploited Vulnerability Identifier',
        threatLevel: 'MALICIOUS',
        mitreTacticRef: 'TA0001 Initial Access',
      });
    } else {
      iocs.get(key)!.count++;
    }
  }

  // 6. LOLBins & Suspicious Binary Executions
  const lowerText = text.toLowerCase();
  for (const bin of LOLBINS) {
    if (lowerText.includes(bin)) {
      const key = `lolbin:${bin}`;
      if (!iocs.has(key)) {
        iocs.set(key, {
          type: 'lolbin',
          value: bin,
          count: 1,
          firstSeen: seenTime,
          context: 'Living-Off-The-Land Binary Invocation',
          threatLevel: bin.includes('mimikatz') || bin.includes('cobalt') ? 'MALICIOUS' : 'SUSPICIOUS',
          mitreTacticRef: 'TA0005 Defense Evasion',
        });
      } else {
        iocs.get(key)!.count++;
      }
    }
  }

  // 7. Suspicious Commands & Anti-Forensics Indicators
  const patterns: { regex: RegExp; name: string; tactic: string }[] = [
    { regex: /vssadmin\s+(?:delete\s+shadows|resize\s+shadowstorage)/i, name: 'vssadmin delete shadows (Ransomware Inhibitor)', tactic: 'TA0040 Impact' },
    { regex: /powershell(?:.exe)?\s+-(?:enc|encodedcommand)\s+[a-zA-Z0-9+/=]+/i, name: 'Encoded PowerShell Command Payload', tactic: 'TA0002 Execution' },
    { regex: /wevtutil\s+cl\s+/i, name: 'wevtutil clear log (Anti-Forensics Event Purge)', tactic: 'TA0005 Defense Evasion' },
    { regex: /comsvcs\.dll[,\s]+#24|minidump/i, name: 'LSASS Memory Dumping via comsvcs.dll', tactic: 'TA0006 Credential Access' },
    { regex: /certutil(?:\.exe)?\s+-urlcache\s+-split\s+-f/i, name: 'certutil Ingress Tool Transfer', tactic: 'TA0011 Command and Control' },
    { regex: /bcdedit\s+\/set\s+\{[^}]+\}\s+recoveryenabled\s+no/i, name: 'bcdedit Disable Windows Recovery', tactic: 'TA0040 Impact' },
    { regex: /PAGE_EXECUTE_READWRITE/i, name: 'RWX Memory Protection (Code Injection / Malfind)', tactic: 'TA0004 Privilege Escalation' },
  ];

  for (const p of patterns) {
    if (p.regex.test(text)) {
      const key = `cmd:${p.name}`;
      if (!iocs.has(key)) {
        iocs.set(key, {
          type: 'powershell_cmd',
          value: p.name,
          count: 1,
          firstSeen: seenTime,
          context: 'High-Risk Threat Activity Pattern',
          threatLevel: 'MALICIOUS',
          mitreTacticRef: p.tactic,
        });
      }
    }
  }

  return Array.from(iocs.values());
}
