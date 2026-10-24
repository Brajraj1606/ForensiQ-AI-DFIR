import { TimelineEvent } from './types';

/**
 * Normalizes multi-format forensic log streams into standardized Chronological Events.
 * Supports Windows Event Logs (EVTX translated), Volatility pslist/netscan/malfind,
 * Syslog, Apache access logs, and Suricata/Snort alerts.
 */
export function parseRawLogLines(
  rawText: string,
  artifactName: string,
  idPrefix?: string
): TimelineEvent[] {
  const lines = rawText.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const events: TimelineEvent[] = [];
  const prefix = idPrefix || artifactName.replace(/[^a-zA-Z0-9]/g, '_').slice(0, 10);

  let syntheticIndex = 1;
  const baseTime = new Date('2026-10-24T02:00:00Z').getTime();

  for (const line of lines) {
    if (line.startsWith('#') || line.startsWith('//') || line.length < 5) continue;

    // Check for ISO timestamp (e.g. 2026-10-24T03:14:02Z or 2026-10-24 03:14:02)
    const isoMatch = line.match(/\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{3})?(?:Z|[+-]\d{2}:?\d{2})?)\b/);
    // Check for Syslog timestamp (e.g. Oct 24 03:14:02)
    const syslogMatch = line.match(/\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b/);

    let timestamp: string;
    if (isoMatch) {
      timestamp = isoMatch[1].replace(' ', 'T');
      if (!timestamp.endsWith('Z') && !timestamp.includes('+')) timestamp += 'Z';
    } else if (syslogMatch) {
      timestamp = `2026-${syslogMatch[1]}`;
    } else {
      // Deterministic offset based on line position
      const offsetMs = syntheticIndex * 45000;
      timestamp = new Date(baseTime + offsetMs).toISOString();
    }

    // Heuristics for event classification and MITRE ATT&CK assignment
    let eventType = 'System Event';
    let summary = line.slice(0, 100);
    let severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
    let mitreTactic = 'TA0007 Discovery';
    let mitreTechnique = 'System Information Discovery';
    let mitreId = 'T1082';
    let processName: string | undefined;
    let pid: number | undefined;
    let user: string | undefined;
    let sourceIp: string | undefined;
    let destIp: string | undefined;
    let isAnomaly = false;
    const tags: string[] = [];

    // Extract PID if present
    const pidMatch = line.match(/\bPID[:=\s]+(\d+)\b/i) || line.match(/\[(\d{3,6})\]/);
    if (pidMatch) pid = parseInt(pidMatch[1], 10);

    // Extract IP addresses if present
    const ips = line.match(/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g);
    if (ips && ips.length >= 1) {
      sourceIp = ips[0];
      if (ips.length >= 2) destIp = ips[1];
    }

    // Check high-risk security events
    const lower = line.toLowerCase();

    if (lower.includes('vssadmin') && lower.includes('delete')) {
      eventType = 'Shadow Copy Invalidation';
      summary = 'Adversary executed vssadmin to delete volume shadow copies';
      severity = 'CRITICAL';
      mitreTactic = 'TA0040 Impact';
      mitreTechnique = 'Inhibit System Recovery';
      mitreId = 'T1490';
      isAnomaly = true;
      tags.push('Ransomware Precursor', 'VSS Tampering');
    } else if (
      lower.includes('1102') ||
      lower.includes('wevtutil cl') ||
      (lower.includes('audit log') && lower.includes('clear')) ||
      (lower.includes('event log') && lower.includes('clear'))
    ) {
      eventType = 'Forensic Log Cleared';
      summary = 'Security Event Log was purposefully cleared (Event ID 1102)';
      severity = 'CRITICAL';
      mitreTactic = 'TA0005 Defense Evasion';
      mitreTechnique = 'Indicator Removal: Clear Event Logs';
      mitreId = 'T1070.001';
      isAnomaly = true;
      tags.push('Anti-Forensics', 'Evasion');
    } else if (lower.includes('malfind') || lower.includes('page_execute_readwrite') || lower.includes('vad rwx')) {
      eventType = 'Memory Injection (RWX)';
      summary = 'VAD allocation with PAGE_EXECUTE_READWRITE permissions detected';
      severity = 'CRITICAL';
      mitreTactic = 'TA0004 Privilege Escalation';
      mitreTechnique = 'Process Injection: Dynamic-link Library Injection';
      mitreId = 'T1055.001';
      isAnomaly = true;
      tags.push('Volatility', 'Memory Forensics', 'Shellcode');
    } else if (lower.includes('event 7045') || lower.includes('new service was installed')) {
      eventType = 'Service Installation';
      summary = 'New system service created (Windows Event 7045)';
      severity = 'HIGH';
      mitreTactic = 'TA0003 Persistence';
      mitreTechnique = 'Create or Modify System Process: Windows Service';
      mitreId = 'T1543.003';
      tags.push('Persistence', 'Service Creation');
    } else if (lower.includes('event 4625') || lower.includes('logon failure')) {
      eventType = 'Failed Authentication';
      summary = 'Account logon failure detected (Windows Event 4625)';
      severity = 'MEDIUM';
      mitreTactic = 'TA0006 Credential Access';
      mitreTechnique = 'Brute Force: Password Guessing';
      mitreId = 'T1110.001';
      tags.push('Auth', 'Failed Logon');
    } else if (lower.includes('event 4624') || lower.includes('an account was successfully logged on')) {
      eventType = 'Logon Succeeded';
      summary = 'Successful authentication session established (Event 4624)';
      severity = 'LOW';
      mitreTactic = 'TA0001 Initial Access';
      mitreTechnique = 'Valid Accounts';
      mitreId = 'T1078';
      tags.push('Auth', 'Logon');
    } else if (lower.includes('event 4688') || lower.includes('a new process has been created')) {
      eventType = 'Process Execution';
      summary = 'New process spawned (Windows Event 4688)';
      severity = 'MEDIUM';
      mitreTactic = 'TA0002 Execution';
      mitreTechnique = 'Command and Scripting Interpreter';
      mitreId = 'T1059';
      tags.push('Process', 'Execution');
    } else if (lower.includes('dns') && (lower.includes('tunnel') || lower.includes('.top') || lower.includes('.onion'))) {
      eventType = 'Suspicious DNS Query';
      summary = 'High entropy DNS query indicative of covert data channel';
      severity = 'HIGH';
      mitreTactic = 'TA0011 Command and Control';
      mitreTechnique = 'Protocol Tunneling: DNS';
      mitreId = 'T1572';
      isAnomaly = true;
      tags.push('DNS Exfiltration', 'C2');
    } else if (lower.includes('powershell') && (lower.includes('-enc') || lower.includes('downloadstring'))) {
      eventType = 'Encoded PowerShell Execution';
      summary = 'Obfuscated PowerShell command line executed';
      severity = 'HIGH';
      mitreTactic = 'TA0002 Execution';
      mitreTechnique = 'PowerShell Scripting';
      mitreId = 'T1059.001';
      isAnomaly = true;
      tags.push('PowerShell', 'LOLBin');
    }

    // Extract process name
    const procMatch = line.match(/\b([a-zA-Z0-9_\-\.]+\.(?:exe|dll|sys|sh|py))\b/i);
    if (procMatch) processName = procMatch[1];

    // Extract user if present
    const userMatch = line.match(/(?:User|Account|TargetUserName)[:=\s]+([a-zA-Z0-9_\-\\]+)/i);
    if (userMatch) user = userMatch[1];

    events.push({
      id: `${prefix}-EVT-${String(syntheticIndex).padStart(4, '0')}`,
      timestamp,
      sourceArtifact: artifactName,
      sourceType: artifactName.endsWith('.evtx') ? 'EVTX' : artifactName.endsWith('.raw') ? 'Memory' : 'Log',
      eventType,
      summary,
      rawDetails: line,
      processName,
      pid,
      user,
      sourceIp,
      destIp,
      mitreTactic,
      mitreTechnique,
      mitreId,
      severity,
      confidence: isAnomaly ? 95 : 80,
      tags,
      isAnomaly,
    });

    syntheticIndex++;
  }

  // Sort chronologically ascending
  return events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
}
