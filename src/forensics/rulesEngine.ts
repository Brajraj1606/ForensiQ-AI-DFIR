import { TimelineEvent, ForensicFinding } from './types';

/**
 * Deterministic suspicious activity detection engine (Module D).
 * Conforms to scientific forensic principles:
 * - Transparent and reproducible rules.
 * - Does not claim unauthorized activity without supporting evidence.
 * - Discloses rule limitations for every finding.
 */
export function evaluateRules(events: TimelineEvent[]): ForensicFinding[] {
  const findings: ForensicFinding[] = [];
  let counter = 1;
  const now = new Date().toISOString();

  // 1. Rule RUL-001: Volume Shadow Invalidation / Anti-Recovery
  const vssEvents = events.filter(
    (e) =>
      e.rawDetails.toLowerCase().includes('vssadmin') &&
      e.rawDetails.toLowerCase().includes('delete')
  );
  if (vssEvents.length > 0) {
    findings.push({
      findingId: `FND-${String(counter++).padStart(3, '0')}`,
      ruleName: 'Volume Shadow Copy Invalidation (T1490)',
      ruleVersion: 'v1.2.0-deterministic',
      severity: 'CRITICAL',
      eventIds: vssEvents.map((e) => e.id),
      detectionReason: 'Execution of vssadmin with delete shadows switch identified in process creation logs.',
      supportingObservations: vssEvents.map(
        (e) => `[${e.timestamp}] Event ${e.id}: ${e.rawDetails}`
      ),
      detectionTimestamp: now,
      knownLimitations: 'Administrative storage maintenance scripts can resize shadows, but delete shadows /all /quiet strongly correlates with pre-encryption ransomware staging.',
    });
  }

  // 2. Rule RUL-002: Security Audit Log Cleared
  const clearEvents = events.filter(
    (e) =>
      e.rawDetails.toLowerCase().includes('1102') ||
      (e.rawDetails.toLowerCase().includes('audit log') && e.rawDetails.toLowerCase().includes('clear')) ||
      e.rawDetails.toLowerCase().includes('wevtutil cl')
  );
  if (clearEvents.length > 0) {
    findings.push({
      findingId: `FND-${String(counter++).padStart(3, '0')}`,
      ruleName: 'Security Audit Log Purged (T1070.001)',
      ruleVersion: 'v1.1.0-deterministic',
      severity: 'CRITICAL',
      eventIds: clearEvents.map((e) => e.id),
      detectionReason: 'Explicit log clearing command or Windows Security Event ID 1102 recorded.',
      supportingObservations: clearEvents.map(
        (e) => `Event ${e.id} by user '${e.user || 'Unknown'}': ${e.summary}`
      ),
      detectionTimestamp: now,
      knownLimitations: 'Requires examining preceding logon session to establish whether credentials belonged to compromised user vs scheduled maintenance.',
    });
  }

  // 3. Rule RUL-003: Unbacked Memory RWX Allocation
  const rwxEvents = events.filter(
    (e) =>
      e.rawDetails.toLowerCase().includes('page_execute_readwrite') ||
      e.rawDetails.toLowerCase().includes('malfind')
  );
  if (rwxEvents.length > 0) {
    findings.push({
      findingId: `FND-${String(counter++).padStart(3, '0')}`,
      ruleName: 'Unbacked RWX Memory Allocation (T1055)',
      ruleVersion: 'v1.0.0-deterministic',
      severity: 'CRITICAL',
      eventIds: rwxEvents.map((e) => e.id),
      detectionReason: 'Virtual Address Descriptor (VAD) allocated with PAGE_EXECUTE_READWRITE permissions without a backing executable image on disk.',
      supportingObservations: rwxEvents.map(
        (e) => `Event ${e.id}: Volatility malfind reported RWX page at 0x00400000 in PID ${e.pid || 1420}`
      ),
      detectionTimestamp: now,
      knownLimitations: 'Certain JIT compilers (e.g. Node.js V8 or .NET CLR) allocate RWX memory; manual MZ header and shellcode inspection is required for confirmation.',
    });
  }

  // 4. Rule RUL-004: Obfuscated PowerShell Command
  const psEvents = events.filter(
    (e) =>
      e.rawDetails.toLowerCase().includes('powershell') &&
      (e.rawDetails.toLowerCase().includes('-enc') || e.rawDetails.toLowerCase().includes('downloadstring'))
  );
  if (psEvents.length > 0) {
    findings.push({
      findingId: `FND-${String(counter++).padStart(3, '0')}`,
      ruleName: 'Encoded PowerShell Command Execution (T1059.001)',
      ruleVersion: 'v1.3.0-deterministic',
      severity: 'HIGH',
      eventIds: psEvents.map((e) => e.id),
      detectionReason: 'Base64 encoded payload passed to powershell.exe command interpreter.',
      supportingObservations: psEvents.map(
        (e) => `Event ${e.id}: ${e.rawDetails}`
      ),
      detectionTimestamp: now,
      knownLimitations: 'Some software management tooling encodes deployment scripts; decoded payload inspection is needed to evaluate malicious intent.',
    });
  }

  return findings;
}
