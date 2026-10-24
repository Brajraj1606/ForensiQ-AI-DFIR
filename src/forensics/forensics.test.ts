import test from 'node:test';
import assert from 'node:assert/strict';
import {
  computeSha256Simulated,
  computeMd5Simulated,
  verifyEvidenceIntegrity,
  generateCustodySeal,
} from './hasher';
import { extractIOCsFromText } from './iocExtractor';
import { parseRawLogLines } from './timelineParser';
import { mapEventsToMitre } from './mitreMapper';

test('hasher: computes deterministic hashes and verifies integrity correctly', () => {
  const sample1 = 'Forensic Evidence Sample Block A';
  const sample2 = 'Forensic Evidence Sample Block B';

  const hash1 = computeSha256Simulated(sample1);
  const hash2 = computeSha256Simulated(sample2);
  const hash1Repeat = computeSha256Simulated(sample1);

  // Determinism
  assert.equal(hash1, hash1Repeat);
  assert.notEqual(hash1, hash2);
  assert.equal(hash1.length, 64);

  // MD5 length check
  const md5 = computeMd5Simulated(sample1);
  assert.equal(md5.length, 32);

  // Verification
  assert.equal(verifyEvidenceIntegrity(hash1, hash1Repeat), true);
  assert.equal(verifyEvidenceIntegrity(hash1, hash2), false);
  assert.equal(verifyEvidenceIntegrity(hash1.toUpperCase(), hash1.toLowerCase()), true);
});

test('hasher: generates valid chain of custody seal', () => {
  const hashes = ['a1b2c3d4', 'e5f6g7h8'];
  const seal = generateCustodySeal('CAS-2026-0891', hashes, '2026-10-24T00:00:00Z');
  assert.match(seal, /^SEAL-[0-9A-F]{32}$/);
});

test('iocExtractor: extracts IPs, CVEs, hashes, and LOLBins from log strings', () => {
  const text = `
    Connection from 185.220.101.4 to 192.168.1.105 on port 443.
    Payload hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    Adversary exploited CVE-2023-34362 using certutil.exe and vssadmin delete shadows.
    Downloaded from http://malicious-c2-beacon.top/payload
  `;

  const iocs = extractIOCsFromText(text);

  const ipValues = iocs.filter((i) => i.type === 'ipv4').map((i) => i.value);
  assert.ok(ipValues.includes('185.220.101.4'));
  assert.ok(ipValues.includes('192.168.1.105'));

  const cveValues = iocs.filter((i) => i.type === 'cve').map((i) => i.value);
  assert.ok(cveValues.includes('CVE-2023-34362'));

  const lolbinValues = iocs.filter((i) => i.type === 'lolbin').map((i) => i.value);
  assert.ok(lolbinValues.includes('certutil.exe'));
  assert.ok(lolbinValues.some((v) => v.includes('vssadmin')));

  const cmdIocs = iocs.filter((i) => i.type === 'powershell_cmd').map((i) => i.value);
  assert.ok(cmdIocs.some((c) => c.includes('vssadmin delete shadows')));
});

test('timelineParser: accurately scores severity and identifies anti-forensics anomalies', () => {
  const logSnippet = `
    2026-10-24T01:20:45Z [Security-Event-4688] CommandLine: vssadmin delete shadows /all /quiet
    2026-10-24T01:25:30Z [Security-Event-1102] The audit log was cleared. SubjectUserName: Administrator
    2026-10-24T01:14:22Z [Security-Event-4624] An account was successfully logged on.
  `;

  const events = parseRawLogLines(logSnippet, 'Security_DC01.evtx');
  assert.equal(events.length, 3);

  // Verify chronological sorting
  assert.ok(new Date(events[0].timestamp).getTime() <= new Date(events[1].timestamp).getTime());
  assert.ok(new Date(events[1].timestamp).getTime() <= new Date(events[2].timestamp).getTime());

  // Check critical severity detections
  const shadowEvt = events.find((e) => e.eventType === 'Shadow Copy Invalidation');
  assert.ok(shadowEvt);
  assert.equal(shadowEvt?.severity, 'CRITICAL');
  assert.equal(shadowEvt?.mitreId, 'T1490');
  assert.equal(shadowEvt?.isAnomaly, true);

  const clearEvt = events.find((e) => e.eventType === 'Forensic Log Cleared');
  assert.ok(clearEvt);
  assert.equal(clearEvt?.severity, 'CRITICAL');
  assert.equal(clearEvt?.mitreId, 'T1070.001');
});

test('mitreMapper: aggregates events by tactic and assigns correct technique counts', () => {
  const logSnippet = `
    2026-10-24T01:20:45Z [Security-Event-4688] CommandLine: vssadmin delete shadows /all /quiet
    2026-10-24T01:25:30Z [Security-Event-1102] The audit log was cleared.
  `;
  const events = parseRawLogLines(logSnippet, 'Security_DC01.evtx');
  const tactics = mapEventsToMitre(events);

  assert.ok(tactics.length > 0);

  const impactTactic = tactics.find((t) => t.id === 'TA0040');
  assert.ok(impactTactic);
  const vssTech = impactTactic?.techniques.find((t) => t.id === 'T1490');
  assert.ok(vssTech);
  assert.equal(vssTech?.name, 'Inhibit System Recovery');

  const evasionTactic = tactics.find((t) => t.id === 'TA0005');
  assert.ok(evasionTactic);
  const clearTech = evasionTactic?.techniques.find((t) => t.id === 'T1070.001');
  assert.ok(clearTech);
  assert.equal(clearTech?.name, 'Indicator Removal: Clear Event Logs');
});
