export interface CaseMetadata {
  id: string;
  title: string;
  incidentType: 'Ransomware' | 'Memory Injection' | 'Data Exfiltration' | 'Insider Threat' | 'Web Shell Compromise';
  examinerName: string;
  examinerTitle: string;
  agency: string;
  dateCreated: string;
  status: 'ACTIVE_INVESTIGATION' | 'EVIDENCE_TRIAGED' | 'REPORT_GENERATED' | 'CLOSED';
  classification: 'TLP:AMBER+STRICT' | 'TLP:RED' | 'TLP:GREEN' | 'RESTRICTED EVIDENCE';
  caseSummary: string;
  leadSuspectOrThreatActor?: string;
}

export interface CustodyEntry {
  id: string;
  timestamp: string;
  action: 'ACQUISITION' | 'HASH_VERIFICATION' | 'TRANSFERRED' | 'PARSED' | 'AI_ANALYSIS' | 'SEALED';
  actor: string;
  location: string;
  notes: string;
  hashMatch: boolean;
  algorithm: 'SHA-256' | 'MD5' | 'SHA-1';
  hashValue: string;
}

export interface EvidenceItem {
  id: string;
  name: string;
  filename: string;
  fileType: 'memory_dump' | 'evtx_logs' | 'pcap_network' | 'disk_image' | 'syslog' | 'registry_hive';
  sizeBytes: number;
  md5: string;
  sha1: string;
  sha256: string;
  acquiredAt: string;
  acquiredBy: string;
  writeBlockerModel: string;
  custodyLog: CustodyEntry[];
  rawContent: string;
  parsedArtifactsCount: number;
  integrityVerified: boolean;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  sourceArtifact: string;
  sourceType: string;
  eventType: string;
  summary: string;
  rawDetails: string;
  processName?: string;
  pid?: number;
  user?: string;
  sourceIp?: string;
  destIp?: string;
  mitreTactic?: string;
  mitreTechnique?: string;
  mitreId?: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: number; // 0 - 100
  tags: string[];
  isAnomaly?: boolean;
}

export interface ExtractedIOC {
  type: 'ipv4' | 'domain' | 'sha256' | 'md5' | 'cve' | 'lolbin' | 'powershell_cmd' | 'registry_key';
  value: string;
  count: number;
  firstSeen: string;
  context: string;
  threatLevel: 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS';
  mitreTacticRef?: string;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  tacticId: string;
  description: string;
  detectedEventsCount: number;
  eventIds: string[];
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: number;
}

export interface MitreTacticGroup {
  id: string;
  name: string;
  techniques: MitreTechnique[];
}

export interface ForensicFinding {
  findingId: string;
  ruleName: string;
  ruleVersion: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  eventIds: string[];
  detectionReason: string;
  supportingObservations: string[];
  detectionTimestamp: string;
  knownLimitations: string;
}

export interface ForensicReport {
  caseId: string;
  caseTitle: string;
  examinerName: string;
  agency: string;
  dateGenerated: string;
  executiveSummary: string;
  chainOfCustodySummary: string;
  attackVectorAnalysis: string;
  timelineHighlights: TimelineEvent[];
  identifiedIOCs: ExtractedIOC[];
  mitreMapping: { tactic: string; technique: string; id: string }[];
  conclusions: string[];
  remediationSteps: string[];
  custodySealHash: string;
  findings?: ForensicFinding[];
  humanReviewChecklist?: string[];
  limitationsNotes?: string;
}
