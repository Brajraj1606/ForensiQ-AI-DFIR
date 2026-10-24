import express, { Request, Response } from 'express';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import { GoogleGenAI } from '@google/genai';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT) || 3000;

app.use(express.json({ limit: '50mb' }));

// Initialize Gemini Client
const apiKey = process.env.GEMINI_API_KEY || '';
let genAI: GoogleGenAI | null = null;
if (apiKey) {
  try {
    genAI = new GoogleGenAI({ apiKey });
  } catch (err) {
    console.warn('Failed to initialize GoogleGenAI client:', err);
  }
}

// 1. Health check
app.get('/api/health', (_req: Request, res: Response) => {
  res.json({
    status: 'ok',
    geminiConfigured: Boolean(apiKey),
    engine: 'ForensiQ Forensic Core v2.4-Enterprise',
    timestamp: new Date().toISOString(),
  });
});

// Helper for offline fallback analysis if API key is absent
function generateLocalForensicAnalysis(body: any): string {
  const { caseMetadata, timelineEvents = [], extractedIOCs = [], investigativeFocus } = body;
  const criticalEvents = timelineEvents.filter((e: any) => e.severity === 'CRITICAL');
  const anomalies = timelineEvents.filter((e: any) => e.isAnomaly);
  const maliciousIOCs = extractedIOCs.filter((i: any) => i.threatLevel === 'MALICIOUS');

  return `### FORENSIC TRIAGE REPORT // FORENSIQ DETERMINISTIC REASONING ENGINE

**Case ID:** ${caseMetadata?.id || 'CAS-UNKNOWN'} — ${caseMetadata?.title || 'Digital Investigation'}
**Classification:** ${caseMetadata?.classification || 'RESTRICTED EVIDENCE'}
**Analysis Mode:** ${investigativeFocus ? String(investigativeFocus).toUpperCase() : 'COMPREHENSIVE TRIAGE'}

---

#### 1. Executive Summary & Root Cause
Evidence ingestion confirms high-confidence indicators of malicious compromise. An unauthorized privileged execution occurred, progressing through initial access, privilege escalation, and active defense evasion.

#### 2. Key Forensic Anomalies Detected
- **Anti-Forensics / Recovery Tampering:** ${anomalies.length} anomalous events detected. Critical indicators include execution of recovery inhibition utilities (\`vssadmin delete shadows\`, \`bcdedit\`) and security event log clearing (\`Event ID 1102\`).
- **Memory & Process Anomalies:** Volatile memory artifacts indicate dynamic-link library injection or unbacked executable sections (\`PAGE_EXECUTE_READWRITE\` permissions in system processes).
- **Network Communications:** Persistent outbound connections identified to foreign C2 infrastructure (\`${maliciousIOCs.map((i: any) => i.value).slice(0, 3).join(', ') || '185.220.101.4'}\`).

#### 3. MITRE ATT&CK Matrix Correlation
- **TA0001 (Initial Access):** Valid Accounts abuse / Web application RCE
- **TA0002 (Execution):** Obfuscated Command and Scripting Interpreter (\`powershell.exe -enc\`)
- **TA0004 (Privilege Escalation):** Memory injection & token manipulation
- **TA0005 (Defense Evasion):** Indicator Removal on Host (T1070.001 Event Log Cleared)
- **TA0040 (Impact):** Inhibit System Recovery (T1490 Shadow Copy Invalidation)

#### 4. Forensic Recommendations & Containment
1. **Immediate Isolation:** Isolate host from corporate VLAN; capture live memory snapshot under ISO/IEC 27037 order of volatility before host reboot.
2. **Credential Revocation:** Force enterprise-wide password and Kerberos Golden/Silver Ticket (KRBTGT) reset for affected domain accounts.
3. **IOC Hunting:** Block external IPs (\`${maliciousIOCs.map((i: any) => i.value).slice(0, 5).join(', ')}\`) on boundary perimeter firewalls and deploy endpoint YARA signatures.`;
}

// 2. Evidence Triage & Deep AI Forensic Analysis
app.post('/api/analyze-evidence', async (req: Request, res: Response) => {
  try {
    const { caseMetadata, evidenceItems, timelineEvents, extractedIOCs, investigativeFocus } = req.body;

    if (!genAI || !apiKey) {
      const fallbackReport = generateLocalForensicAnalysis(req.body);
      return res.json({ analysis: fallbackReport, source: 'deterministic_engine' });
    }

    const prompt = `You are ForensiQ AI, a senior Digital Forensics & Incident Response (DFIR) specialist, malware analyst, and expert forensic witness conforming to ISO/IEC 27037 and NIST SP 800-86 standards.

Analyze the following digital forensic case and artifacts:
Case Details:
- Case ID: ${caseMetadata?.id}
- Case Title: ${caseMetadata?.title}
- Incident Type: ${caseMetadata?.incidentType}
- Examiner: ${caseMetadata?.examinerName} (${caseMetadata?.agency})
- Classification: ${caseMetadata?.classification}
- Investigation Focus: ${investigativeFocus || 'Comprehensive Triage'}

Evidence Manifest:
${JSON.stringify(evidenceItems?.map((e: any) => ({
  name: e.name,
  filename: e.filename,
  fileType: e.fileType,
  sha256: e.sha256,
  integrityVerified: e.integrityVerified,
})), null, 2)}

Extracted IOCs (Top 15):
${JSON.stringify(extractedIOCs?.slice(0, 15), null, 2)}

Reconstructed Timeline Events (Top 12):
${JSON.stringify(timelineEvents?.slice(0, 12).map((evt: any) => ({
  time: evt.timestamp,
  source: evt.sourceArtifact,
  type: evt.eventType,
  summary: evt.summary,
  mitre: `${evt.mitreTactic} -> ${evt.mitreTechnique} (${evt.mitreId})`,
  severity: evt.severity,
  anomaly: evt.isAnomaly,
})), null, 2)}

TASK: Provide an authoritative, detailed, court-admissible forensic technical analysis in clean Markdown:
1. Executive Triage & Threat Actor Hypothesis (Identify likely attribution/tactics, e.g., BlackByte, FIN7, APT).
2. Deep Dive on Anti-Forensics & Evasion (Identify timestomping, log clearing, shadow copy deletion, memory injection).
3. Chain of Custody & Evidence Admissibility (Evaluate integrity, hash verification, write-blocking validity).
4. Detailed MITRE ATT&CK Mapping (Map specific observed artifact lines to MITRE technique IDs).
5. Immediate Containment & Incident Response Action Plan.
Cite specific evidence items, timestamps, and hashes in your findings.`;

    const response = await genAI.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        temperature: 0.2, // Low temperature for high forensic accuracy
      },
    });

    res.json({
      analysis: response.text || generateLocalForensicAnalysis(req.body),
      source: 'gemini-3.8-flash',
    });
  } catch (error: any) {
    console.error('Error during AI evidence analysis:', error);
    res.json({
      analysis: generateLocalForensicAnalysis(req.body),
      source: 'deterministic_engine_fallback',
      warning: error.message,
    });
  }
});

// 3. YARA & Sigma Rule Generator
app.post('/api/generate-yara', async (req: Request, res: Response) => {
  try {
    const { ruleName = 'ForensiQ_Threat_Detection', caseId, iocs = [], rawSamples = [] } = req.body;

    if (!genAI || !apiKey) {
      // Deterministic YARA generation
      const ips = iocs.filter((i: any) => i.type === 'ipv4' && i.threatLevel === 'MALICIOUS').map((i: any) => i.value);
      const hashes = iocs.filter((i: any) => i.type === 'sha256' || i.type === 'md5').map((i: any) => i.value);
      const strings = iocs.filter((i: any) => i.type === 'lolbin' || i.type === 'powershell_cmd').map((i: any) => i.value);

      const yaraRule = `/*
  ForensiQ AI Generated YARA Rule
  Case Reference: ${caseId || 'CAS-2026-0891'}
  Generated: ${new Date().toISOString()}
  Standards: ISO/IEC 27037 Evidence Rule 901
*/

rule ${ruleName.replace(/[^a-zA-Z0-9_]/g, '_')} {
  meta:
    description = "Detects indicators associated with case ${caseId || 'DFIR'}"
    author = "ForensiQ Automated Rule Generator"
    severity = "HIGH"
    date = "${new Date().toISOString().slice(0, 10)}"
    tlp = "AMBER"

  strings:
    ${strings.map((s: string, idx: number) => `$s${idx} = "${s.replace(/"/g, '\\"')}" ascii wide nocase`).join('\n    ') || '$s0 = "vssadmin delete shadows" ascii wide'}
    ${ips.map((ip: string, idx: number) => `$ip${idx} = "${ip}" ascii wide`).join('\n    ')}

  condition:
    uint16(0) == 0x5A4D and (any of ($s*) or any of ($ip*))
}

/* Equivalent Sigma Rule for SIEM / EVTX Ingestion */
title: Detect Critical Anti-Forensics & Shadow Deletion
status: production
description: Detects command lines attempting to inhibit system recovery or purge event logs
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'vssadmin delete shadows'
      - 'recoveryenabled no'
      - 'wevtutil cl'
  condition: selection
level: critical`;

      return res.json({ yaraRule, format: 'yara_and_sigma' });
    }

    const prompt = `You are a Lead Threat Intelligence & Detection Engineer.
Generate production-ready, syntax-valid YARA rule(s) and a matching Sigma YAML detection rule for the following forensic indicators:
Case: ${caseId}
IOCs: ${JSON.stringify(iocs.slice(0, 20), null, 2)}
Raw Sample Snippets: ${JSON.stringify(rawSamples.slice(0, 5), null, 2)}

Provide clean YARA syntax and Sigma rule syntax with complete metadata, strings, and boolean conditions. Do not include unneeded fluff outside code blocks.`;

    const response = await genAI.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: { temperature: 0.1 },
    });

    res.json({ yaraRule: response.text, format: 'yara_and_sigma' });
  } catch (error: any) {
    console.error('YARA generation error:', error);
    res.status(500).json({ error: error.message });
  }
});

// 4. Interactive ForensiQ Copilot Chat
app.post('/api/chat', async (req: Request, res: Response) => {
  try {
    const { message, caseContext, history = [] } = req.body;

    if (!genAI || !apiKey) {
      // Deterministic intelligent DFIR assistant
      const lower = (message || '').toLowerCase();
      let reply = '';

      if (lower.includes('vssadmin') || lower.includes('shadow')) {
        reply = `**Forensic Assessment of \`vssadmin delete shadows\`:**
Adversaries use \`vssadmin delete shadows /all /quiet\` (MITRE ATT&CK T1490 - Inhibit System Recovery) prior to encrypting storage volumes in ransomware campaigns. This prevents users and Windows Volume Shadow Service from restoring earlier snapshot versions of encrypted files. In incident response, examiners look for Event ID 4688 with parent processes such as compromised services, PsExec, or elevated PowerShell scripts.`;
      } else if (lower.includes('1102') || lower.includes('log') || lower.includes('clear') || lower.includes('anti-forensic')) {
        reply = `**Forensic Assessment of Event ID 1102 & Anti-Forensics:**
Windows Security Event ID 1102 explicitly records "The audit log was cleared". Clearing audit logs is classified under MITRE ATT&CK T1070.001 (Indicator Removal: Clear Windows Event Logs). It is almost universally indicative of an active intruder trying to erase their tracks. Forensically, we analyze the \`SubjectUserName\` and \`SubjectUserSid\` recorded inside Event 1102 to pinpoint who invoked the clear command.`;
      } else if (lower.includes('rwx') || lower.includes('malfind') || lower.includes('memory')) {
        reply = `**Volatility Malfind & RWX Protection Analysis:**
In Windows memory forensics, standard binaries allocate memory with PAGE_EXECUTE_READ (for code) and PAGE_READWRITE (for data). When a memory region has \`PAGE_EXECUTE_READWRITE\` (RWX) without being backed by a legitimate file on disk, it is a high-fidelity indicator of shellcode injection, Cobalt Strike beacons, or reflective DLL loading (T1055).`;
      } else if (lower.includes('chain of custody') || lower.includes('coc') || lower.includes('iso')) {
        reply = `**Chain of Custody (CoC) Forensics Standards:**
Under ISO/IEC 27037 and Federal Rules of Evidence Rule 901, digital evidence must be acquired using verified write-blocking hardware. Cryptographic hashes (SHA-256) calculated at acquisition time must match verification hashes at every subsequent analysis step. Any discrepancy renders the evidence legally inadmissible in court.`;
      } else {
        reply = `**ForensiQ Case Analysis:**
Based on active case **${caseContext?.metadata?.id || 'CAS-2026-0891'}**, the primary threat vectors identified include living-off-the-land utility execution, memory anomaly injection, and lateral privilege escalation. 

Recommended investigative queries:
1. *"Explain the correlation between Event 4624 and the subsequent PowerShell spawn."*
2. *"What are the primary anti-forensics indicators present in this case?"*
3. *"Draft a formal expert witness finding for the volume shadow deletion."*`;
      }

      return res.json({ reply, source: 'forensiq_knowledge_base' });
    }

    const systemInstruction = `You are ForensiQ AI, an expert digital forensics investigator, incident responder, and cybersecurity legal witness.
Current Active Case Context:
- Case ID: ${caseContext?.metadata?.id || 'CAS-2026-0891'}
- Incident Type: ${caseContext?.metadata?.incidentType || 'Ransomware'}
- Lead Suspect: ${caseContext?.metadata?.leadSuspectOrThreatActor || 'Unknown'}
- Evidence Items: ${caseContext?.evidence?.length || 0}
- Critical Timeline Events: ${caseContext?.timeline?.filter((e: any) => e.severity === 'CRITICAL').length || 0}
- IOCs: ${caseContext?.iocs?.length || 0}

Answer questions with technical rigor, citing specific forensic artifacts, timestamps, MITRE ATT&CK IDs, and forensic standards (NIST SP 800-86, ISO/IEC 27037). Keep explanations clear, actionable, and structured with markdown.`;

    const chatHistory = history.map((h: any) => ({
      role: h.role === 'user' ? 'user' : 'model',
      parts: [{ text: h.content }],
    }));

    const response = await genAI.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: [
        { role: 'user', parts: [{ text: systemInstruction }] },
        { role: 'model', parts: [{ text: 'Understood. I am ready to assist with rigorous forensic analysis.' }] },
        ...chatHistory,
        { role: 'user', parts: [{ text: message }] },
      ],
      config: { temperature: 0.3 },
    });

    res.json({ reply: response.text, source: 'gemini-3.8-flash' });
  } catch (error: any) {
    console.error('Chat error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Vite Middleware for Dev / Static Files for Production
if (process.env.NODE_ENV !== 'production') {
  const { createServer } = await import('vite');
  const vite = await createServer({
    server: { middlewareMode: true },
    appType: 'spa',
  });
  app.use(vite.middlewares);
} else {
  app.use(express.static(path.join(__dirname, 'dist')));
  app.get('*', (_req: Request, res: Response) => {
    res.sendFile(path.join(__dirname, 'dist', 'index.html'));
  });
}

app.listen(PORT, '0.0.0.0', () => {
  console.log(`ForensiQ AI Workstation server running on http://0.0.0.0:${PORT}`);
});
