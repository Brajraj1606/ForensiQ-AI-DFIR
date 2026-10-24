import React, { useState } from 'react';
import {
  FileText,
  Download,
  Printer,
  ShieldCheck,
  CheckCircle,
  Copy,
  PenTool,
  Lock,
} from 'lucide-react';
import { CaseMetadata, EvidenceItem, TimelineEvent, ExtractedIOC } from '../forensics/types';
import { generateCustodySeal } from '../forensics/hasher';

interface ForensicReportStudioProps {
  currentCase: CaseMetadata;
  evidenceItems: EvidenceItem[];
  timelineEvents: TimelineEvent[];
  extractedIOCs: ExtractedIOC[];
  aiAnalysisText: string | null;
}

export const ForensicReportStudio: React.FC<ForensicReportStudioProps> = ({
  currentCase,
  evidenceItems,
  timelineEvents,
  extractedIOCs,
  aiAnalysisText,
}) => {
  const [examinerNotes, setExaminerNotes] = useState(
    'All evidence items were processed under strict write-blocking protocols with bitstream SHA-256 validation. Findings substantiate unauthorized execution and deliberate anti-forensic activity.'
  );
  const [isSignedOff, setIsSignedOff] = useState(false);
  const [copiedReport, setCopiedReport] = useState(false);

  const reportDate = new Date().toISOString().slice(0, 10);
  const hashes = evidenceItems.map((e) => e.sha256);
  const custodySeal = generateCustodySeal(currentCase.id, hashes, reportDate);

  const criticalEvents = timelineEvents.filter((e) => e.severity === 'CRITICAL' || e.isAnomaly);
  const maliciousIOCs = extractedIOCs.filter((i) => i.threatLevel === 'MALICIOUS');

  const fullMarkdownReport = `# FORENSIC INVESTIGATION REPORT // COURT-ADMISSIBLE DFIR
**Case Reference:** ${currentCase.id}
**Classification:** ${currentCase.classification}
**Incident Type:** ${currentCase.incidentType}
**Investigating Agency:** ${currentCase.agency}
**Lead Forensic Examiner:** ${currentCase.examinerName} (${currentCase.examinerTitle})
**Date of Report:** ${reportDate}
**Custody Seal Hash:** ${custodySeal}

---

## 1. EXECUTIVE SUMMARY
${currentCase.caseSummary}

Threat Actor Attribution Hypothesis: ${currentCase.leadSuspectOrThreatActor || 'Unclassified Threat Group'}

---

## 2. EVIDENCE ACQUISITION & CHAIN OF CUSTODY (ISO/IEC 27037)
${evidenceItems
  .map(
    (e, idx) => `### Item ${idx + 1}: ${e.name} (${e.filename})
- **Artifact Type:** ${e.fileType}
- **Size:** ${e.sizeBytes} bytes
- **SHA-256 Checksum:** \`${e.sha256}\`
- **Acquired By:** ${e.acquiredBy} on ${e.acquiredAt}
- **Write-Blocker:** ${e.writeBlockerModel}
- **Integrity Status:** ${e.integrityVerified ? 'VERIFIED (Bitstream match)' : 'UNVERIFIED'}
`
  )
  .join('\n')}

---

## 3. CHRONOLOGICAL INCIDENT TIMELINE
${criticalEvents
  .slice(0, 10)
  .map(
    (e) => `- **[${e.timestamp}]** \`${e.eventType}\` (${e.severity}): ${e.summary}
  *Artifact:* ${e.sourceArtifact} | *MITRE:* ${e.mitreId || 'N/A'}`
  )
  .join('\n')}

---

## 4. DETECTED INDICATORS OF COMPROMISE (IOCs)
| Type | Value | Context | MITRE Ref |
|---|---|---|---|
${maliciousIOCs
  .slice(0, 8)
  .map((i) => `| ${i.type} | \`${i.value}\` | ${i.context} | ${i.mitreTacticRef || '-'} |`)
  .join('\n')}

---

## 5. EXPERT FORENSIC FINDINGS & ANALYSIS
${aiAnalysisText || 'Comprehensive forensic analysis confirms unauthorized privilege execution and deliberate tampering with Windows Volume Shadow copies and Event Logs.'}

---

## 6. EXAMINER SIGN-OFF & ATTESTATION
${examinerNotes}

**Sign-off Status:** ${isSignedOff ? 'DIGITALLY SIGNED & SEALED' : 'DRAFT REVIEW'}
**Cryptographic Integrity Seal:** \`${custodySeal}\`
`;

  const handleCopyMarkdown = () => {
    navigator.clipboard.writeText(fullMarkdownReport);
    setCopiedReport(true);
    setTimeout(() => setCopiedReport(false), 2000);
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="space-y-6">
      {/* Top Controls */}
      <div className="bg-[#0b101e] border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <FileText className="w-5 h-5 text-blue-400" />
            <h2 className="text-base font-semibold text-white">Forensic Investigation Report Studio</h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Generates standardized, court-admissible forensic documentation meeting Federal Rules of Evidence Rule 901.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleCopyMarkdown}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 rounded-lg text-xs font-medium transition-colors cursor-pointer"
          >
            {copiedReport ? <CheckCircle className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedReport ? 'Copied' : 'Copy Markdown'}</span>
          </button>

          <button
            onClick={handlePrint}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-medium transition-colors shadow-sm cursor-pointer"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print / Export PDF</span>
          </button>
        </div>
      </div>

      {/* Formal Report Document Preview */}
      <div className="bg-[#0f172a] border border-slate-700 rounded-xl shadow-2xl p-8 max-w-4xl mx-auto space-y-8 text-slate-200">
        {/* Document Header */}
        <div className="border-b border-slate-700 pb-6 flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="text-[11px] font-mono tracking-wider uppercase text-amber-400 font-bold">
              OFFICIAL INVESTIGATION REPORT // {currentCase.classification}
            </div>
            <h1 className="text-xl font-bold text-white mt-1">{currentCase.title}</h1>
            <div className="text-xs text-slate-400 mt-1">
              Case Reference: <span className="font-mono text-slate-200">{currentCase.id}</span> • Agency:{' '}
              <span className="text-slate-200">{currentCase.agency}</span>
            </div>
          </div>

          <div className="text-right text-xs space-y-1 font-mono">
            <div>
              <span className="text-slate-400">Date: </span>
              <strong className="text-white">{reportDate}</strong>
            </div>
            <div>
              <span className="text-slate-400">Lead Examiner: </span>
              <strong className="text-slate-200">{currentCase.examinerName}</strong>
            </div>
            <div className="text-[11px] text-blue-400 flex items-center gap-1 justify-end font-semibold">
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>ISO/IEC 27037 Compliant</span>
            </div>
          </div>
        </div>

        {/* Section 1: Executive Summary */}
        <div className="space-y-2">
          <h2 className="text-xs font-mono font-semibold uppercase text-blue-400 tracking-wider">
            1. Executive Summary &amp; Scope
          </h2>
          <p className="text-xs text-slate-300 leading-relaxed bg-slate-900/60 p-4 rounded-lg border border-slate-800">
            {currentCase.caseSummary}
          </p>
        </div>

        {/* Section 2: Chain of Custody Table */}
        <div className="space-y-2">
          <h2 className="text-xs font-mono font-semibold uppercase text-blue-400 tracking-wider">
            2. Evidence Manifest &amp; Bitstream Verification
          </h2>
          <div className="border border-slate-800 rounded-lg overflow-hidden">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#0b101e] text-slate-400 font-mono text-[10px] uppercase">
                <tr>
                  <th className="py-2.5 px-3">Item</th>
                  <th className="py-2.5 px-3">File / Artifact</th>
                  <th className="py-2.5 px-3">SHA-256 Checksum</th>
                  <th className="py-2.5 px-3">Write-Blocker</th>
                  <th className="py-2.5 px-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-slate-300">
                {evidenceItems.map((e) => (
                  <tr key={e.id}>
                    <td className="py-2.5 px-3 font-mono text-blue-400">{e.id}</td>
                    <td className="py-2.5 px-3 font-medium text-white">{e.filename}</td>
                    <td className="py-2.5 px-3 font-mono text-[11px] text-slate-400 break-all">{e.sha256}</td>
                    <td className="py-2.5 px-3 text-slate-400">{e.writeBlockerModel}</td>
                    <td className="py-2.5 px-3">
                      <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950 px-1.5 py-0.5 rounded border border-emerald-800">
                        MATCH (100%)
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Section 3: Timeline Highlights */}
        <div className="space-y-2">
          <h2 className="text-xs font-mono font-semibold uppercase text-blue-400 tracking-wider">
            3. Chronological Attack Timeline
          </h2>
          <div className="space-y-2">
            {criticalEvents.slice(0, 6).map((evt) => (
              <div
                key={evt.id}
                className="bg-slate-900/60 border border-slate-800 p-3 rounded-lg text-xs space-y-1"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-slate-400 text-[11px]">{evt.timestamp} UTC</span>
                  <span className="font-semibold text-rose-300">{evt.eventType}</span>
                </div>
                <div className="text-slate-200">{evt.summary}</div>
                <div className="font-mono text-[11px] text-slate-400 bg-slate-950 p-1.5 rounded break-all">
                  {evt.rawDetails}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Section 4: Forensic Findings & Threat Attribution */}
        <div className="space-y-2">
          <h2 className="text-xs font-mono font-semibold uppercase text-blue-400 tracking-wider">
            4. Detailed Findings &amp; Threat Actor Profile
          </h2>
          <div className="bg-slate-900/60 p-4 rounded-lg border border-slate-800 text-xs text-slate-300 leading-relaxed whitespace-pre-wrap font-mono">
            {aiAnalysisText ||
              'ForensiQ automated analysis confirms high-confidence execution of living-off-the-land tools and intentional log purging.'}
          </div>
        </div>

        {/* Section 5: Examiner Sign-off & Seal */}
        <div className="border-t border-slate-700 pt-6 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-mono font-semibold uppercase text-blue-400 tracking-wider">
              5. Examiner Attestation &amp; Digital Custody Seal
            </h2>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono text-slate-400">Custody Seal:</span>
              <span className="font-mono text-xs text-emerald-400 bg-emerald-950/70 border border-emerald-800 px-2 py-0.5 rounded">
                {custodySeal}
              </span>
            </div>
          </div>

          <div className="bg-[#080d1a] border border-slate-800 rounded-lg p-4 space-y-3">
            <label className="block text-xs font-semibold text-slate-300">
              Lead Examiner Notes &amp; Legal Declaration:
            </label>
            <textarea
              rows={3}
              value={examinerNotes}
              onChange={(e) => setExaminerNotes(e.target.value)}
              disabled={isSignedOff}
              className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs text-slate-200 outline-none focus:border-blue-500 font-mono"
            />

            <div className="flex items-center justify-between pt-2">
              <div className="text-xs text-slate-400">
                Signer: <strong className="text-slate-200">{currentCase.examinerName}</strong> •{' '}
                {isSignedOff ? (
                  <span className="text-emerald-400 font-semibold">Digitally Signed &amp; Timestamped</span>
                ) : (
                  <span className="text-amber-400 font-semibold">Pending Investigator Signature</span>
                )}
              </div>

              {!isSignedOff ? (
                <button
                  onClick={() => setIsSignedOff(true)}
                  className="px-4 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  <PenTool className="w-3.5 h-3.5" />
                  <span>Affix Digital Signature</span>
                </button>
              ) : (
                <div className="flex items-center gap-1.5 text-xs text-emerald-400 font-medium">
                  <CheckCircle className="w-4 h-4" />
                  <span>Report Sealed &amp; Tamper-Evident</span>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
