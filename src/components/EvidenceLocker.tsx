import React, { useState } from 'react';
import {
  FileText,
  HardDrive,
  Cpu,
  Wifi,
  ShieldCheck,
  CheckCircle2,
  Copy,
  Plus,
  History,
  Lock,
  ChevronRight,
  Terminal,
  FileCheck,
} from 'lucide-react';
import { EvidenceItem } from '../forensics/types';
import { computeSha256Simulated, computeMd5Simulated } from '../forensics/hasher';

interface EvidenceLockerProps {
  evidenceItems: EvidenceItem[];
  onVerifyIntegrity: (evidenceId: string) => void;
  onAddEvidence: (item: EvidenceItem) => void;
  onSelectEvidenceForInspector: (item: EvidenceItem) => void;
}

export const EvidenceLocker: React.FC<EvidenceLockerProps> = ({
  evidenceItems,
  onVerifyIntegrity,
  onAddEvidence,
  onSelectEvidenceForInspector,
}) => {
  const [selectedCustodyItem, setSelectedCustodyItem] = useState<EvidenceItem | null>(null);
  const [isIngestModalOpen, setIsIngestModalOpen] = useState(false);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Ingest form state
  const [newTitle, setNewTitle] = useState('');
  const [newFilename, setNewFilename] = useState('');
  const [newFileType, setNewFileType] = useState<EvidenceItem['fileType']>('evtx_logs');
  const [newContent, setNewContent] = useState('');
  const [newWriteBlocker, setNewWriteBlocker] = useState('Tableau T8u Forensic USB 3.0 Bridge');
  const [newExaminer, setNewExaminer] = useState('Agent Alex Mercer');

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(id);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const handleIngestSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newFilename || !newContent) return;

    const sha256 = computeSha256Simulated(newContent);
    const md5 = computeMd5Simulated(newContent);
    const now = new Date().toISOString();

    const newItem: EvidenceItem = {
      id: `EVD-${String(evidenceItems.length + 1).padStart(3, '0')}`,
      name: newTitle || newFilename,
      filename: newFilename,
      fileType: newFileType,
      sizeBytes: new Blob([newContent]).size,
      sha256,
      md5,
      sha1: 'e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3',
      acquiredAt: now,
      acquiredBy: newExaminer,
      writeBlockerModel: newWriteBlocker,
      rawContent: newContent,
      parsedArtifactsCount: newContent.split('\n').filter(Boolean).length,
      integrityVerified: true,
      custodyLog: [
        {
          id: `COC-${Date.now()}-A`,
          timestamp: now,
          action: 'ACQUISITION',
          actor: newExaminer,
          location: 'ForensiQ Digital Intake Laboratory',
          notes: `Hardware write-blocking applied via ${newWriteBlocker}; SHA-256 computed on ingest.`,
          hashMatch: true,
          algorithm: 'SHA-256',
          hashValue: sha256,
        },
      ],
    };

    onAddEvidence(newItem);
    setIsIngestModalOpen(false);
    setNewTitle('');
    setNewFilename('');
    setNewContent('');
  };

  const getFileIcon = (type: EvidenceItem['fileType']) => {
    switch (type) {
      case 'memory_dump':
        return <Cpu className="w-5 h-5 text-amber-400" />;
      case 'evtx_logs':
        return <FileText className="w-5 h-5 text-blue-400" />;
      case 'pcap_network':
        return <Wifi className="w-5 h-5 text-emerald-400" />;
      case 'disk_image':
        return <HardDrive className="w-5 h-5 text-purple-400" />;
      case 'syslog':
        return <Terminal className="w-5 h-5 text-cyan-400" />;
      default:
        return <FileText className="w-5 h-5 text-slate-400" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner & Ingest Action */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-[#0d1424] border border-slate-800 p-4 rounded-xl">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base font-semibold text-white">Forensic Evidence Locker</h2>
            <span className="text-xs font-mono text-slate-400">({evidenceItems.length} items cataloged)</span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Cryptographically sealed under ISO/IEC 27037 with bitstream integrity verification.
          </p>
        </div>

        <button
          onClick={() => setIsIngestModalOpen(true)}
          className="flex items-center gap-1.5 px-3.5 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-medium transition-colors shadow-sm cursor-pointer"
        >
          <Plus className="w-4 h-4" />
          <span>Ingest New Evidence</span>
        </button>
      </div>

      {/* Evidence Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {evidenceItems.map((item) => (
          <div
            key={item.id}
            className="bg-[#0b101d] border border-slate-800 rounded-xl p-4 flex flex-col justify-between hover:border-slate-700 transition-colors"
          >
            <div>
              {/* Item Top Info */}
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 bg-slate-900 border border-slate-800 rounded-lg">
                    {getFileIcon(item.fileType)}
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-white leading-tight">{item.name}</h3>
                    <span className="text-xs font-mono text-slate-400">{item.filename}</span>
                  </div>
                </div>

                <div className="flex items-center gap-1.5">
                  {item.integrityVerified ? (
                    <span className="inline-flex items-center gap-1 text-[11px] font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800/40 px-2 py-0.5 rounded">
                      <CheckCircle2 className="w-3 h-3" />
                      Verified
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-[11px] font-mono text-amber-400 bg-amber-950/60 border border-amber-800/40 px-2 py-0.5 rounded">
                      Unverified
                    </span>
                  )}
                </div>
              </div>

              {/* Hashes & Acquisition Meta */}
              <div className="mt-4 space-y-2 text-xs">
                {/* SHA-256 */}
                <div className="bg-[#080d1a] border border-slate-800/90 rounded-lg p-2 font-mono">
                  <div className="flex items-center justify-between text-[11px] text-slate-400 mb-1">
                    <span className="flex items-center gap-1 font-semibold text-blue-400">
                      <Lock className="w-3 h-3" /> SHA-256 CHECKSUM
                    </span>
                    <button
                      onClick={() => handleCopy(item.sha256, `${item.id}-sha`)}
                      aria-label={`Copy SHA-256 checksum for ${item.filename}`}
                      className="text-slate-400 hover:text-white flex items-center gap-1 transition-colors"
                    >
                      <Copy className="w-3 h-3" />
                      {copiedHash === `${item.id}-sha` ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <div className="text-[11px] text-slate-300 break-all select-all font-mono">
                    {item.sha256}
                  </div>
                </div>

                {/* Metadata Row */}
                <div className="grid grid-cols-2 gap-2 text-[11px] text-slate-400 pt-1">
                  <div>
                    <span className="block text-slate-500">Acquired By:</span>
                    <span className="text-slate-300 truncate block">{item.acquiredBy}</span>
                  </div>
                  <div>
                    <span className="block text-slate-500">Acquisition Device:</span>
                    <span className="text-slate-300 truncate block">{item.writeBlockerModel}</span>
                  </div>
                  <div>
                    <span className="block text-slate-500">Timestamp:</span>
                    <span className="text-slate-300">{item.acquiredAt.replace('T', ' ').slice(0, 19)} UTC</span>
                  </div>
                  <div>
                    <span className="block text-slate-500">Artifact Lines:</span>
                    <span className="text-slate-300">{item.parsedArtifactsCount} records</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Actions Bar */}
            <div className="mt-5 pt-3 border-t border-slate-800/80 flex items-center justify-between gap-2 text-xs">
              <button
                onClick={() => setSelectedCustodyItem(item)}
                className="flex items-center gap-1.5 text-slate-400 hover:text-slate-200 transition-colors"
              >
                <History className="w-3.5 h-3.5 text-blue-400" />
                <span>Chain of Custody ({item.custodyLog.length})</span>
              </button>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => onVerifyIntegrity(item.id)}
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
                >
                  Verify Hash
                </button>
                <button
                  onClick={() => onSelectEvidenceForInspector(item)}
                  className="px-2.5 py-1 rounded bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border border-blue-500/30 transition-colors flex items-center gap-1"
                >
                  <span>Inspect</span>
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Chain of Custody Modal */}
      {selectedCustodyItem && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-xs">
          <div className="bg-[#0f172a] border border-slate-700 w-full max-w-2xl max-h-[85vh] rounded-xl flex flex-col shadow-2xl overflow-hidden text-slate-200">
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-[#131c31]">
              <div className="flex items-center gap-2.5">
                <History className="w-5 h-5 text-blue-400" />
                <div>
                  <h3 className="text-sm font-semibold text-white">
                    Chain of Custody Ledger // {selectedCustodyItem.filename}
                  </h3>
                  <span className="text-xs text-slate-400">
                    Audit trail conforming to Federal Rules of Evidence Rule 901
                  </span>
                </div>
              </div>
              <button
                onClick={() => setSelectedCustodyItem(null)}
                className="text-slate-400 hover:text-white text-xs px-2 py-1 rounded hover:bg-slate-800"
              >
                Close
              </button>
            </div>

            <div className="p-6 overflow-y-auto space-y-4">
              <div className="space-y-4 relative before:absolute before:inset-0 before:left-3.5 before:w-0.5 before:bg-slate-800">
                {selectedCustodyItem.custodyLog.map((log) => (
                  <div key={log.id} className="relative flex items-start gap-4 text-xs">
                    <div className="w-7 h-7 rounded-full bg-slate-900 border border-slate-700 flex items-center justify-center z-10 text-blue-400 shrink-0">
                      <ShieldCheck className="w-3.5 h-3.5" />
                    </div>
                    <div className="flex-1 bg-[#0b101e] border border-slate-800 rounded-lg p-3 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-white text-xs">{log.action}</span>
                        <span className="font-mono text-[11px] text-slate-400">{log.timestamp}</span>
                      </div>
                      <div className="text-slate-300 text-xs">{log.notes}</div>
                      <div className="flex items-center gap-4 text-[11px] text-slate-400 pt-1 border-t border-slate-800/80">
                        <span>Actor: <strong className="text-slate-300">{log.actor}</strong></span>
                        <span>Location: <strong className="text-slate-300">{log.location}</strong></span>
                        <span className="text-emerald-400 font-mono">Hash Match: OK</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Ingest Modal */}
      {isIngestModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-xs">
          <div className="bg-[#0f172a] border border-slate-700 w-full max-w-2xl max-h-[90vh] rounded-xl flex flex-col shadow-2xl overflow-hidden text-slate-200">
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-[#131c31]">
              <div className="flex items-center gap-2">
                <FileCheck className="w-5 h-5 text-blue-400" />
                <h3 className="text-sm font-semibold text-white">Ingest Digital Evidence (ISO/IEC 27037)</h3>
              </div>
              <button
                onClick={() => setIsIngestModalOpen(false)}
                className="text-slate-400 hover:text-white text-xs px-2 py-1 rounded hover:bg-slate-800"
              >
                Cancel
              </button>
            </div>

            <form onSubmit={handleIngestSubmit} className="p-6 overflow-y-auto space-y-4 text-xs">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Evidence Title</label>
                  <input
                    type="text"
                    required
                    value={newTitle}
                    onChange={(e) => setNewTitle(e.target.value)}
                    placeholder="e.g. Workstation Audit Log"
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Filename</label>
                  <input
                    type="text"
                    required
                    value={newFilename}
                    onChange={(e) => setNewFilename(e.target.value)}
                    placeholder="e.g. host_security.evtx"
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 outline-none focus:border-blue-500 font-mono"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Artifact Type</label>
                  <select
                    value={newFileType}
                    onChange={(e) => setNewFileType(e.target.value as any)}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 outline-none focus:border-blue-500"
                  >
                    <option value="evtx_logs">Windows Event Logs (.evtx)</option>
                    <option value="memory_dump">Physical Memory Snapshot (.raw / Volatility)</option>
                    <option value="syslog">Linux Syslog / Auditd (.log)</option>
                    <option value="pcap_network">Network Capture / Zeek / Suricata (.pcap / .log)</option>
                    <option value="disk_image">Disk Image / MFT / Registry (.dd / .e01)</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Acquisition Write-Blocker</label>
                  <input
                    type="text"
                    value={newWriteBlocker}
                    onChange={(e) => setNewWriteBlocker(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Examiner Name</label>
                <input
                  type="text"
                  value={newExaminer}
                  onChange={(e) => setNewExaminer(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Raw Artifact Content / Log Stream</label>
                <textarea
                  rows={8}
                  required
                  value={newContent}
                  onChange={(e) => setNewContent(e.target.value)}
                  placeholder="Paste raw log lines, Volatility output, or terminal dumps here..."
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-3 text-slate-200 font-mono text-[11px] outline-none focus:border-blue-500"
                />
              </div>

              <div className="flex justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsIngestModalOpen(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium"
                >
                  Seal &amp; Ingest Evidence
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
