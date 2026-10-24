import React from 'react';
import { X, BookOpen, ShieldCheck, Scale, Cpu, Layers } from 'lucide-react';

interface StandardsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const StandardsModal: React.FC<StandardsModalProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-xs">
      <div className="bg-[#0f172a] border border-slate-700 w-full max-w-4xl max-h-[85vh] rounded-xl flex flex-col shadow-2xl overflow-hidden text-slate-200">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-[#131c31]">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-500/10 border border-blue-500/30 rounded-lg text-blue-400">
              <BookOpen className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-white">Forensic Standards, Methodologies &amp; Legal Admissibility</h2>
              <p className="text-xs text-slate-400">Academic &amp; Operational Reference Guide for Digital Forensics Specialists</p>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close standards modal"
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-6 text-sm text-slate-300">
          {/* Section 1: ISO/IEC 27037 */}
          <div className="space-y-2 border-b border-slate-800 pb-5">
            <div className="flex items-center gap-2 text-blue-400 font-medium text-base">
              <ShieldCheck className="w-4 h-4" />
              <span>1. ISO/IEC 27037: Guidelines for Handling Digital Evidence</span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              International standard establishing four primary phases for digital evidence: <strong className="text-white">Identification</strong>, <strong className="text-white">Collection</strong>, <strong className="text-white">Acquisition</strong>, and <strong className="text-white">Preservation</strong>. ForensiQ AI verifies write-blocker compliance, computes cryptographic checksums at acquisition, and maintains a tamper-evident audit ledger.
            </p>
          </div>

          {/* Section 2: Order of Volatility */}
          <div className="space-y-2 border-b border-slate-800 pb-5">
            <div className="flex items-center gap-2 text-amber-400 font-medium text-base">
              <Cpu className="w-4 h-4" />
              <span>2. RFC 3227 Order of Volatility</span>
            </div>
            <p className="text-xs text-slate-300 mb-2">
              During triage, evidence must be collected from most volatile to least volatile to prevent critical data loss upon system shutdown:
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono bg-slate-900/80 p-3 rounded-lg border border-slate-800">
              <div className="text-slate-400">1. CPU Registers &amp; Cache</div>
              <div className="text-slate-400">2. Routing Tables, ARP &amp; Kernel Stats</div>
              <div className="text-amber-300 font-medium">3. Physical Memory (RAM) &amp; Processes</div>
              <div className="text-slate-400">4. Temporary File Systems &amp; Swap</div>
              <div className="text-blue-300">5. Disk / Non-volatile Media (MFT, Logs)</div>
              <div className="text-slate-400">6. Archival Media &amp; Off-site Backups</div>
            </div>
          </div>

          {/* Section 3: Legal Admissibility & FRE 901 */}
          <div className="space-y-2 border-b border-slate-800 pb-5">
            <div className="flex items-center gap-2 text-emerald-400 font-medium text-base">
              <Scale className="w-4 h-4" />
              <span>3. Legal Admissibility (Federal Rules of Evidence 901 &amp; Daubert Standard)</span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              In court proceedings, digital evidence is admissible only if authenticated under FRE 901(b)(9)—demonstrating the system or process produces an accurate result without unauthorized alteration. The <strong>Daubert Standard</strong> requires that scientific methodologies (such as SHA-256 integrity verification, Volatility memory analysis, and AI reasoning) possess known error rates, peer-reviewed acceptance, and verifiable chain-of-custody tracking.
            </p>
          </div>

          {/* Section 4: Locard's Exchange Principle */}
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-purple-400 font-medium text-base">
              <Layers className="w-4 h-4" />
              <span>4. Locard&apos;s Exchange Principle in Digital Forensics</span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              <em>&ldquo;Every contact leaves a trace.&rdquo;</em> Whenever an adversary or analyst touches a system, data is both transferred to and taken from the host. In cyber incidents, this manifests as Shellbags, Shimcache, Prefetch records, Event Log IDs (4624, 4688, 7045), and unbacked executable memory allocations. ForensiQ AI automates the correlation of these traces into a cohesive chronological graph.
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-6 py-3 border-t border-slate-800 bg-[#0d1424] text-xs text-slate-400">
          <span>ForensiQ AI Standards Engine • NIST SP 800-86 Compliant</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded-md transition-colors"
          >
            Close Guide
          </button>
        </div>
      </div>
    </div>
  );
};
