import React, { useState } from 'react';
import {
  ShieldAlert,
  Copy,
  Check,
  FileCode,
  Terminal,
  Binary,
  Code2,
  Sparkles,
  Download,
} from 'lucide-react';
import { ExtractedIOC, EvidenceItem } from '../forensics/types';

interface IOCInspectorProps {
  iocs: ExtractedIOC[];
  evidenceItems: EvidenceItem[];
  selectedEvidence: EvidenceItem | null;
  onSelectEvidence: (item: EvidenceItem) => void;
  caseId: string;
}

export const IOCInspector: React.FC<IOCInspectorProps> = ({
  iocs,
  evidenceItems,
  selectedEvidence,
  onSelectEvidence,
  caseId,
}) => {
  const [activeTab, setActiveTab] = useState<'iocs' | 'raw_hex'>('iocs');
  const [threatFilter, setThreatFilter] = useState<string>('ALL');
  const [copiedValue, setCopiedValue] = useState<string | null>(null);
  const [isYaraModalOpen, setIsYaraModalOpen] = useState<boolean>(false);
  const [generatedYara, setGeneratedYara] = useState<string | null>(null);
  const [isGeneratingYara, setIsGeneratingYara] = useState<boolean>(false);

  const activeEvidence = selectedEvidence || evidenceItems[0] || null;

  const filteredIocs = iocs.filter((ioc) => {
    if (threatFilter !== 'ALL' && ioc.threatLevel !== threatFilter) return false;
    return true;
  });

  const handleCopy = (val: string) => {
    navigator.clipboard.writeText(val);
    setCopiedValue(val);
    setTimeout(() => setCopiedValue(null), 2000);
  };

  const handleGenerateYara = async () => {
    setIsGeneratingYara(true);
    setIsYaraModalOpen(true);
    try {
      const res = await fetch('/api/generate-yara', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ruleName: `Detect_Case_${caseId.replace(/[^a-zA-Z0-9]/g, '_')}`,
          caseId,
          iocs: iocs.slice(0, 15),
          rawSamples: activeEvidence ? [activeEvidence.rawContent.slice(0, 500)] : [],
        }),
      });
      const data = await res.json();
      setGeneratedYara(data.yaraRule);
    } catch (err) {
      console.error(err);
      setGeneratedYara('// Error connecting to YARA synthesis service.');
    } finally {
      setIsGeneratingYara(false);
    }
  };

  // Generate simulated hex view for raw artifact
  const generateHexDump = (content: string) => {
    const lines = content.slice(0, 1500).split('\n');
    return lines.map((l, idx) => {
      const offset = (idx * 16).toString(16).padStart(8, '0');
      const hex = Array.from(l.slice(0, 16))
        .map((c) => c.charCodeAt(0).toString(16).padStart(2, '0'))
        .join(' ')
        .padEnd(48, ' ');
      const ascii = l.slice(0, 16).replace(/[^\x20-\x7E]/g, '.');
      return `${offset}  ${hex} |${ascii}|`;
    });
  };

  return (
    <div className="space-y-4">
      {/* View Switcher & Action Bar */}
      <div className="bg-[#0b101e] border border-slate-800 rounded-xl p-3 flex flex-wrap items-center justify-between gap-4 text-xs">
        <div className="flex items-center gap-2">
          <div className="flex items-center bg-slate-900 border border-slate-800 p-1 rounded-lg">
            <button
              onClick={() => setActiveTab('iocs')}
              className={`px-3 py-1.5 rounded-md font-medium transition-colors ${
                activeTab === 'iocs' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'
              }`}
            >
              Extracted Indicators ({iocs.length})
            </button>
            <button
              onClick={() => setActiveTab('raw_hex')}
              className={`px-3 py-1.5 rounded-md font-medium transition-colors ${
                activeTab === 'raw_hex' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'
              }`}
            >
              Raw Artifact &amp; Hex Inspector
            </button>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {activeTab === 'iocs' && (
            <div className="flex items-center gap-1 bg-slate-900 border border-slate-800 p-1 rounded-lg">
              {['ALL', 'MALICIOUS', 'SUSPICIOUS', 'BENIGN'].map((lvl) => (
                <button
                  key={lvl}
                  onClick={() => setThreatFilter(lvl)}
                  className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                    threatFilter === lvl ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {lvl}
                </button>
              ))}
            </div>
          )}

          <button
            onClick={handleGenerateYara}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border border-blue-500/30 rounded-lg font-medium transition-colors cursor-pointer"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>Generate YARA &amp; Sigma Rules</span>
          </button>
        </div>
      </div>

      {/* Tab 1: IOCs Table */}
      {activeTab === 'iocs' && (
        <div className="bg-[#0b101e] border border-slate-800 rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#0f172a] text-slate-400 uppercase font-mono text-[10px] border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Indicator Type</th>
                  <th className="py-3 px-4">Observable Value</th>
                  <th className="py-3 px-4">Threat Rating</th>
                  <th className="py-3 px-4">Forensic Context</th>
                  <th className="py-3 px-4">MITRE Ref</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80 text-slate-300">
                {filteredIocs.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-slate-500">
                      No indicators match the current filter.
                    </td>
                  </tr>
                ) : (
                  filteredIocs.map((ioc, idx) => (
                    <tr key={`${ioc.type}-${ioc.value}-${idx}`} className="hover:bg-slate-900/50 transition-colors">
                      <td className="py-3 px-4 font-mono">
                        <span className="text-blue-400 font-semibold">{ioc.type}</span>
                        {ioc.count > 1 && (
                          <span className="text-[10px] text-slate-500 ml-1">({ioc.count}x)</span>
                        )}
                      </td>
                      <td className="py-3 px-4 font-mono select-all text-slate-200 break-all max-w-xs">
                        {ioc.value}
                      </td>
                      <td className="py-3 px-4">
                        {ioc.threatLevel === 'MALICIOUS' ? (
                          <span className="text-[10px] font-semibold text-rose-300 bg-rose-950/70 border border-rose-800/50 px-2 py-0.5 rounded">
                            MALICIOUS
                          </span>
                        ) : ioc.threatLevel === 'SUSPICIOUS' ? (
                          <span className="text-[10px] font-semibold text-amber-300 bg-amber-950/70 border border-amber-800/50 px-2 py-0.5 rounded">
                            SUSPICIOUS
                          </span>
                        ) : (
                          <span className="text-[10px] text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                            BENIGN
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-slate-400">{ioc.context}</td>
                      <td className="py-3 px-4 font-mono text-[11px] text-blue-300">
                        {ioc.mitreTacticRef || '—'}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => handleCopy(ioc.value)}
                          aria-label={`Copy observable value ${ioc.value}`}
                          className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800 transition-colors inline-flex items-center gap-1"
                        >
                          {copiedValue === ioc.value ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 2: Raw Artifact & Hex Inspector */}
      {activeTab === 'raw_hex' && activeEvidence && (
        <div className="space-y-4">
          {/* Artifact Selector */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400">Inspecting Artifact:</span>
            <select
              value={activeEvidence.id}
              onChange={(e) => {
                const found = evidenceItems.find((item) => item.id === e.target.value);
                if (found) onSelectEvidence(found);
              }}
              className="bg-slate-900 border border-slate-700 text-slate-200 text-xs rounded px-2.5 py-1 outline-none"
            >
              {evidenceItems.map((e) => (
                <option key={e.id} value={e.id}>
                  {e.name} ({e.filename})
                </option>
              ))}
            </select>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Raw Text Stream */}
            <div className="bg-[#060a12] border border-slate-800 rounded-xl p-4 flex flex-col h-[500px]">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2 mb-3 text-xs">
                <span className="font-semibold text-slate-300 flex items-center gap-1.5">
                  <Terminal className="w-4 h-4 text-blue-400" />
                  Raw Text / Log Stream
                </span>
                <span className="font-mono text-[11px] text-slate-500">
                  {activeEvidence.rawContent.split('\n').length} lines
                </span>
              </div>
              <div className="flex-1 overflow-y-auto font-mono text-[11px] text-slate-300 space-y-1 select-all">
                {activeEvidence.rawContent.split('\n').map((line, idx) => (
                  <div key={idx} className="hover:bg-slate-900/60 px-1 rounded flex gap-2">
                    <span className="text-slate-600 select-none w-8 text-right shrink-0">{idx + 1}</span>
                    <span className="break-all">{line}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Hex Dump */}
            <div className="bg-[#060a12] border border-slate-800 rounded-xl p-4 flex flex-col h-[500px]">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2 mb-3 text-xs">
                <span className="font-semibold text-slate-300 flex items-center gap-1.5">
                  <Binary className="w-4 h-4 text-purple-400" />
                  Hexadecimal Offset Inspection
                </span>
                <span className="font-mono text-[11px] text-slate-500">Offset | Hex | ASCII</span>
              </div>
              <div className="flex-1 overflow-y-auto font-mono text-[11px] text-slate-300 space-y-1 select-all">
                {generateHexDump(activeEvidence.rawContent).map((line, idx) => (
                  <div key={idx} className="hover:bg-slate-900/60 px-1 rounded whitespace-pre">
                    {line}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* YARA & Sigma Rules Modal */}
      {isYaraModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-xs">
          <div className="bg-[#0f172a] border border-slate-700 w-full max-w-3xl max-h-[85vh] rounded-xl flex flex-col shadow-2xl overflow-hidden text-slate-200">
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-[#131c31]">
              <div className="flex items-center gap-2">
                <Code2 className="w-5 h-5 text-blue-400" />
                <h3 className="text-base font-semibold text-white">Generated YARA &amp; Sigma Detection Rules</h3>
              </div>
              <button
                onClick={() => setIsYaraModalOpen(false)}
                className="text-slate-400 hover:text-white text-xs px-2 py-1 rounded hover:bg-slate-800"
              >
                Close
              </button>
            </div>

            <div className="p-6 overflow-y-auto space-y-4">
              {isGeneratingYara ? (
                <div className="py-12 text-center text-slate-400 space-y-2">
                  <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto" />
                  <p className="text-xs">Synthesizing production YARA and Sigma rules from case IOCs...</p>
                </div>
              ) : (
                <div className="space-y-3">
                  <p className="text-xs text-slate-400">
                    Use these rules in your EDR/SIEM or Volatility memory scanner to detect related adversary artifacts:
                  </p>
                  <pre className="bg-[#070b14] border border-slate-800 rounded-lg p-4 font-mono text-xs text-emerald-300 overflow-x-auto select-all leading-relaxed">
                    {generatedYara}
                  </pre>
                </div>
              )}
            </div>

            <div className="px-6 py-3 border-t border-slate-800 bg-[#0d1424] flex items-center justify-between text-xs">
              <span className="text-slate-400">Ready for deployment in Splunk, Elastic, or Suricata</span>
              <div className="flex gap-2">
                {generatedYara && (
                  <button
                    onClick={() => handleCopy(generatedYara)}
                    className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded font-medium flex items-center gap-1"
                  >
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy Rules</span>
                  </button>
                )}
                <button
                  onClick={() => setIsYaraModalOpen(false)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded font-medium"
                >
                  Done
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
