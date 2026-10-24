import React, { useState } from 'react';
import { AlertTriangle, Flame, ShieldAlert, CheckCircle, Info, ChevronRight, ExternalLink } from 'lucide-react';
import { ForensicFinding, TimelineEvent } from '../forensics/types';

interface FindingsViewProps {
  findings: ForensicFinding[];
  allEvents: TimelineEvent[];
  onSelectEvent: (event: TimelineEvent) => void;
}

export const FindingsView: React.FC<FindingsViewProps> = ({
  findings,
  allEvents,
  onSelectEvent,
}) => {
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [selectedFinding, setSelectedFinding] = useState<ForensicFinding | null>(null);

  const filteredFindings = findings.filter((f) => {
    if (severityFilter !== 'ALL' && f.severity !== severityFilter) return false;
    return true;
  });

  const getSeverityBadge = (sev: ForensicFinding['severity']) => {
    if (sev === 'CRITICAL') {
      return (
        <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-rose-300 bg-rose-950/80 border border-rose-800/60 px-2 py-0.5 rounded">
          <Flame className="w-3 h-3 text-rose-400" />
          CRITICAL
        </span>
      );
    }
    if (sev === 'HIGH') {
      return (
        <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-amber-300 bg-amber-950/80 border border-amber-800/60 px-2 py-0.5 rounded">
          <AlertTriangle className="w-3 h-3 text-amber-400" />
          HIGH
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 text-[11px] font-medium text-slate-300 bg-slate-900 border border-slate-700 px-2 py-0.5 rounded">
        {sev}
      </span>
    );
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-[#0b101e] border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-rose-400" />
            <h2 className="text-base font-semibold text-white">Rule-Based Suspicious Activity Findings (Module D)</h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Deterministic detection rules. Findings disclose exact event citations, logic rationale, and known limitations.
          </p>
        </div>

        <div className="flex items-center gap-1 bg-slate-900 border border-slate-800 p-1 rounded-lg text-xs">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map((lvl) => (
            <button
              key={lvl}
              onClick={() => setSeverityFilter(lvl)}
              className={`px-3 py-1 rounded text-[11px] font-medium transition-colors ${
                severityFilter === lvl ? 'bg-blue-600 text-white shadow-xs' : 'text-slate-400 hover:text-white'
              }`}
            >
              {lvl} ({lvl === 'ALL' ? findings.length : findings.filter((f) => f.severity === lvl).length})
            </button>
          ))}
        </div>
      </div>

      {/* Disclosed Methodology Banner */}
      <div className="bg-[#080d1a] border border-slate-800 rounded-xl p-3.5 flex items-start gap-3 text-xs text-slate-400">
        <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
        <div className="leading-relaxed">
          <strong className="text-slate-200">Scientific Forensic Transparency Principle:</strong> ForensiQ AI avoids fabricated percentage risk scores. Every finding links to verifiable record numbers and explicitly documents boundary limitations to prevent false positive misinterpretation during court testimony.
        </div>
      </div>

      {/* Findings List */}
      <div className="space-y-4">
        {filteredFindings.length === 0 ? (
          <div className="bg-[#0b101e] border border-slate-800 rounded-xl p-12 text-center text-slate-400 text-xs">
            No rule violations match current severity filter.
          </div>
        ) : (
          filteredFindings.map((f) => (
            <div
              key={f.findingId}
              className="bg-[#0b101d] border border-slate-800 rounded-xl p-5 space-y-3 hover:border-slate-700 transition-colors"
            >
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="flex items-center gap-2.5">
                  <span className="font-mono text-xs font-semibold text-blue-400 bg-slate-900 border border-slate-800 px-2 py-0.5 rounded">
                    {f.findingId}
                  </span>
                  <h3 className="text-sm font-bold text-white">{f.ruleName}</h3>
                </div>

                <div className="flex items-center gap-3">
                  {getSeverityBadge(f.severity)}
                  <span className="text-[11px] font-mono text-slate-500">Rule: {f.ruleVersion}</span>
                </div>
              </div>

              {/* Detection Reason */}
              <div className="bg-[#070b14] border border-slate-800/90 rounded-lg p-3 text-xs text-slate-200">
                <span className="block text-slate-400 font-semibold text-[10px] uppercase mb-1">Detection Reason</span>
                {f.detectionReason}
              </div>

              {/* Supporting Observations */}
              <div className="space-y-1.5 text-xs">
                <span className="block text-slate-400 font-semibold text-[10px] uppercase">
                  Supporting Observations ({f.supportingObservations.length})
                </span>
                <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-3 space-y-1 text-slate-300 font-mono text-[11px]">
                  {f.supportingObservations.map((obs, idx) => (
                    <div key={idx} className="break-all">{obs}</div>
                  ))}
                </div>
              </div>

              {/* Known Limitations */}
              <div className="text-xs bg-amber-950/20 border border-amber-900/40 rounded-lg p-3 text-amber-200/90">
                <span className="block text-amber-400 font-semibold text-[10px] uppercase mb-0.5">
                  Known Rule Limitations &amp; Context
                </span>
                {f.knownLimitations}
              </div>

              {/* Event IDs Bar */}
              <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-800/80 text-xs">
                <div className="flex items-center gap-1.5 flex-wrap">
                  <span className="text-slate-400 text-[11px]">Cited Event IDs:</span>
                  {f.eventIds.map((eid) => (
                    <span
                      key={eid}
                      className="font-mono text-[11px] text-blue-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800"
                    >
                      {eid}
                    </span>
                  ))}
                </div>

                <span className="text-[11px] text-slate-500 font-mono">
                  Evaluated at: {f.detectionTimestamp.slice(0, 19).replace('T', ' ')} UTC
                </span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
