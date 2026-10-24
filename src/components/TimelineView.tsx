import React, { useState, useMemo } from 'react';
import {
  Clock,
  Filter,
  Search,
  AlertTriangle,
  Flame,
  Shield,
  FileCode,
  Tag,
  ExternalLink,
  Info,
} from 'lucide-react';
import { TimelineEvent } from '../forensics/types';

interface TimelineViewProps {
  events: TimelineEvent[];
  onSelectEventForAnalysis: (event: TimelineEvent) => void;
}

export const TimelineView: React.FC<TimelineViewProps> = ({ events, onSelectEventForAnalysis }) => {
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [showAnomaliesOnly, setShowAnomaliesOnly] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedEvent, setSelectedEvent] = useState<TimelineEvent | null>(null);

  const filteredEvents = useMemo(() => {
    return events.filter((evt) => {
      if (severityFilter !== 'ALL' && evt.severity !== severityFilter) return false;
      if (showAnomaliesOnly && !evt.isAnomaly) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const match =
          evt.summary.toLowerCase().includes(q) ||
          evt.rawDetails.toLowerCase().includes(q) ||
          evt.eventType.toLowerCase().includes(q) ||
          (evt.processName && evt.processName.toLowerCase().includes(q)) ||
          (evt.mitreId && evt.mitreId.toLowerCase().includes(q)) ||
          (evt.sourceIp && evt.sourceIp.includes(q));
        if (!match) return false;
      }
      return true;
    });
  }, [events, severityFilter, showAnomaliesOnly, searchQuery]);

  const getSeverityBadge = (severity: TimelineEvent['severity']) => {
    switch (severity) {
      case 'CRITICAL':
        return (
          <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-rose-300 bg-rose-950/80 border border-rose-800/60 px-2 py-0.5 rounded">
            <Flame className="w-3 h-3 text-rose-400" />
            CRITICAL
          </span>
        );
      case 'HIGH':
        return (
          <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-amber-300 bg-amber-950/80 border border-amber-800/60 px-2 py-0.5 rounded">
            <AlertTriangle className="w-3 h-3 text-amber-400" />
            HIGH
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="inline-flex items-center gap-1 text-[11px] font-medium text-yellow-300 bg-yellow-950/60 border border-yellow-800/40 px-2 py-0.5 rounded">
            MEDIUM
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 text-[11px] font-medium text-slate-300 bg-slate-900 border border-slate-700 px-2 py-0.5 rounded">
            LOW
          </span>
        );
    }
  };

  return (
    <div className="space-y-4">
      {/* Principle Banner */}
      <div className="bg-[#0b101d] border border-slate-800 rounded-xl p-3 flex flex-wrap items-center justify-between text-xs text-slate-400">
        <div className="flex items-center gap-2">
          <Info className="w-4 h-4 text-blue-400 shrink-0" />
          <span>
            <strong className="text-slate-200">Evidence Integrity Principle:</strong> Reconstructed timeline strictly separates{' '}
            <span className="text-blue-300 font-medium">Observed Timestamps</span> from{' '}
            <span className="text-amber-300 font-medium">Rule-Based Classifications</span>.
          </span>
        </div>
        <div className="font-mono text-slate-300">
          Showing {filteredEvents.length} of {events.length} chronological events
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-[#0f172a] border border-slate-800 p-3 rounded-xl flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2 flex-1 min-w-[260px]">
          <Search className="w-4 h-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search processes, IPs, Event IDs, or commands..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-slate-200 placeholder-slate-500 outline-none focus:border-blue-500"
          />
        </div>

        <div className="flex items-center gap-3">
          {/* Anomaly Toggle */}
          <button
            onClick={() => setShowAnomaliesOnly(!showAnomaliesOnly)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium transition-colors ${
              showAnomaliesOnly
                ? 'bg-rose-950/80 border-rose-700 text-rose-300'
                : 'bg-slate-900 border-slate-700 text-slate-300 hover:text-white'
            }`}
          >
            <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
            <span>Anti-Forensics &amp; Anomalies</span>
          </button>

          {/* Severity Segmented Filter */}
          <div className="flex items-center gap-1 bg-slate-900 p-1 rounded-lg border border-slate-800">
            <Filter className="w-3.5 h-3.5 text-slate-500 ml-1.5 mr-0.5" />
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((lvl) => (
              <button
                key={lvl}
                onClick={() => setSeverityFilter(lvl)}
                className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                  severityFilter === lvl
                    ? 'bg-blue-600 text-white shadow-xs'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {lvl}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Timeline Stream */}
      <div className="space-y-3">
        {filteredEvents.length === 0 ? (
          <div className="bg-[#0b101d] border border-slate-800 rounded-xl p-12 text-center text-slate-400 text-xs">
            No events match current filter criteria.
          </div>
        ) : (
          filteredEvents.map((evt) => (
            <div
              key={evt.id}
              onClick={() => setSelectedEvent(evt)}
              className={`bg-[#0b101d] border rounded-xl p-4 transition-all cursor-pointer ${
                selectedEvent?.id === evt.id
                  ? 'border-blue-500 bg-[#0e1628]'
                  : evt.isAnomaly
                  ? 'border-rose-900/60 hover:border-rose-700/80'
                  : 'border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="flex items-center gap-3">
                  <div className="text-xs font-mono text-slate-400 flex items-center gap-1.5 bg-slate-900 px-2.5 py-1 rounded border border-slate-800">
                    <Clock className="w-3.5 h-3.5 text-blue-400" />
                    <span>{evt.timestamp.replace('T', ' ').slice(0, 19)} UTC</span>
                  </div>

                  <span className="text-xs font-semibold text-white">{evt.eventType}</span>

                  {evt.isAnomaly && (
                    <span className="text-[10px] font-semibold text-rose-400 bg-rose-950/70 border border-rose-800/50 px-2 py-0.5 rounded">
                      ANOMALY DETECTED
                    </span>
                  )}
                </div>

                <div className="flex items-center gap-2">
                  {getSeverityBadge(evt.severity)}
                  {evt.mitreId && (
                    <span className="text-[11px] font-mono text-blue-300 bg-blue-950/60 border border-blue-800/40 px-2 py-0.5 rounded">
                      {evt.mitreId}
                    </span>
                  )}
                </div>
              </div>

              {/* Summary */}
              <div className="mt-2 text-xs text-slate-200 font-medium">
                {evt.summary}
              </div>

              {/* Raw Details / Command Line */}
              <div className="mt-2 bg-[#060a12] border border-slate-800/90 rounded-lg p-2 font-mono text-[11px] text-slate-300 break-all select-all">
                {evt.rawDetails}
              </div>

              {/* Tags & Artifact Source */}
              <div className="mt-3 flex flex-wrap items-center justify-between text-[11px] text-slate-400">
                <div className="flex items-center gap-2">
                  <span className="flex items-center gap-1 text-slate-400">
                    <FileCode className="w-3.5 h-3.5 text-slate-500" />
                    Source: <span className="text-slate-300">{evt.sourceArtifact}</span>
                  </span>
                  {evt.processName && (
                    <span className="text-slate-400">
                      Process: <span className="font-mono text-blue-300">{evt.processName}</span>
                      {evt.pid ? ` (PID: ${evt.pid})` : ''}
                    </span>
                  )}
                  {evt.sourceIp && (
                    <span className="text-slate-400">
                      IP: <span className="font-mono text-amber-300">{evt.sourceIp}</span>
                    </span>
                  )}
                </div>

                <div className="flex items-center gap-2">
                  {evt.tags.map((t) => (
                    <span key={t} className="flex items-center gap-1 text-slate-400">
                      <Tag className="w-3 h-3 text-slate-500" />
                      {t}
                    </span>
                  ))}
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onSelectEventForAnalysis(evt);
                    }}
                    className="ml-2 text-blue-400 hover:text-blue-300 flex items-center gap-1 font-medium transition-colors"
                  >
                    <span>Analyze with ForensiQ</span>
                    <ExternalLink className="w-3 h-3" />
                  </button>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Selected Event Inspection Drawer */}
      {selectedEvent && (
        <div className="fixed inset-y-0 right-0 w-full max-w-lg bg-[#0d1424] border-l border-slate-700 z-50 p-6 flex flex-col justify-between shadow-2xl overflow-y-auto text-xs text-slate-200">
          <div className="space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <span className="font-mono text-[11px] text-blue-400">{selectedEvent.id}</span>
                <h3 className="text-sm font-bold text-white mt-0.5">{selectedEvent.eventType}</h3>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-slate-400 hover:text-white px-2 py-1 rounded bg-slate-800"
              >
                Close
              </button>
            </div>

            <div className="space-y-3">
              <div>
                <span className="block text-slate-400 text-[11px] uppercase font-semibold">Timestamp (UTC)</span>
                <span className="font-mono text-slate-200">{selectedEvent.timestamp}</span>
              </div>

              <div>
                <span className="block text-slate-400 text-[11px] uppercase font-semibold">Severity Rating</span>
                <div className="mt-1">{getSeverityBadge(selectedEvent.severity)}</div>
              </div>

              <div>
                <span className="block text-slate-400 text-[11px] uppercase font-semibold">MITRE ATT&amp;CK Mapping</span>
                <div className="mt-1 bg-slate-900 border border-slate-800 rounded p-2 text-[11px] space-y-1">
                  <div>Tactic: <strong className="text-blue-400">{selectedEvent.mitreTactic}</strong></div>
                  <div>Technique: <strong className="text-slate-200">{selectedEvent.mitreTechnique}</strong></div>
                  <div>ID: <strong className="font-mono text-amber-300">{selectedEvent.mitreId}</strong></div>
                </div>
              </div>

              <div>
                <span className="block text-slate-400 text-[11px] uppercase font-semibold">Raw Artifact Evidence</span>
                <div className="mt-1 bg-[#060a12] border border-slate-800 rounded-lg p-3 font-mono text-[11px] text-slate-300 break-all select-all">
                  {selectedEvent.rawDetails}
                </div>
              </div>

              {selectedEvent.isAnomaly && (
                <div className="bg-rose-950/40 border border-rose-800/60 rounded-lg p-3 text-rose-200 space-y-1">
                  <div className="flex items-center gap-1.5 font-semibold text-rose-400">
                    <Shield className="w-4 h-4" />
                    <span>Anti-Forensics / Tampering Indicator</span>
                  </div>
                  <p className="text-[11px] leading-relaxed">
                    This event represents intentional interference with evidentiary logs or system recovery safeguards.
                  </p>
                </div>
              )}
            </div>
          </div>

          <div className="pt-4 border-t border-slate-800">
            <button
              onClick={() => {
                onSelectEventForAnalysis(selectedEvent);
                setSelectedEvent(null);
              }}
              className="w-full py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-medium transition-colors"
            >
              Send Event to ForensiQ Copilot for Deep Reasoning
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
