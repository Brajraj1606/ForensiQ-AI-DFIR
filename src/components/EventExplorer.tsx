import React, { useState, useMemo } from 'react';
import { Search, Filter, Database, Send, ExternalLink, AlertCircle, CheckCircle, Tag } from 'lucide-react';
import { TimelineEvent } from '../forensics/types';

interface EventExplorerProps {
  events: TimelineEvent[];
  onPivotToAiAssistant: (selectedEvents: TimelineEvent[], queryPrompt?: string) => void;
}

export const EventExplorer: React.FC<EventExplorerProps> = ({ events, onPivotToAiAssistant }) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [hostFilter, setHostFilter] = useState('ALL');
  const [accountFilter, setAccountFilter] = useState('ALL');
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  // Extract unique hosts and accounts
  const uniqueHosts = useMemo(() => {
    const s = new Set<string>();
    events.forEach((e) => {
      const match = e.rawDetails.match(/(?:WorkstationName|Workstation|Host|ComputerName)[:=\s]+([a-zA-Z0-9_\-\.]+)/i);
      if (match) s.add(match[1]);
    });
    return Array.from(s);
  }, [events]);

  const uniqueAccounts = useMemo(() => {
    const s = new Set<string>();
    events.forEach((e) => {
      if (e.user) s.add(e.user);
    });
    return Array.from(s);
  }, [events]);

  const filteredEvents = useMemo(() => {
    return events.filter((evt) => {
      if (hostFilter !== 'ALL' && !evt.rawDetails.includes(hostFilter)) return false;
      if (accountFilter !== 'ALL' && evt.user !== accountFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const match =
          evt.id.toLowerCase().includes(q) ||
          evt.summary.toLowerCase().includes(q) ||
          evt.rawDetails.toLowerCase().includes(q) ||
          evt.eventType.toLowerCase().includes(q) ||
          (evt.processName && evt.processName.toLowerCase().includes(q)) ||
          (evt.sourceIp && evt.sourceIp.includes(q)) ||
          (evt.user && evt.user.toLowerCase().includes(q));
        if (!match) return false;
      }
      return true;
    });
  }, [events, hostFilter, accountFilter, searchQuery]);

  const handleToggleSelect = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleSendSelectedToAi = () => {
    const selected = events.filter((e) => selectedIds.has(e.id));
    if (selected.length > 0) {
      onPivotToAiAssistant(selected, `Analyze the relationship between selected events: ${selected.map((s) => s.id).join(', ')}.`);
    }
  };

  return (
    <div className="space-y-4">
      {/* Top Banner */}
      <div className="bg-[#0b101e] border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4 text-xs">
        <div>
          <div className="flex items-center gap-2">
            <Database className="w-5 h-5 text-blue-400" />
            <h2 className="text-base font-semibold text-white">Event Explorer &amp; Evidence-Aware Retrieval (Module C &amp; G)</h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Normalized forensic records preserving original representation, timezone metadata, and source line numbers.
          </p>
        </div>

        {selectedIds.size > 0 && (
          <div className="flex items-center gap-3">
            <span className="text-blue-300 font-mono">{selectedIds.size} records selected</span>
            <button
              onClick={handleSendSelectedToAi}
              className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-medium flex items-center gap-1.5 transition-colors shadow-sm cursor-pointer"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Query AI with Bounded Context</span>
            </button>
          </div>
        )}
      </div>

      {/* Filter and Search Controls */}
      <div className="bg-[#0f172a] border border-slate-800 p-3 rounded-xl flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2 flex-1 min-w-[260px]">
          <Search className="w-4 h-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search normalized events, processes, IPs, accounts, or messages..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-slate-200 outline-none focus:border-blue-500"
          />
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          {uniqueHosts.length > 0 && (
            <div className="flex items-center gap-1.5">
              <span className="text-slate-400">Host:</span>
              <select
                value={hostFilter}
                onChange={(e) => setHostFilter(e.target.value)}
                className="bg-slate-900 border border-slate-700 rounded px-2.5 py-1 text-slate-200 text-xs outline-none"
              >
                <option value="ALL">All Hosts</option>
                {uniqueHosts.map((h) => (
                  <option key={h} value={h}>{h}</option>
                ))}
              </select>
            </div>
          )}

          {uniqueAccounts.length > 0 && (
            <div className="flex items-center gap-1.5">
              <span className="text-slate-400">Account:</span>
              <select
                value={accountFilter}
                onChange={(e) => setAccountFilter(e.target.value)}
                className="bg-slate-900 border border-slate-700 rounded px-2.5 py-1 text-slate-200 text-xs outline-none"
              >
                <option value="ALL">All Accounts</option>
                {uniqueAccounts.map((a) => (
                  <option key={a} value={a}>{a}</option>
                ))}
              </select>
            </div>
          )}

          <span className="font-mono text-slate-400">
            {filteredEvents.length} of {events.length} records
          </span>
        </div>
      </div>

      {/* Event Records Table */}
      <div className="bg-[#0b101e] border border-slate-800 rounded-xl overflow-hidden text-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead className="bg-[#0f172a] text-slate-400 font-mono text-[10px] uppercase border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3 w-8">
                  <span className="sr-only">Select</span>
                </th>
                <th className="py-2.5 px-3">Event ID</th>
                <th className="py-2.5 px-3">Normalized Timestamp (UTC)</th>
                <th className="py-2.5 px-3">Event Type</th>
                <th className="py-2.5 px-3">User / Account</th>
                <th className="py-2.5 px-3">Source &amp; Dest IP</th>
                <th className="py-2.5 px-3">Raw Message Details</th>
                <th className="py-2.5 px-3">Artifact Source</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 text-slate-300">
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500">
                    No records match the current search query.
                  </td>
                </tr>
              ) : (
                filteredEvents.map((evt) => (
                  <tr
                    key={evt.id}
                    className={`hover:bg-slate-900/50 transition-colors ${
                      selectedIds.has(evt.id) ? 'bg-blue-950/30' : ''
                    }`}
                  >
                    <td className="py-2.5 px-3">
                      <input
                        type="checkbox"
                        checked={selectedIds.has(evt.id)}
                        onChange={() => handleToggleSelect(evt.id)}
                        aria-label={`Select event ${evt.id}`}
                        className="rounded border-slate-700 bg-slate-900 text-blue-600 focus:ring-0 cursor-pointer"
                      />
                    </td>
                    <td className="py-2.5 px-3 font-mono font-semibold text-blue-400 whitespace-nowrap">
                      {evt.id}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">
                      {evt.timestamp.replace('T', ' ').slice(0, 19)}
                    </td>
                    <td className="py-2.5 px-3 font-medium text-slate-200 whitespace-nowrap">
                      {evt.eventType}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-300">
                      {evt.user || '—'}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-400 whitespace-nowrap">
                      {evt.sourceIp || '—'}
                      {evt.destIp ? ` → ${evt.destIp}` : ''}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[11px] text-slate-300 max-w-md truncate select-all">
                      {evt.rawDetails}
                    </td>
                    <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                      {evt.sourceArtifact}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
