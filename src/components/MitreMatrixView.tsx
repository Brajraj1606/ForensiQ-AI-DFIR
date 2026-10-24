import React, { useState } from 'react';
import { Shield, Target, AlertTriangle, Layers, ExternalLink, CheckCircle } from 'lucide-react';
import { MitreTacticGroup, MitreTechnique, TimelineEvent } from '../forensics/types';

interface MitreMatrixViewProps {
  tacticGroups: MitreTacticGroup[];
  allEvents: TimelineEvent[];
  onSelectEvent: (event: TimelineEvent) => void;
}

export const MitreMatrixView: React.FC<MitreMatrixViewProps> = ({
  tacticGroups,
  allEvents,
  onSelectEvent,
}) => {
  const [selectedTechnique, setSelectedTechnique] = useState<MitreTechnique | null>(null);

  const totalObservedTechniques = tacticGroups.reduce((acc, t) => acc + t.techniques.length, 0);

  return (
    <div className="space-y-6">
      {/* Overview Card */}
      <div className="bg-[#0b101e] border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Target className="w-5 h-5 text-blue-400" />
            <h2 className="text-base font-semibold text-white">MITRE ATT&amp;CK Enterprise Matrix Correlation</h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Deterministic mapping of parsed forensic artifacts against adversarial tactics and techniques.
          </p>
        </div>

        <div className="flex items-center gap-4 text-xs font-mono">
          <div className="bg-slate-900 px-3 py-1.5 rounded-lg border border-slate-800">
            <span className="text-slate-400">Observed Techniques: </span>
            <strong className="text-blue-400">{totalObservedTechniques}</strong>
          </div>
          <div className="bg-slate-900 px-3 py-1.5 rounded-lg border border-slate-800">
            <span className="text-slate-400">Active Tactics: </span>
            <strong className="text-emerald-400">
              {tacticGroups.filter((t) => t.techniques.length > 0).length} of {tacticGroups.length}
            </strong>
          </div>
        </div>
      </div>

      {/* Grid of Tactics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
        {tacticGroups.map((group) => {
          const hasDetections = group.techniques.length > 0;
          return (
            <div
              key={group.id}
              className={`rounded-xl border p-4 flex flex-col justify-between transition-colors ${
                hasDetections
                  ? 'bg-[#0c1222] border-blue-900/60 shadow-sm'
                  : 'bg-[#080c16] border-slate-800/80 opacity-75'
              }`}
            >
              <div>
                {/* Tactic Header */}
                <div className="flex items-center justify-between border-b border-slate-800/80 pb-2 mb-3">
                  <span className="text-xs font-mono font-semibold text-blue-400">{group.id}</span>
                  <span
                    className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                      hasDetections
                        ? 'bg-blue-950 text-blue-300 border border-blue-800'
                        : 'text-slate-500 bg-slate-900'
                    }`}
                  >
                    {group.techniques.length} detected
                  </span>
                </div>

                <h3 className="text-sm font-semibold text-white mb-2">{group.name}</h3>

                {/* Techniques List */}
                {group.techniques.length === 0 ? (
                  <p className="text-xs text-slate-500 italic py-4">No active evidence observed for this tactic.</p>
                ) : (
                  <div className="space-y-2 mt-2">
                    {group.techniques.map((tech) => (
                      <button
                        key={tech.id}
                        onClick={() => setSelectedTechnique(tech)}
                        className={`w-full text-left p-2.5 rounded-lg border text-xs transition-colors cursor-pointer ${
                          tech.severity === 'CRITICAL'
                            ? 'bg-rose-950/40 border-rose-800/60 hover:bg-rose-900/40'
                            : tech.severity === 'HIGH'
                            ? 'bg-amber-950/40 border-amber-800/60 hover:bg-amber-900/40'
                            : 'bg-slate-900/80 border-slate-800 hover:bg-slate-800'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-[11px] font-semibold text-slate-300">{tech.id}</span>
                          <span className="text-[10px] text-slate-400">
                            {tech.detectedEventsCount} {tech.detectedEventsCount === 1 ? 'event' : 'events'}
                          </span>
                        </div>
                        <div className="font-medium text-slate-200 mt-1 truncate">{tech.name}</div>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Selected Technique Detail Modal */}
      {selectedTechnique && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-xs">
          <div className="bg-[#0f172a] border border-slate-700 w-full max-w-2xl max-h-[85vh] rounded-xl flex flex-col shadow-2xl overflow-hidden text-slate-200">
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-[#131c31]">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-blue-500/10 border border-blue-500/30 rounded-lg text-blue-400">
                  <Shield className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs text-blue-400">{selectedTechnique.id}</span>
                    <h3 className="text-base font-semibold text-white">{selectedTechnique.name}</h3>
                  </div>
                  <span className="text-xs text-slate-400">{selectedTechnique.tactic}</span>
                </div>
              </div>
              <button
                onClick={() => setSelectedTechnique(null)}
                className="text-slate-400 hover:text-white text-xs px-2 py-1 rounded bg-slate-800"
              >
                Close
              </button>
            </div>

            <div className="p-6 overflow-y-auto space-y-4 text-xs">
              <div>
                <h4 className="text-slate-400 uppercase font-semibold text-[11px] mb-1">Observation Context</h4>
                <p className="text-slate-200 bg-slate-900 border border-slate-800 p-3 rounded-lg leading-relaxed">
                  {selectedTechnique.description}
                </p>
              </div>

              <div>
                <h4 className="text-slate-400 uppercase font-semibold text-[11px] mb-2">
                  Correlated Chronological Events ({selectedTechnique.eventIds.length})
                </h4>
                <div className="space-y-2">
                  {allEvents
                    .filter((e) => selectedTechnique.eventIds.includes(e.id))
                    .map((evt) => (
                      <div
                        key={evt.id}
                        className="p-3 bg-[#080d1a] border border-slate-800 rounded-lg space-y-1"
                      >
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="font-mono text-slate-400">{evt.timestamp}</span>
                          <span className="font-semibold text-white">{evt.sourceArtifact}</span>
                        </div>
                        <div className="text-slate-300 font-medium">{evt.summary}</div>
                        <div className="font-mono text-[11px] text-slate-400 bg-slate-950 p-1.5 rounded break-all select-all">
                          {evt.rawDetails}
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            </div>

            <div className="px-6 py-3 border-t border-slate-800 bg-[#0d1424] flex justify-end">
              <button
                onClick={() => setSelectedTechnique(null)}
                className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded-md transition-colors"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
