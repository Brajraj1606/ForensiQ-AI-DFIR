import React, { useState } from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  FileText,
  Clock,
  Sparkles,
  FolderPlus,
  Activity,
  CheckCircle2,
  Lock,
  Layers,
  ArrowRight,
} from 'lucide-react';
import { CaseMetadata, EvidenceItem, TimelineEvent, ForensicFinding } from '../forensics/types';
import { PRECONFIGURED_SCENARIOS, IncidentScenario } from '../forensics/scenarioData';

interface OverviewDashboardProps {
  currentCase: CaseMetadata;
  evidenceItems: EvidenceItem[];
  timelineEvents: TimelineEvent[];
  findings: ForensicFinding[];
  onNavigateTab: (tab: any) => void;
  onSelectScenario: (scenario: IncidentScenario) => void;
  onCreateNewInvestigation: (newCase: CaseMetadata) => void;
  onTriggerTriage: () => void;
  isAiAnalyzing: boolean;
}

export const OverviewDashboard: React.FC<OverviewDashboardProps> = ({
  currentCase,
  evidenceItems,
  timelineEvents,
  findings,
  onNavigateTab,
  onSelectScenario,
  onCreateNewInvestigation,
  onTriggerTriage,
  isAiAnalyzing,
}) => {
  const [isNewCaseModalOpen, setIsNewCaseModalOpen] = useState(false);
  const [newCaseId, setNewCaseId] = useState(`CAS-${new Date().getFullYear()}-${Math.floor(1000 + Math.random() * 9000)}`);
  const [newTitle, setNewTitle] = useState('');
  const [newType, setNewType] = useState<CaseMetadata['incidentType']>('Ransomware');
  const [newExaminer, setNewExaminer] = useState(currentCase.examinerName);
  const [newAgency, setNewAgency] = useState(currentCase.agency);
  const [newSummary, setNewSummary] = useState('');

  const flaggedEventsCount = timelineEvents.filter((e) => e.severity === 'CRITICAL' || e.isAnomaly).length;
  const criticalFindingsCount = findings.filter((f) => f.severity === 'CRITICAL').length;
  const allHashesVerified = evidenceItems.every((e) => e.integrityVerified);

  const handleCreateCaseSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;

    const newCase: CaseMetadata = {
      id: newCaseId,
      title: newTitle,
      incidentType: newType,
      examinerName: newExaminer,
      examinerTitle: 'Forensics Specialist',
      agency: newAgency,
      dateCreated: new Date().toISOString(),
      status: 'ACTIVE_INVESTIGATION',
      classification: 'TLP:AMBER+STRICT',
      caseSummary: newSummary || `New investigation initiated for ${newTitle}.`,
    };

    onCreateNewInvestigation(newCase);
    setIsNewCaseModalOpen(false);
  };

  return (
    <div className="space-y-6">
      {/* Top Banner / Case Summary Card */}
      <div className="bg-[#0b101e] border border-slate-800 rounded-xl p-5 flex flex-wrap items-start justify-between gap-4">
        <div className="space-y-1.5 max-w-2xl">
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs font-semibold text-blue-400">{currentCase.id}</span>
            <span className="text-slate-500">·</span>
            <span className="text-xs text-amber-400 font-semibold">{currentCase.classification}</span>
            <span className="text-slate-500">·</span>
            <span className="text-xs text-emerald-400 font-medium">Status: {currentCase.status}</span>
          </div>

          <h2 className="text-lg font-bold text-white tracking-tight">{currentCase.title}</h2>
          <p className="text-xs text-slate-300 leading-relaxed">{currentCase.caseSummary}</p>

          <div className="flex flex-wrap items-center gap-4 text-xs text-slate-400 pt-2">
            <span>Investigating Agency: <strong className="text-slate-200">{currentCase.agency}</strong></span>
            <span>Lead Examiner: <strong className="text-slate-200">{currentCase.examinerName}</strong></span>
            {currentCase.leadSuspectOrThreatActor && (
              <span>Threat Pattern: <strong className="text-rose-300 font-mono">{currentCase.leadSuspectOrThreatActor}</strong></span>
            )}
          </div>
        </div>

        {/* Quick Actions */}
        <div className="flex flex-col gap-2 shrink-0">
          <button
            onClick={() => setIsNewCaseModalOpen(true)}
            className="flex items-center gap-1.5 px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-medium transition-colors cursor-pointer"
          >
            <FolderPlus className="w-4 h-4 text-blue-400" />
            <span>New Investigation</span>
          </button>

          <button
            onClick={onTriggerTriage}
            disabled={isAiAnalyzing || evidenceItems.length === 0}
            className="flex items-center gap-1.5 px-3.5 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold shadow-sm transition-all cursor-pointer"
          >
            <Sparkles className={`w-4 h-4 ${isAiAnalyzing ? 'animate-spin' : ''}`} />
            <span>{isAiAnalyzing ? 'Triaging...' : 'Run ForensiQ Triage'}</span>
          </button>
        </div>
      </div>

      {/* Forensic Metrics Grid (Restrained, Real Data - No Fabricated Scores) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1 */}
        <div
          onClick={() => onNavigateTab('locker')}
          className="bg-[#0b101d] border border-slate-800 hover:border-slate-700 p-4 rounded-xl flex items-center justify-between cursor-pointer transition-colors"
        >
          <div>
            <span className="text-xs text-slate-400 font-medium">Cataloged Evidence</span>
            <div className="text-2xl font-bold text-white mt-1 font-mono">{evidenceItems.length}</div>
            <span className="text-[11px] text-emerald-400 flex items-center gap-1 mt-0.5">
              <CheckCircle2 className="w-3 h-3" />
              {allHashesVerified ? '100% SHA-256 Bitstream Verified' : 'Integrity Pending'}
            </span>
          </div>
          <div className="p-3 bg-blue-950/60 border border-blue-800/40 rounded-lg text-blue-400">
            <ShieldCheck className="w-6 h-6" />
          </div>
        </div>

        {/* Metric 2 */}
        <div
          onClick={() => onNavigateTab('timeline')}
          className="bg-[#0b101d] border border-slate-800 hover:border-slate-700 p-4 rounded-xl flex items-center justify-between cursor-pointer transition-colors"
        >
          <div>
            <span className="text-xs text-slate-400 font-medium">Imported Events</span>
            <div className="text-2xl font-bold text-white mt-1 font-mono">{timelineEvents.length}</div>
            <span className="text-[11px] text-slate-400 mt-0.5 block">Chronologically Normalized</span>
          </div>
          <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg text-slate-400">
            <Clock className="w-6 h-6" />
          </div>
        </div>

        {/* Metric 3 */}
        <div
          onClick={() => onNavigateTab('findings')}
          className="bg-[#0b101d] border border-slate-800 hover:border-slate-700 p-4 rounded-xl flex items-center justify-between cursor-pointer transition-colors"
        >
          <div>
            <span className="text-xs text-slate-400 font-medium">Deterministic Findings</span>
            <div className="text-2xl font-bold text-rose-400 mt-1 font-mono">{findings.length}</div>
            <span className="text-[11px] text-rose-400/90 flex items-center gap-1 mt-0.5">
              <AlertTriangle className="w-3 h-3" />
              {criticalFindingsCount} Critical Invariants
            </span>
          </div>
          <div className="p-3 bg-rose-950/60 border border-rose-800/40 rounded-lg text-rose-400">
            <AlertTriangle className="w-6 h-6" />
          </div>
        </div>

        {/* Metric 4 */}
        <div
          onClick={() => onNavigateTab('timeline')}
          className="bg-[#0b101d] border border-slate-800 hover:border-slate-700 p-4 rounded-xl flex items-center justify-between cursor-pointer transition-colors"
        >
          <div>
            <span className="text-xs text-slate-400 font-medium">Flagged Anomalies</span>
            <div className="text-2xl font-bold text-amber-400 mt-1 font-mono">{flaggedEventsCount}</div>
            <span className="text-[11px] text-amber-400/90 mt-0.5 block">Anti-Forensics / Recovery Tamper</span>
          </div>
          <div className="p-3 bg-amber-950/60 border border-amber-800/40 rounded-lg text-amber-400">
            <Activity className="w-6 h-6" />
          </div>
        </div>
      </div>

      {/* Two Column Layout: Recent Analysis Activity & Quick Scenario Switcher */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Recent Forensic Activity Log */}
        <div className="lg:col-span-2 bg-[#0b101d] border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-blue-400" />
              <h3 className="text-xs font-semibold text-white uppercase tracking-wider">
                Recent Investigation Activity &amp; Findings
              </h3>
            </div>
            <button
              onClick={() => onNavigateTab('findings')}
              className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 font-medium transition-colors"
            >
              <span>View All ({findings.length})</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-3">
            {findings.length === 0 ? (
              <p className="text-xs text-slate-500 py-6 text-center">
                No active rule violations detected in loaded evidence.
              </p>
            ) : (
              findings.slice(0, 4).map((f) => (
                <div
                  key={f.findingId}
                  onClick={() => onNavigateTab('findings')}
                  className="p-3 bg-[#080d1a] border border-slate-800 hover:border-slate-700 rounded-lg space-y-1.5 transition-colors cursor-pointer"
                >
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-white">{f.ruleName}</span>
                    <span className="text-[10px] font-mono font-semibold text-rose-300 bg-rose-950 border border-rose-800 px-2 py-0.5 rounded">
                      {f.severity}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300">{f.detectionReason}</p>
                  <div className="flex items-center justify-between text-[11px] text-slate-500 pt-1 font-mono">
                    <span>Events: {f.eventIds.join(', ')}</span>
                    <span>Rule: {f.ruleVersion}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right: Demo Forensic Scenarios */}
        <div className="bg-[#0b101d] border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="border-b border-slate-800/80 pb-3">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-purple-400" />
              <h3 className="text-xs font-semibold text-white uppercase tracking-wider">
                Demo Forensic Scenarios
              </h3>
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              Select verified synthetic incident packages for instant live demonstration.
            </p>
          </div>

          <div className="space-y-2.5">
            {PRECONFIGURED_SCENARIOS.map((sc) => (
              <button
                key={sc.id}
                onClick={() => onSelectScenario(sc)}
                className={`w-full text-left p-3 rounded-lg border text-xs transition-colors cursor-pointer ${
                  sc.id === currentCase.id || sc.metadata.id === currentCase.id
                    ? 'bg-blue-600/15 border-blue-500/50 text-white'
                    : 'bg-slate-900/60 border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-xs text-white">{sc.name.split(':')[0]}</span>
                  <span className="text-[10px] font-mono text-slate-400">{sc.difficulty}</span>
                </div>
                <p className="text-[11px] text-slate-400 mt-1 line-clamp-2">{sc.subtitle}</p>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* New Investigation Modal */}
      {isNewCaseModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-xs">
          <div className="bg-[#0f172a] border border-slate-700 w-full max-w-lg rounded-xl flex flex-col shadow-2xl overflow-hidden text-slate-200">
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-[#131c31]">
              <div className="flex items-center gap-2">
                <FolderPlus className="w-5 h-5 text-blue-400" />
                <h3 className="text-sm font-semibold text-white">Create New Forensic Investigation</h3>
              </div>
              <button
                onClick={() => setIsNewCaseModalOpen(false)}
                className="text-slate-400 hover:text-white text-xs px-2 py-1 rounded hover:bg-slate-800"
              >
                Cancel
              </button>
            </div>

            <form onSubmit={handleCreateCaseSubmit} className="p-6 space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">Case ID (Unique Identifier)</label>
                <input
                  type="text"
                  required
                  value={newCaseId}
                  onChange={(e) => setNewCaseId(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 font-mono outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Investigation Title</label>
                <input
                  type="text"
                  required
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="e.g. Investigation of Unauthorized Domain Admin Activity"
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 outline-none focus:border-blue-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Incident Type</label>
                  <select
                    value={newType}
                    onChange={(e) => setNewType(e.target.value as any)}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 outline-none focus:border-blue-500"
                  >
                    <option value="Ransomware">Ransomware</option>
                    <option value="Memory Injection">Memory Injection</option>
                    <option value="Data Exfiltration">Data Exfiltration</option>
                    <option value="Web Shell Compromise">Web Shell Compromise</option>
                    <option value="Insider Threat">Insider Threat</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">Lead Examiner</label>
                  <input
                    type="text"
                    value={newExaminer}
                    onChange={(e) => setNewExaminer(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Case Scope &amp; Summary</label>
                <textarea
                  rows={3}
                  value={newSummary}
                  onChange={(e) => setNewSummary(e.target.value)}
                  placeholder="Describe initial breach notification, involved assets, and investigative objectives..."
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-3 text-slate-200 outline-none focus:border-blue-500"
                />
              </div>

              <div className="flex justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsNewCaseModalOpen(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium cursor-pointer"
                >
                  Create Case
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
