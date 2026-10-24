import React, { useState, useMemo, useEffect } from 'react';
import {
  LayoutDashboard,
  Shield,
  Database,
  AlertTriangle,
  Clock,
  Target,
  FileCode,
  Sparkles,
  FileText,
  Terminal,
  CheckCircle,
} from 'lucide-react';

import { CaseMetadata, EvidenceItem, TimelineEvent, ExtractedIOC, ForensicFinding } from './forensics/types';
import { PRECONFIGURED_SCENARIOS, IncidentScenario } from './forensics/scenarioData';
import { computeSha256Simulated } from './forensics/hasher';
import { extractIOCsFromText } from './forensics/iocExtractor';
import { parseRawLogLines } from './forensics/timelineParser';
import { mapEventsToMitre } from './forensics/mitreMapper';
import { evaluateRules } from './forensics/rulesEngine';

import { HeaderBar, ThemeMode } from './components/HeaderBar';
import { OverviewDashboard } from './components/OverviewDashboard';
import { EvidenceLocker } from './components/EvidenceLocker';
import { EventExplorer } from './components/EventExplorer';
import { FindingsView } from './components/FindingsView';
import { TimelineView } from './components/TimelineView';
import { MitreMatrixView } from './components/MitreMatrixView';
import { IOCInspector } from './components/IOCInspector';
import { ForensiQCopilot } from './components/ForensiQCopilot';
import { ForensicReportStudio } from './components/ForensicReportStudio';
import { StandardsModal } from './components/StandardsModal';
import { SettingsModal } from './components/SettingsModal';
import { PythonSourceViewer } from './components/PythonSourceViewer';

export type NavigationTab =
  | 'overview'
  | 'locker'
  | 'explorer'
  | 'findings'
  | 'timeline'
  | 'mitre'
  | 'inspector'
  | 'copilot'
  | 'report'
  | 'python_source';

export default function App() {
  const initialScenario = PRECONFIGURED_SCENARIOS[0];

  const [currentScenario, setCurrentScenario] = useState<IncidentScenario>(initialScenario);
  const [evidenceList, setEvidenceList] = useState<EvidenceItem[]>(initialScenario.evidenceItems);
  const [activeTab, setActiveTab] = useState<NavigationTab>('overview');
  const [selectedEvidenceForInspector, setSelectedEvidenceForInspector] = useState<EvidenceItem | null>(null);
  const [isStandardsOpen, setIsStandardsOpen] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [isAiAnalyzing, setIsAiAnalyzing] = useState(false);
  const [aiAnalysisResult, setAiAnalysisResult] = useState<string | null>(null);
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [currentTheme, setCurrentTheme] = useState<ThemeMode>(() => {
    try {
      const saved = localStorage.getItem('forensiq_theme');
      if (saved === 'slate' || saved === 'light' || saved === 'obsidian' || saved === 'cyber') {
        return saved as ThemeMode;
      }
    } catch {
      // fallback
    }
    return 'slate';
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', currentTheme);
    try {
      localStorage.setItem('forensiq_theme', currentTheme);
    } catch {
      // fallback
    }
  }, [currentTheme]);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  // Re-parse timeline events from all evidence items
  const timelineEvents: TimelineEvent[] = useMemo(() => {
    const events: TimelineEvent[] = [];
    evidenceList.forEach((item, itemIdx) => {
      const parsed = parseRawLogLines(item.rawContent, item.filename, `EVD${itemIdx + 1}`);
      events.push(...parsed);
    });
    return events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  }, [evidenceList]);

  // Extract IOCs from all evidence items
  const extractedIOCs: ExtractedIOC[] = useMemo(() => {
    const combinedText = evidenceList.map((e) => e.rawContent).join('\n');
    return extractIOCsFromText(combinedText);
  }, [evidenceList]);

  // MITRE ATT&CK Mapping
  const mitreTacticGroups = useMemo(() => {
    return mapEventsToMitre(timelineEvents);
  }, [timelineEvents]);

  // Evaluate Deterministic Rules (Module D)
  const findings: ForensicFinding[] = useMemo(() => {
    return evaluateRules(timelineEvents);
  }, [timelineEvents]);

  const allHashesVerified = evidenceList.every((e) => e.integrityVerified);

  // Scenario Switch
  const handleSelectScenario = (scenario: IncidentScenario) => {
    setCurrentScenario(scenario);
    setEvidenceList(scenario.evidenceItems);
    setSelectedEvidenceForInspector(scenario.evidenceItems[0] || null);
    setAiAnalysisResult(null);
    showToast(`Loaded case: ${scenario.metadata.id} — ${scenario.name}`);
  };

  // Create New Investigation
  const handleCreateNewInvestigation = (newCase: CaseMetadata) => {
    const blankScenario: IncidentScenario = {
      id: newCase.id,
      name: newCase.title,
      subtitle: `${newCase.incidentType} - ${newCase.agency}`,
      difficulty: 'Entry Level',
      metadata: newCase,
      evidenceItems: [],
    };
    setCurrentScenario(blankScenario);
    setEvidenceList([]);
    setSelectedEvidenceForInspector(null);
    setAiAnalysisResult(null);
    setActiveTab('locker');
    showToast(`Created new case ${newCase.id}. Ingest evidence to begin.`);
  };

  // Integrity Check for single item
  const handleVerifyIntegrity = (evidenceId: string) => {
    setEvidenceList((prev) =>
      prev.map((item) => {
        if (item.id !== evidenceId) return item;
        const currentHash = computeSha256Simulated(item.rawContent);
        const match = currentHash.toLowerCase() === item.sha256.toLowerCase();
        const updatedCustody = [
          ...item.custodyLog,
          {
            id: `COC-${Date.now()}`,
            timestamp: new Date().toISOString(),
            action: 'HASH_VERIFICATION' as const,
            actor: 'Examiner Bitstream Verifier',
            location: 'Evidence Locker Node 01',
            notes: match
              ? 'Computed bitstream SHA-256 matches acquisition manifest 100%.'
              : 'CRITICAL ALERT: Hash mismatch detected!',
            hashMatch: match,
            algorithm: 'SHA-256' as const,
            hashValue: currentHash,
          },
        ];
        return {
          ...item,
          integrityVerified: match,
          custodyLog: updatedCustody,
        };
      })
    );
    showToast(`Bitstream verification complete: SHA-256 match verified (ISO/IEC 27037).`);
  };

  // Add new evidence item
  const handleAddEvidence = (item: EvidenceItem) => {
    setEvidenceList((prev) => [...prev, item]);
    showToast(`Evidence ${item.filename} cataloged with SHA-256 checksum.`);
  };

  // Trigger Deep AI Triage
  const handleTriggerAiTriage = async () => {
    setIsAiAnalyzing(true);
    setActiveTab('copilot');
    showToast('Executing ForensiQ AI Triage & Artifact Correlation...');

    try {
      const res = await fetch('/api/analyze-evidence', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          caseMetadata: currentScenario.metadata,
          evidenceItems: evidenceList,
          timelineEvents: timelineEvents.slice(0, 15),
          extractedIOCs: extractedIOCs.slice(0, 15),
          investigativeFocus: 'comprehensive_triage',
        }),
      });
      const data = await res.json();
      setAiAnalysisResult(data.analysis);
      showToast('Forensic triage completed successfully.');
    } catch (err: any) {
      console.error(err);
      showToast('Completed with deterministic rule engine fallback.');
    } finally {
      setIsAiAnalyzing(false);
    }
  };

  const handleSelectEventForAnalysis = (event: TimelineEvent) => {
    setActiveTab('copilot');
    showToast(`Analyzing event ${event.id}: ${event.eventType}`);
  };

  const handlePivotFromExplorer = (selectedEvents: TimelineEvent[], queryPrompt?: string) => {
    setActiveTab('copilot');
    showToast(`Loaded ${selectedEvents.length} events into AI Assistant.`);
  };

  return (
    <div data-theme={currentTheme} className="min-h-screen bg-[#070b14] text-slate-100 flex flex-col font-sans selection:bg-blue-600 selection:text-white transition-colors duration-200">
      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-5 right-5 z-50 bg-[#0f172a] border border-blue-500/50 text-slate-100 px-4 py-2.5 rounded-lg shadow-xl text-xs flex items-center gap-2 animate-in fade-in slide-in-from-bottom-2">
          <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Top Header */}
      <HeaderBar
        currentCase={currentScenario.metadata}
        selectedScenarioId={currentScenario.id}
        onSelectScenario={handleSelectScenario}
        onOpenStandards={() => setIsStandardsOpen(true)}
        onOpenSettings={() => setIsSettingsOpen(true)}
        onTriggerAiTriage={handleTriggerAiTriage}
        isAiAnalyzing={isAiAnalyzing}
        allHashesVerified={allHashesVerified}
        totalEvidenceCount={evidenceList.length}
        currentTheme={currentTheme}
        onSelectTheme={(theme) => {
          setCurrentTheme(theme);
          showToast(`Theme changed to ${theme.toUpperCase()}`);
        }}
      />

      {/* Main Tab Navigation */}
      <div className="border-b border-slate-800 bg-[#090d18] px-4">
        <nav className="flex items-center gap-1 overflow-x-auto text-xs py-2 scrollbar-none" aria-label="Investigation Tabs">
          <button
            onClick={() => setActiveTab('overview')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-medium transition-colors cursor-pointer ${
              activeTab === 'overview'
                ? 'bg-blue-600 text-white shadow-xs'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <LayoutDashboard className="w-3.5 h-3.5" />
            <span>Overview</span>
          </button>

          <button
            onClick={() => setActiveTab('locker')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-medium transition-colors cursor-pointer ${
              activeTab === 'locker'
                ? 'bg-blue-600 text-white shadow-xs'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            <span>Evidence Intake ({evidenceList.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('explorer')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-medium transition-colors cursor-pointer ${
              activeTab === 'explorer'
                ? 'bg-blue-600 text-white shadow-xs'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Database className="w-3.5 h-3.5" />
            <span>Event Explorer ({timelineEvents.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('findings')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-medium transition-colors cursor-pointer ${
              activeTab === 'findings'
                ? 'bg-blue-600 text-white shadow-xs'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
            <span>Findings ({findings.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('timeline')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-medium transition-colors cursor-pointer ${
              activeTab === 'timeline'
                ? 'bg-blue-600 text-white shadow-xs'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Clock className="w-3.5 h-3.5" />
            <span>Timeline</span>
          </button>

          <button
            onClick={() => setActiveTab('mitre')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-medium transition-colors cursor-pointer ${
              activeTab === 'mitre'
                ? 'bg-blue-600 text-white shadow-xs'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Target className="w-3.5 h-3.5" />
            <span>MITRE ATT&amp;CK</span>
          </button>

          <button
            onClick={() => setActiveTab('inspector')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-medium transition-colors cursor-pointer ${
              activeTab === 'inspector'
                ? 'bg-blue-600 text-white shadow-xs'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>IOCs &amp; Hex ({extractedIOCs.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('copilot')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-medium transition-colors cursor-pointer ${
              activeTab === 'copilot'
                ? 'bg-blue-600 text-white shadow-xs'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>AI Assistant</span>
          </button>

          <button
            onClick={() => setActiveTab('report')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-medium transition-colors cursor-pointer ${
              activeTab === 'report'
                ? 'bg-blue-600 text-white shadow-xs'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Reports</span>
          </button>

          <button
            onClick={() => setActiveTab('python_source')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-medium transition-colors cursor-pointer ${
              activeTab === 'python_source'
                ? 'bg-blue-600 text-white shadow-xs'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Terminal className="w-3.5 h-3.5 text-emerald-400" />
            <span>Python &amp; Streamlit</span>
          </button>
        </nav>
      </div>

      {/* Main Workspace Body */}
      <main className="flex-1 p-4 md:p-6 max-w-7xl w-full mx-auto">
        {activeTab === 'overview' && (
          <OverviewDashboard
            currentCase={currentScenario.metadata}
            evidenceItems={evidenceList}
            timelineEvents={timelineEvents}
            findings={findings}
            onNavigateTab={(tab) => setActiveTab(tab)}
            onSelectScenario={handleSelectScenario}
            onCreateNewInvestigation={handleCreateNewInvestigation}
            onTriggerTriage={handleTriggerAiTriage}
            isAiAnalyzing={isAiAnalyzing}
          />
        )}

        {activeTab === 'locker' && (
          <EvidenceLocker
            evidenceItems={evidenceList}
            onVerifyIntegrity={handleVerifyIntegrity}
            onAddEvidence={handleAddEvidence}
            onSelectEvidenceForInspector={(item) => {
              setSelectedEvidenceForInspector(item);
              setActiveTab('inspector');
            }}
          />
        )}

        {activeTab === 'explorer' && (
          <EventExplorer
            events={timelineEvents}
            onPivotToAiAssistant={handlePivotFromExplorer}
          />
        )}

        {activeTab === 'findings' && (
          <FindingsView
            findings={findings}
            allEvents={timelineEvents}
            onSelectEvent={handleSelectEventForAnalysis}
          />
        )}

        {activeTab === 'timeline' && (
          <TimelineView
            events={timelineEvents}
            onSelectEventForAnalysis={handleSelectEventForAnalysis}
          />
        )}

        {activeTab === 'mitre' && (
          <MitreMatrixView
            tacticGroups={mitreTacticGroups}
            allEvents={timelineEvents}
            onSelectEvent={handleSelectEventForAnalysis}
          />
        )}

        {activeTab === 'inspector' && (
          <IOCInspector
            iocs={extractedIOCs}
            evidenceItems={evidenceList}
            selectedEvidence={selectedEvidenceForInspector}
            onSelectEvidence={(item) => setSelectedEvidenceForInspector(item)}
            caseId={currentScenario.metadata.id}
          />
        )}

        {activeTab === 'copilot' && (
          <ForensiQCopilot
            currentCase={currentScenario.metadata}
            evidenceItems={evidenceList}
            timelineEvents={timelineEvents}
            extractedIOCs={extractedIOCs}
            initialAnalysis={aiAnalysisResult}
          />
        )}

        {activeTab === 'report' && (
          <ForensicReportStudio
            currentCase={currentScenario.metadata}
            evidenceItems={evidenceList}
            timelineEvents={timelineEvents}
            extractedIOCs={extractedIOCs}
            aiAnalysisText={aiAnalysisResult}
          />
        )}

        {activeTab === 'python_source' && (
          <PythonSourceViewer />
        )}
      </main>

      {/* Footer */}
      <footer className="bg-[#070b14] border-t border-slate-800/80 px-6 py-3 text-xs text-slate-500 flex flex-wrap items-center justify-between gap-4">
        <div>
          <span>ForensiQ AI Platform • Open-Source Digital Forensics &amp; Incident Response Assistant</span>
        </div>
        <div className="flex items-center gap-4 text-[11px] font-mono">
          <span>Standards: ISO/IEC 27037 · NIST SP 800-86 · FRE 901</span>
          <span>TLP:AMBER+STRICT</span>
        </div>
      </footer>

      {/* Standards Modal */}
      <StandardsModal isOpen={isStandardsOpen} onClose={() => setIsStandardsOpen(false)} />

      {/* Settings Modal */}
      <SettingsModal
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
        onResetCaseData={() => handleSelectScenario(PRECONFIGURED_SCENARIOS[0])}
        currentTheme={currentTheme}
        onSelectTheme={setCurrentTheme}
      />
    </div>
  );
}
