import {
  ShieldCheck,
  ShieldAlert,
  BookOpen,
  Sparkles,
  FolderArchive,
  UserCheck,
  AlertTriangle,
  Settings,
  Sun,
  Moon,
  Palette,
} from 'lucide-react';
import { CaseMetadata } from '../forensics/types';
import { PRECONFIGURED_SCENARIOS, IncidentScenario } from '../forensics/scenarioData';

export type ThemeMode = 'slate' | 'light' | 'obsidian' | 'cyber';

interface HeaderBarProps {
  currentCase: CaseMetadata;
  selectedScenarioId: string;
  onSelectScenario: (scenario: IncidentScenario) => void;
  onOpenStandards: () => void;
  onOpenSettings: () => void;
  onTriggerAiTriage: () => void;
  isAiAnalyzing: boolean;
  allHashesVerified: boolean;
  totalEvidenceCount: number;
  currentTheme: ThemeMode;
  onSelectTheme: (theme: ThemeMode) => void;
}

export const HeaderBar: React.FC<HeaderBarProps> = ({
  currentCase,
  selectedScenarioId,
  onSelectScenario,
  onOpenStandards,
  onOpenSettings,
  onTriggerAiTriage,
  isAiAnalyzing,
  allHashesVerified,
  totalEvidenceCount,
  currentTheme,
  onSelectTheme,
}) => {
  return (
    <header className="bg-[#0b1120] border-b border-slate-800 text-slate-200 sticky top-0 z-40">
      {/* Top Banner: Classification and Quick Stats */}
      <div className="bg-[#070b14] border-b border-slate-800/80 px-4 py-1.5 flex flex-wrap items-center justify-between text-xs">
        <div className="flex items-center gap-3">
          <span className="font-mono text-amber-400 font-semibold flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5" />
            {currentCase.classification}
          </span>
          <span className="text-slate-500">|</span>
          <span className="text-slate-400">
            Case: <strong className="text-slate-200 font-mono">{currentCase.id}</strong>
          </span>
          <span className="text-slate-500">·</span>
          <span className="text-slate-400">{currentCase.incidentType}</span>
        </div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5 text-slate-300">
            <UserCheck className="w-3.5 h-3.5 text-blue-400" />
            <span>{currentCase.examinerName}</span>
            <span className="text-slate-500">({currentCase.agency})</span>
          </div>

          <div className="flex items-center gap-1.5">
            {allHashesVerified ? (
              <span className="flex items-center gap-1 text-emerald-400 font-medium">
                <ShieldCheck className="w-3.5 h-3.5" />
                Evidence Sealed (SHA-256 Verified)
              </span>
            ) : (
              <span className="flex items-center gap-1 text-rose-400 font-medium">
                <ShieldAlert className="w-3.5 h-3.5" />
                Integrity Pending
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Main Bar */}
      <div className="px-4 py-3 flex flex-wrap items-center justify-between gap-4">
        {/* Brand & Title */}
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400 shadow-inner">
            <ShieldCheck className="w-5 h-5 text-blue-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold text-white tracking-tight">ForensiQ AI</h1>
              <span className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-blue-950/70 text-blue-300 border border-blue-800/50">
                DFIR Platform
              </span>
            </div>
            <p className="text-xs text-slate-400 max-w-md truncate">
              {currentCase.title}
            </p>
          </div>
        </div>

        {/* Scenario Switcher & Actions */}
        <div className="flex items-center gap-3">
          {/* Scenario Selector */}
          <div className="flex items-center gap-2 bg-slate-900/90 border border-slate-700/80 rounded-lg px-2.5 py-1.5 text-xs">
            <FolderArchive className="w-4 h-4 text-slate-400" />
            <label htmlFor="scenario-select" className="text-slate-400 sr-only">
              Select Forensic Case Scenario
            </label>
            <select
              id="scenario-select"
              aria-label="Select Forensic Case Scenario"
              value={selectedScenarioId}
              onChange={(e) => {
                const found = PRECONFIGURED_SCENARIOS.find((s) => s.id === e.target.value);
                if (found) onSelectScenario(found);
              }}
              className="bg-transparent text-slate-200 border-none outline-none focus:ring-0 cursor-pointer pr-2 font-medium"
            >
              {PRECONFIGURED_SCENARIOS.map((sc) => (
                <option key={sc.id} value={sc.id} className="bg-slate-900 text-slate-200">
                  {sc.name} ({sc.difficulty})
                </option>
              ))}
            </select>
          </div>

          {/* Theme Switcher */}
          <div className="flex items-center bg-slate-900/90 border border-slate-700/80 rounded-lg p-0.5 text-xs shadow-inner">
            <button
              onClick={() => onSelectTheme('slate')}
              className={`flex items-center gap-1 px-2 py-1 rounded text-[11px] font-medium transition-all cursor-pointer ${
                currentTheme === 'slate'
                  ? 'bg-blue-600 text-white shadow-xs'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
              title="Tactical Slate (DFIR Dark)"
              aria-label="Switch to Tactical Slate Theme"
            >
              <Moon className="w-3 h-3" />
              <span className="hidden sm:inline">Slate</span>
            </button>
            <button
              onClick={() => onSelectTheme('light')}
              className={`flex items-center gap-1 px-2 py-1 rounded text-[11px] font-medium transition-all cursor-pointer ${
                currentTheme === 'light'
                  ? 'bg-blue-600 text-white shadow-xs'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
              title="Courtroom / Lab Light"
              aria-label="Switch to Courtroom Light Theme"
            >
              <Sun className="w-3 h-3" />
              <span className="hidden sm:inline">Light</span>
            </button>
            <button
              onClick={() => onSelectTheme('obsidian')}
              className={`flex items-center gap-1 px-2 py-1 rounded text-[11px] font-medium transition-all cursor-pointer ${
                currentTheme === 'obsidian'
                  ? 'bg-zinc-800 text-white shadow-xs border border-zinc-600'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
              title="Obsidian OLED Black"
              aria-label="Switch to Obsidian Black Theme"
            >
              <span className="w-2.5 h-2.5 rounded-full bg-black border border-slate-400"></span>
              <span className="hidden md:inline">Obsidian</span>
            </button>
            <button
              onClick={() => onSelectTheme('cyber')}
              className={`flex items-center gap-1 px-2 py-1 rounded text-[11px] font-medium transition-all cursor-pointer ${
                currentTheme === 'cyber'
                  ? 'bg-indigo-600 text-white shadow-xs'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
              title="Cyber Indigo Theme"
              aria-label="Switch to Cyber Indigo Theme"
            >
              <Palette className="w-3 h-3 text-indigo-300" />
              <span className="hidden md:inline">Cyber</span>
            </button>
          </div>

          {/* Academic & Methodology Standards Button */}
          <button
            onClick={onOpenStandards}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800/70 hover:bg-slate-700 hover:text-white text-xs font-medium text-slate-300 transition-colors cursor-pointer"
            title="View ISO/IEC 27037 and NIST SP 800-86 Methodologies"
          >
            <BookOpen className="w-3.5 h-3.5 text-blue-400" />
            <span className="hidden sm:inline">Forensic Standards</span>
          </button>

          {/* Settings & Model Status Button */}
          <button
            onClick={onOpenSettings}
            className="p-1.5 rounded-lg border border-slate-700 bg-slate-800/70 hover:bg-slate-700 hover:text-white text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
            title="Settings & Model Status (Module F & I)"
            aria-label="Settings and Model Status"
          >
            <Settings className="w-4 h-4" />
          </button>

          {/* AI Triage Trigger */}
          <button
            onClick={onTriggerAiTriage}
            disabled={isAiAnalyzing || totalEvidenceCount === 0}
            className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold shadow-sm transition-all ${
              isAiAnalyzing
                ? 'bg-blue-800 text-blue-200 cursor-not-allowed opacity-75'
                : 'bg-blue-600 hover:bg-blue-500 text-white shadow-blue-900/40 active:scale-95'
            }`}
          >
            <Sparkles className={`w-3.5 h-3.5 ${isAiAnalyzing ? 'animate-spin' : ''}`} />
            <span>{isAiAnalyzing ? 'Analyzing Artifacts...' : 'Run ForensiQ Triage'}</span>
          </button>
        </div>
      </div>
    </header>
  );
};
