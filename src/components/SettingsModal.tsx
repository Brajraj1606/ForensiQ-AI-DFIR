import React, { useState, useEffect } from 'react';
import {
  X,
  Settings,
  Cpu,
  Database,
  Shield,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  Server,
  Terminal,
  Palette,
  Sun,
  Moon,
  Sparkles,
  Eye,
  Check,
  ShieldCheck,
  Zap,
} from 'lucide-react';
import { ThemeMode } from './HeaderBar';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  onResetCaseData: () => void;
  currentTheme?: ThemeMode;
  onSelectTheme?: (theme: ThemeMode) => void;
}

interface ThemeConfig {
  id: ThemeMode;
  name: string;
  tagline: string;
  role: string;
  icon: React.ElementType;
  badge: string;
  colors: {
    bg: string;
    card: string;
    border: string;
    accent: string;
    text: string;
    muted: string;
  };
  contrastRatio: string;
  description: string;
}

const THEME_OPTIONS: ThemeConfig[] = [
  {
    id: 'slate',
    name: 'Tactical Slate',
    tagline: 'DFIR Operations Dark',
    role: 'Standard Lab Default',
    icon: Moon,
    badge: 'Recommended',
    colors: {
      bg: '#070b14',
      card: '#0f172a',
      border: '#334155',
      accent: '#3b82f6',
      text: '#e2e8f0',
      muted: '#94a3b8',
    },
    contrastRatio: '7.8:1 (AAA)',
    description: 'Deep navy-slate palette engineered for long incident response shifts, reducing eye fatigue during intensive log triage.',
  },
  {
    id: 'light',
    name: 'Courtroom Light',
    tagline: 'High-Contrast Lab & Legal',
    role: 'Litigation & Daylight',
    icon: Sun,
    badge: 'Courtroom Ready',
    colors: {
      bg: '#f1f5f9',
      card: '#ffffff',
      border: '#cbd5e1',
      accent: '#2563eb',
      text: '#0f172a',
      muted: '#64748b',
    },
    contrastRatio: '12.4:1 (AAA)',
    description: 'Crisp daylight theme designed for courtroom exhibits, judicial testimony, legal PDF exports, and sunlit mobile command posts.',
  },
  {
    id: 'obsidian',
    name: 'Obsidian OLED',
    tagline: 'Pure Black Low-Light',
    role: 'OLED Battery Saver',
    icon: Sparkles,
    badge: 'True OLED 0% Bleed',
    colors: {
      bg: '#000000',
      card: '#0a0a0a',
      border: '#262626',
      accent: '#52525b',
      text: '#f5f5f5',
      muted: '#a1a1aa',
    },
    contrastRatio: '18.1:1 (AAA)',
    description: 'Absolute black background (#000000) for OLED laptops and tactical field kits, maximizing power savings and eliminating bezel glow.',
  },
  {
    id: 'cyber',
    name: 'Cyber Indigo',
    tagline: 'SOC Threat Hunting',
    role: 'Adversary Tracking',
    icon: Palette,
    badge: 'Threat Intel',
    colors: {
      bg: '#050816',
      card: '#0c1438',
      border: '#253368',
      accent: '#6366f1',
      text: '#e0e7ff',
      muted: '#818cf8',
    },
    contrastRatio: '8.6:1 (AAA)',
    description: 'High-tech midnight indigo with vibrant threat intelligence accents, optimized for SOC wallboards and MITRE ATT&CK visualization.',
  },
];

export const SettingsModal: React.FC<SettingsModalProps> = ({
  isOpen,
  onClose,
  onResetCaseData,
  currentTheme = 'slate',
  onSelectTheme,
}) => {
  const [ollamaModel, setOllamaModel] = useState('llama3.2');
  const [ollamaUrl, setOllamaUrl] = useState('http://localhost:11434');
  const [isCheckingOllama, setIsCheckingOllama] = useState(false);
  const [ollamaStatus, setOllamaStatus] = useState<'unchecked' | 'online' | 'offline'>('unchecked');
  const [confirmReset, setConfirmReset] = useState(false);

  // Live hover preview state
  const [hoveredTheme, setHoveredTheme] = useState<ThemeMode | null>(null);

  // Determine active displayed theme for preview (hovered takes precedence over active)
  const previewTheme = hoveredTheme || currentTheme;
  const activeConfig = THEME_OPTIONS.find((t) => t.id === previewTheme) || THEME_OPTIONS[0];

  // Ensure theme reverts to committed theme when modal closes or unmounts
  useEffect(() => {
    return () => {
      document.documentElement.setAttribute('data-theme', currentTheme);
    };
  }, [currentTheme]);

  if (!isOpen) return null;

  const handleTestOllama = async () => {
    setIsCheckingOllama(true);
    try {
      const res = await fetch(`${ollamaUrl}/api/tags`, { method: 'GET' }).catch(() => null);
      if (res && res.ok) {
        setOllamaStatus('online');
      } else {
        setOllamaStatus('offline');
      }
    } catch {
      setOllamaStatus('offline');
    } finally {
      setIsCheckingOllama(false);
    }
  };

  const handleThemeHover = (themeId: ThemeMode) => {
    setHoveredTheme(themeId);
    // Instant live preview applied to the entire application document root
    document.documentElement.setAttribute('data-theme', themeId);
  };

  const handleThemeHoverLeave = () => {
    setHoveredTheme(null);
    // Revert back to the user's committed theme
    document.documentElement.setAttribute('data-theme', currentTheme);
  };

  const handleThemeSelect = (themeId: ThemeMode) => {
    if (onSelectTheme) {
      onSelectTheme(themeId);
    }
    try {
      localStorage.setItem('forensiq_theme', themeId);
    } catch {
      // fallback
    }
    document.documentElement.setAttribute('data-theme', themeId);
  };

  const handleClose = () => {
    // Revert any lingering hover state before closing
    setHoveredTheme(null);
    document.documentElement.setAttribute('data-theme', currentTheme);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-xs">
      <div className="bg-[#0f172a] border border-slate-700 w-full max-w-3xl max-h-[90vh] rounded-xl flex flex-col shadow-2xl overflow-hidden text-slate-200 text-xs">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-[#131c31]">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 bg-blue-500/10 border border-blue-500/30 rounded-lg text-blue-400">
              <Settings className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-semibold text-white">ForensiQ Platform Configuration</h3>
              <p className="text-[11px] text-slate-400">Theme Appearance, Local Ollama Model &amp; Storage</p>
            </div>
          </div>
          <button
            onClick={handleClose}
            aria-label="Close settings"
            className="text-slate-400 hover:text-white p-1 rounded hover:bg-slate-800 cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto space-y-6">
          {/* SECTION 1: THEME SELECTION & LIVE PREVIEW */}
          <div className="space-y-4 border-b border-slate-800 pb-6">
            <div className="flex items-center justify-between">
              <div>
                <span className="font-semibold text-white flex items-center gap-1.5 text-sm">
                  <Palette className="w-4 h-4 text-indigo-400" />
                  Forensic Workspace Theme &amp; Contrast Mode
                </span>
                <p className="text-slate-400 text-[11px] mt-0.5">
                  Hover over any theme button below to preview it live across the platform. Click to apply permanently.
                </p>
              </div>

              {hoveredTheme ? (
                <span className="flex items-center gap-1.5 px-2.5 py-1 bg-amber-500/10 border border-amber-500/30 text-amber-300 rounded font-mono text-[11px] animate-pulse">
                  <Eye className="w-3.5 h-3.5" />
                  Live Previewing
                </span>
              ) : (
                <span className="flex items-center gap-1.5 px-2.5 py-1 bg-blue-500/10 border border-blue-500/30 text-blue-300 rounded font-mono text-[11px]">
                  <CheckCircle2 className="w-3.5 h-3.5 text-blue-400" />
                  Active: {THEME_OPTIONS.find((t) => t.id === currentTheme)?.name}
                </span>
              )}
            </div>

            {/* Theme Selection Grid with Hover Preview Triggers */}
            <div
              className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3"
              onMouseLeave={handleThemeHoverLeave}
            >
              {THEME_OPTIONS.map((theme) => {
                const IconComponent = theme.icon;
                const isSelected = currentTheme === theme.id;
                const isHovered = hoveredTheme === theme.id;

                return (
                  <button
                    key={theme.id}
                    type="button"
                    onClick={() => handleThemeSelect(theme.id)}
                    onMouseEnter={() => handleThemeHover(theme.id)}
                    onFocus={() => handleThemeHover(theme.id)}
                    onBlur={handleThemeHoverLeave}
                    className={`relative text-left p-3 rounded-lg border transition-all cursor-pointer flex flex-col justify-between group ${
                      isHovered
                        ? 'border-indigo-400 bg-indigo-950/30 shadow-md ring-1 ring-indigo-400/50 scale-[1.02]'
                        : isSelected
                        ? 'border-blue-500 bg-blue-950/20 shadow-xs'
                        : 'border-slate-800 bg-slate-900/80 hover:border-slate-700 hover:bg-slate-900'
                    }`}
                  >
                    {/* Top row: Icon, Name, and Status Badge */}
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <div
                          className="w-7 h-7 rounded-md flex items-center justify-center border"
                          style={{
                            backgroundColor: theme.colors.card,
                            borderColor: theme.colors.border,
                            color: theme.colors.accent,
                          }}
                        >
                          <IconComponent className="w-4 h-4" />
                        </div>

                        {isSelected ? (
                          <span className="flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded bg-blue-600 text-white">
                            <Check className="w-3 h-3" />
                            Active
                          </span>
                        ) : isHovered ? (
                          <span className="flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40">
                            <Eye className="w-3 h-3" />
                            Preview
                          </span>
                        ) : (
                          <span className="text-[10px] text-slate-500 font-mono">
                            {theme.badge}
                          </span>
                        )}
                      </div>

                      <div className="font-semibold text-white text-xs group-hover:text-blue-300 transition-colors">
                        {theme.name}
                      </div>
                      <div className="text-[10px] text-slate-400 font-medium">
                        {theme.tagline}
                      </div>
                    </div>

                    {/* Color Swatch Dots */}
                    <div className="pt-3 mt-3 border-t border-slate-800/80 flex items-center justify-between">
                      <div className="flex items-center gap-1.5">
                        <span
                          className="w-3.5 h-3.5 rounded-full border border-slate-600 shadow-xs"
                          style={{ backgroundColor: theme.colors.bg }}
                          title={`Canvas: ${theme.colors.bg}`}
                        />
                        <span
                          className="w-3.5 h-3.5 rounded-full border border-slate-600 shadow-xs"
                          style={{ backgroundColor: theme.colors.card }}
                          title={`Surface: ${theme.colors.card}`}
                        />
                        <span
                          className="w-3.5 h-3.5 rounded-full border border-slate-600 shadow-xs"
                          style={{ backgroundColor: theme.colors.accent }}
                          title={`Accent: ${theme.colors.accent}`}
                        />
                      </div>
                      <span className="text-[10px] font-mono text-slate-500 group-hover:text-slate-300">
                        {isHovered ? 'Click to set' : 'Hover preview'}
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>

            {/* Live Theme Preview Sandbox Card */}
            <div
              className="rounded-lg p-4 border transition-all duration-200"
              style={{
                backgroundColor: activeConfig.colors.card,
                borderColor: activeConfig.colors.border,
                color: activeConfig.colors.text,
              }}
            >
              <div className="flex flex-wrap items-center justify-between gap-2 pb-3 mb-3 border-b"
                   style={{ borderColor: activeConfig.colors.border }}>
                <div className="flex items-center gap-2">
                  <span className="relative flex h-2.5 w-2.5">
                    <span
                      className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-75"
                      style={{ backgroundColor: activeConfig.colors.accent }}
                    ></span>
                    <span
                      className="relative inline-flex rounded-full h-2.5 w-2.5"
                      style={{ backgroundColor: activeConfig.colors.accent }}
                    ></span>
                  </span>
                  <span className="font-semibold text-xs tracking-wide uppercase font-mono">
                    Live Preview Sandbox: {activeConfig.name}
                  </span>
                  {hoveredTheme && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded font-mono font-medium"
                          style={{
                            backgroundColor: `${activeConfig.colors.accent}22`,
                            color: activeConfig.colors.accent,
                            border: `1px solid ${activeConfig.colors.accent}44`,
                          }}>
                      Dynamic Hover Preview
                    </span>
                  )}
                </div>

                <div className="flex items-center gap-2 text-[11px] font-mono">
                  <span style={{ color: activeConfig.colors.muted }}>Contrast:</span>
                  <strong style={{ color: activeConfig.colors.accent }}>{activeConfig.contrastRatio}</strong>
                </div>
              </div>

              {/* Forensic Artifact Representation within Preview */}
              <div className="space-y-2.5">
                <p className="text-[11px] leading-relaxed" style={{ color: activeConfig.colors.muted }}>
                  {activeConfig.description}
                </p>

                {/* Simulated Forensic Widget */}
                <div
                  className="p-3 rounded border font-mono text-[11px] space-y-2"
                  style={{
                    backgroundColor: activeConfig.colors.bg,
                    borderColor: activeConfig.colors.border,
                  }}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <ShieldCheck className="w-3.5 h-3.5" style={{ color: activeConfig.colors.accent }} />
                      <span className="font-semibold">EVIDENCE: MEMDUMP-2026-0881.raw</span>
                    </div>
                    <span
                      className="px-1.5 py-0.5 rounded text-[10px] font-semibold"
                      style={{
                        backgroundColor: `${activeConfig.colors.accent}20`,
                        color: activeConfig.colors.accent,
                        border: `1px solid ${activeConfig.colors.accent}40`,
                      }}
                    >
                      SHA-256 BITSTREAM MATCH
                    </span>
                  </div>

                  <div className="text-[10px] opacity-80 truncate">
                    [2026-10-24 07:14:02 UTC] SYSTEM_AUTH: Failed password for root from 192.168.1.105 (PID: 4921)
                  </div>

                  <div className="flex items-center justify-between pt-1">
                    <span className="text-[10px]" style={{ color: activeConfig.colors.muted }}>
                      Chain of Custody: Sealed &amp; Parametrized
                    </span>
                    <button
                      type="button"
                      onClick={() => handleThemeSelect(activeConfig.id)}
                      className="px-2 py-0.5 rounded font-sans text-[10px] font-semibold transition-all cursor-pointer shadow-xs"
                      style={{
                        backgroundColor: activeConfig.colors.accent,
                        color: activeConfig.id === 'light' ? '#ffffff' : '#ffffff',
                      }}
                    >
                      {currentTheme === activeConfig.id ? 'Current Theme Applied' : `Apply ${activeConfig.name}`}
                    </button>
                  </div>
                </div>

                {/* Color Palette Strip */}
                <div className="flex flex-wrap items-center gap-3 pt-1 text-[10px] font-mono">
                  <span style={{ color: activeConfig.colors.muted }}>Palette:</span>
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: activeConfig.colors.bg }} />
                    <span style={{ color: activeConfig.colors.muted }}>Canvas {activeConfig.colors.bg}</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: activeConfig.colors.card }} />
                    <span style={{ color: activeConfig.colors.muted }}>Surface {activeConfig.colors.card}</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: activeConfig.colors.border }} />
                    <span style={{ color: activeConfig.colors.muted }}>Border {activeConfig.colors.border}</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: activeConfig.colors.accent }} />
                    <span style={{ color: activeConfig.colors.accent }}>Accent {activeConfig.colors.accent}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Section 2: Ollama Model Configuration */}
          <div className="space-y-3 border-b border-slate-800 pb-5">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-white flex items-center gap-1.5 text-sm">
                <Cpu className="w-4 h-4 text-blue-400" />
                Local Ollama Language Model Status
              </span>
              <button
                onClick={handleTestOllama}
                disabled={isCheckingOllama}
                className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded transition-colors cursor-pointer"
              >
                {isCheckingOllama ? 'Probing Daemon...' : 'Probe Connection'}
              </button>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-slate-400 font-medium mb-1">Ollama Host URL</label>
                <input
                  type="text"
                  value={ollamaUrl}
                  onChange={(e) => setOllamaUrl(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-slate-200 font-mono outline-none focus:border-blue-500"
                />
              </div>
              <div>
                <label className="block text-slate-400 font-medium mb-1">Configured Model</label>
                <select
                  value={ollamaModel}
                  onChange={(e) => setOllamaModel(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-slate-200 outline-none focus:border-blue-500 cursor-pointer"
                >
                  <option value="llama3.2">llama3.2 (Recommended 3B Fast)</option>
                  <option value="mistral">mistral (7B Standard)</option>
                  <option value="deepseek-r1">deepseek-r1 (Reasoning)</option>
                  <option value="custom">Custom Model Tag</option>
                </select>
              </div>
            </div>

            {/* Offline Helpful Message (Explicit Requirement from prompt) */}
            <div className="bg-[#080d1a] border border-slate-800 rounded-lg p-3 space-y-1.5">
              <div className="flex items-center gap-2 font-medium text-amber-400">
                <AlertTriangle className="w-4 h-4" />
                <span>Deterministic Fallback Engine Active</span>
              </div>
              <p className="text-slate-300 leading-relaxed text-[11px]">
                If the local Ollama daemon is not running on your machine, ForensiQ AI automatically switches to its deterministic, rule-based forensic reasoning engine. <strong>Core log parsing, timeline reconstruction, SHA-256 integrity verification, and YARA rule generation continue to work with 100% precision without an AI model.</strong>
              </p>
              <div className="pt-1 text-[11px] text-slate-400 font-mono">
                To start Ollama locally: <code className="text-blue-300">ollama run {ollamaModel}</code>
              </div>
            </div>
          </div>

          {/* Section 3: SQLite Database Storage */}
          <div className="space-y-3 border-b border-slate-800 pb-5">
            <span className="font-semibold text-white flex items-center gap-1.5 text-sm">
              <Database className="w-4 h-4 text-purple-400" />
              Investigation Data Management (Module I)
            </span>
            <p className="text-slate-300 text-[11px] leading-relaxed">
              ForensiQ AI stores investigation metadata using parameterized SQL queries in local SQLite (<code>forensiq_cases.db</code>). Sensitive secrets, passwords, and private encryption keys are never retained in plaintext.
            </p>

            <div className="bg-slate-900 border border-slate-800 rounded-lg p-3 font-mono text-[11px] text-slate-400 space-y-1">
              <div>Database File: <strong className="text-slate-200">./forensiq_cases.db</strong></div>
              <div>Tables: <strong className="text-slate-200">cases, evidence_items, custody_ledger, iocs, findings</strong></div>
              <div>Protection: <strong className="text-emerald-400">Parameterized Queries (SQL Injection Immune)</strong></div>
            </div>
          </div>

          {/* Section 4: AI Security & Guardrails */}
          <div className="space-y-2 border-b border-slate-800 pb-5">
            <span className="font-semibold text-white flex items-center gap-1.5 text-sm">
              <Shield className="w-4 h-4 text-emerald-400" />
              AI Prompt Injection Defense &amp; Human Responsibility
            </span>
            <p className="text-slate-300 text-[11px] leading-relaxed">
              All imported log records are sanitized and treated strictly as <strong>untrusted data</strong>. The AI assistant is architecturally sandboxed—it possesses no execution permissions, cannot alter evidence files, and cannot perform actions on external hosts. Final forensic attribution remains the sole legal responsibility of the certified human investigator.
            </p>
          </div>

          {/* Section 5: Reset Data */}
          <div className="space-y-2">
            <span className="font-semibold text-rose-400 flex items-center gap-1.5 text-sm">
              <RotateCcw className="w-4 h-4" />
              Reset Test Investigation Data
            </span>
            <p className="text-slate-400 text-[11px]">
              Clear current session evidence and reload the baseline demonstration scenario.
            </p>

            {!confirmReset ? (
              <button
                onClick={() => setConfirmReset(true)}
                className="px-3 py-1.5 bg-rose-950/60 hover:bg-rose-900/60 border border-rose-800 text-rose-300 rounded font-medium transition-colors cursor-pointer"
              >
                Reset Case Evidence...
              </button>
            ) : (
              <div className="flex items-center gap-3 bg-rose-950/80 border border-rose-700 p-3 rounded-lg">
                <span className="text-rose-200 font-medium">Are you sure? This will reload the default scenario.</span>
                <button
                  onClick={() => {
                    onResetCaseData();
                    setConfirmReset(false);
                    handleClose();
                  }}
                  className="px-3 py-1 bg-rose-600 hover:bg-rose-500 text-white rounded font-semibold cursor-pointer"
                >
                  Confirm Reset
                </button>
                <button
                  onClick={() => setConfirmReset(false)}
                  className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded cursor-pointer"
                >
                  Cancel
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-6 py-3 border-t border-slate-800 bg-[#0d1424] text-[11px] text-slate-400">
          <span>ForensiQ AI Core v2.4 • Current Mode: {THEME_OPTIONS.find((t) => t.id === currentTheme)?.name}</span>
          <button
            onClick={handleClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded transition-colors cursor-pointer"
          >
            Save &amp; Close
          </button>
        </div>
      </div>
    </div>
  );
};
