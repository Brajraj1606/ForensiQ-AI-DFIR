import React, { useState, useRef, useEffect } from 'react';
import {
  Sparkles,
  Send,
  HelpCircle,
  Shield,
  FileSearch,
  Scale,
  RotateCcw,
  Bot,
  User,
  CheckCircle,
} from 'lucide-react';
import { CaseMetadata, EvidenceItem, TimelineEvent, ExtractedIOC } from '../forensics/types';

interface ForensiQCopilotProps {
  currentCase: CaseMetadata;
  evidenceItems: EvidenceItem[];
  timelineEvents: TimelineEvent[];
  extractedIOCs: ExtractedIOC[];
  initialAnalysis?: string | null;
}

interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  source?: string;
  timestamp: string;
}

const QUICK_PROMPTS = [
  'Triage overall incident and synthesize root cause',
  'Identify anti-forensics techniques (e.g. log purging, timestomping)',
  'Explain RWX memory protection and Volatility malfind indicators',
  'Evaluate legal chain of custody compliance under FRE 901',
  'What are the immediate containment priorities for this compromise?',
];

export const ForensiQCopilot: React.FC<ForensiQCopilotProps> = ({
  currentCase,
  evidenceItems,
  timelineEvents,
  extractedIOCs,
  initialAnalysis,
}) => {
  const [messages, setMessages] = useState<ChatMessage[]>(() => {
    const list: ChatMessage[] = [];
    if (initialAnalysis) {
      list.push({
        id: 'msg-initial',
        role: 'assistant',
        content: initialAnalysis,
        source: 'ForensiQ Forensic Triage Engine',
        timestamp: new Date().toISOString(),
      });
    } else {
      list.push({
        id: 'msg-welcome',
        role: 'assistant',
        content: `**ForensiQ AI Digital Forensics Assistant Initialized.**

I am your evidence-aware investigation copilot for case **${currentCase.id}** (*${currentCase.title}*).
All responses follow strict forensic standards (ISO/IEC 27037 and NIST SP 800-86), rigorously separating:
- **[OBSERVED FACT]:** Directly verified artifact strings, timestamps, and hashes.
- **[DETERMINISTIC RULE]:** Pre-compiled MITRE ATT&CK & signature heuristics.
- **[AI INTERPRETATION]:** Threat actor hypothesis and intrusion reconstruction.
- **[UNVERIFIED HYPOTHESIS]:** Points requiring additional physical or network proof.

Ask a question below or click one of the investigation prompts to begin.`,
        source: 'ForensiQ Core',
        timestamp: new Date().toISOString(),
      });
    }
    return list;
  });

  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  const handleSend = async (textToSend?: string) => {
    const text = (textToSend || input).trim();
    if (!text || loading) return;

    const userMsg: ChatMessage = {
      id: `usr-${Date.now()}`,
      role: 'user',
      content: text,
      timestamp: new Date().toISOString(),
    };

    setMessages((prev) => [...prev, userMsg]);
    if (!textToSend) setInput('');
    setLoading(true);

    try {
      const response = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: text,
          caseContext: {
            metadata: currentCase,
            evidence: evidenceItems.map((e) => ({
              id: e.id,
              name: e.name,
              sha256: e.sha256,
              type: e.fileType,
            })),
            timeline: timelineEvents.slice(0, 15),
            iocs: extractedIOCs.slice(0, 15),
          },
          history: messages.slice(-4).map((m) => ({
            role: m.role,
            content: m.content,
          })),
        }),
      });

      const data = await response.json();

      const aiMsg: ChatMessage = {
        id: `ai-${Date.now()}`,
        role: 'assistant',
        content: data.reply || 'No analysis available.',
        source: data.source,
        timestamp: new Date().toISOString(),
      };

      setMessages((prev) => [...prev, aiMsg]);
    } catch (err: any) {
      setMessages((prev) => [
        ...prev,
        {
          id: `ai-err-${Date.now()}`,
          role: 'assistant',
          content: `Forensic Engine Communication Error: ${err.message}`,
          source: 'System Error',
          timestamp: new Date().toISOString(),
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-[700px] bg-[#0b101e] border border-slate-800 rounded-xl overflow-hidden">
      {/* Top Copilot Bar */}
      <div className="bg-[#0f172a] border-b border-slate-800 px-4 py-3 flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 bg-blue-600/20 border border-blue-500/30 rounded-lg text-blue-400">
            <Sparkles className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-xs font-semibold text-white">ForensiQ Investigation Copilot</h3>
            <span className="text-[11px] text-slate-400">
              Evidence-Grounded AI Reasoning • Model: Gemini 3.8 Flash
            </span>
          </div>
        </div>

        <button
          onClick={() => {
            setMessages([
              {
                id: `reset-${Date.now()}`,
                role: 'assistant',
                content: `Chat session reset. Active case is **${currentCase.id}**. Ready for inquiries.`,
                timestamp: new Date().toISOString(),
              },
            ]);
          }}
          className="text-slate-400 hover:text-white text-xs flex items-center gap-1 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 hover:bg-slate-800 transition-colors"
        >
          <RotateCcw className="w-3 h-3" />
          <span>Reset Session</span>
        </button>
      </div>

      {/* Suggested Quick Inquiries */}
      <div className="bg-[#090d18] border-b border-slate-800/80 px-4 py-2 flex items-center gap-2 overflow-x-auto text-xs scrollbar-none">
        <span className="text-slate-500 font-mono text-[11px] whitespace-nowrap">Suggested Inquiries:</span>
        {QUICK_PROMPTS.map((p, idx) => (
          <button
            key={idx}
            onClick={() => handleSend(p)}
            disabled={loading}
            className="whitespace-nowrap bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white px-2.5 py-1 rounded-md text-[11px] transition-colors"
          >
            {p}
          </button>
        ))}
      </div>

      {/* Messages Feed */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs">
        {messages.map((m) => (
          <div
            key={m.id}
            className={`flex items-start gap-3 ${
              m.role === 'user' ? 'justify-end' : 'justify-start'
            }`}
          >
            {m.role === 'assistant' && (
              <div className="w-7 h-7 rounded-lg bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400 shrink-0 mt-0.5">
                <Bot className="w-4 h-4" />
              </div>
            )}

            <div
              className={`max-w-[85%] rounded-xl p-3.5 space-y-2 leading-relaxed ${
                m.role === 'user'
                  ? 'bg-blue-600 text-white font-medium shadow-sm'
                  : 'bg-[#0f172a] border border-slate-800 text-slate-200'
              }`}
            >
              <div className="whitespace-pre-wrap select-text">{m.content}</div>

              {m.source && (
                <div className="flex items-center justify-between text-[10px] text-slate-500 pt-1 border-t border-slate-800">
                  <span className="font-mono">Engine: {m.source}</span>
                  <span>{m.timestamp.slice(11, 19)} UTC</span>
                </div>
              )}
            </div>

            {m.role === 'user' && (
              <div className="w-7 h-7 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300 shrink-0 mt-0.5">
                <User className="w-4 h-4" />
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div className="flex items-center gap-2 text-slate-400 text-xs py-2 bg-slate-900/40 border border-slate-800 rounded-lg px-3 w-fit">
            <div className="w-3.5 h-3.5 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
            <span>ForensiQ is correlating artifacts and reasoning across evidence streams...</span>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input Area */}
      <div className="p-3 bg-[#0d1424] border-t border-slate-800">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend();
          }}
          className="flex items-center gap-2"
        >
          <input
            type="text"
            placeholder="Ask a forensic question or request evidence analysis..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            disabled={loading}
            className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3.5 py-2.5 text-xs text-slate-200 placeholder-slate-500 outline-none focus:border-blue-500"
          />
          <button
            type="submit"
            disabled={loading || !input.trim()}
            aria-label="Send message to ForensiQ Copilot"
            className="p-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-medium transition-colors shadow-sm cursor-pointer"
          >
            <Send className="w-4 h-4" />
          </button>
        </form>
      </div>
    </div>
  );
};
