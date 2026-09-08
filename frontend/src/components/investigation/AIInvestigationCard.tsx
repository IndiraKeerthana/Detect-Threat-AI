import { Sparkles, Terminal, CheckCircle2 } from 'lucide-react';
import type { AIInvestigationResult } from '../../types/investigation';

interface AIInvestigationCardProps {
  aiData?: AIInvestigationResult | null;
}

export const AIInvestigationCard: React.FC<AIInvestigationCardProps> = ({ aiData }) => {
  if (!aiData) {
    return (
      <div className="surface-card p-5 border border-[#1e2430] text-center text-xs text-[#64748b] font-mono">
        NO AUTONOMOUS AI INVESTIGATION ATTACHED
      </div>
    );
  }

  const isAgent = aiData.source === 'ai_agent';

  return (
    <div className="surface-card border border-[#2a3242] p-5 space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-[#1e2430]">
        <div className="flex items-center space-x-2.5">
          <div className="w-7 h-7 rounded bg-[#1e1533] border border-[#432474] flex items-center justify-center text-[#c4b5fd]">
            <Sparkles className="w-3.5 h-3.5 text-[#8b5cf6]" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-[#f1f5f9] tracking-tight flex items-center gap-2">
              Autonomous AI Forensic Agent
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#1e1533] text-[#c4b5fd] border border-[#432474]">
                GROQ
              </span>
            </h3>
            <p className="text-[11px] text-[#64748b] font-mono">
              Multi-turn forensic tool execution & reasoning loop
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="px-2 py-0.5 rounded bg-[#171b23] border border-[#2a3242] text-[#94a3b8]">
            ITERATIONS: <strong className="text-[#f1f5f9]">{aiData.iterations}</strong>
          </span>
          <span className={`px-2 py-0.5 rounded border ${isAgent ? 'bg-[#1e1533] border-[#432474] text-[#c4b5fd]' : 'bg-[#261b0c] border-[#5c3c12] text-[#fcd34d]'}`}>
            SOURCE: {aiData.source}
          </span>
        </div>
      </div>

      {/* Summary Box */}
      <div className="bg-[#0f1217] border border-[#1e2430] p-3.5 rounded space-y-1.5">
        <div className="text-[10px] font-mono uppercase tracking-wider text-[#64748b]">
          Executive Forensic Synthesis
        </div>
        <p className="text-xs text-[#f1f5f9] leading-relaxed">
          {aiData.summary}
        </p>
      </div>

      {/* Reasoning */}
      <div className="space-y-1.5">
        <div className="text-[11px] font-mono uppercase tracking-wider text-[#64748b] flex items-center gap-1.5">
          <Terminal className="w-3 h-3 text-[#8b5cf6]" />
          Evidence-Backed Rationale
        </div>
        <p className="text-xs text-[#94a3b8] leading-relaxed bg-[#12151b] border border-[#1e2430] p-3 rounded font-sans">
          {aiData.reasoning}
        </p>
      </div>

      {/* Tool Calls Execution Record */}
      <div className="space-y-2">
        <div className="flex items-center justify-between text-[11px] font-mono text-[#64748b]">
          <span>AUTONOMOUS TOOL SELECTION & EXECUTION TRACE ({aiData.tool_calls.length})</span>
          <span className="text-[#10b981]">LOCAL SANDBOX</span>
        </div>

        {aiData.tool_calls.length === 0 ? (
          <div className="text-xs font-mono text-[#64748b] p-2 bg-[#0f1217] rounded border border-[#1e2430]">
            No intermediate tool calls recorded.
          </div>
        ) : (
          <div className="space-y-1.5">
            {aiData.tool_calls.map((call, idx) => (
              <div
                key={idx}
                className="bg-[#171b23] border border-[#2a3242] p-2.5 rounded text-xs font-mono flex flex-col sm:flex-row sm:items-center justify-between gap-2"
              >
                <div className="flex items-center space-x-2">
                  <span className="text-[#8b5cf6] font-semibold">{call.name}()</span>
                  {call.target && (
                    <span className="text-[#f1f5f9] bg-[#1e232e] px-1.5 py-0.5 rounded text-[11px] max-w-xs truncate" title={call.target}>
                      {call.target}
                    </span>
                  )}
                </div>

                <div className="flex items-center space-x-3 text-[11px] text-[#64748b]">
                  <span>{call.result_summary || 'Executed successfully'}</span>
                  <span className="inline-flex items-center gap-1 px-1.5 py-0.2 rounded bg-[#0e241b] text-[#6ee7b7] border border-[#164e3b]">
                    <CheckCircle2 className="w-3 h-3" />
                    {call.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Attribution Boundary Requirement */}
      <div className="bg-[#12151b] border border-[#1e2430] p-3.5 rounded space-y-1.5">
        <div className="flex items-center justify-between text-[10px] font-mono text-[#64748b]">
          <span>ATTRIBUTION STATUS: <strong className="text-[#06b6d4]">{aiData.attribution.status}</strong></span>
          <span>CONFIDENCE: {aiData.attribution.confidence}</span>
        </div>
        <p className="text-xs text-[#94a3b8] italic">
          "{aiData.attribution.assessment}"
        </p>
      </div>
    </div>
  );
};
