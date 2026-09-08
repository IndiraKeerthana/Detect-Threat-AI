import React from 'react';
import { Sparkles, Terminal, CheckCircle2, Shield, Wrench, AlertOctagon } from 'lucide-react';
import type { AIInvestigationResult } from '../../types/investigation';
import { SectionHeader } from './SectionHeader';

interface AIInvestigationCardProps {
  aiData?: AIInvestigationResult | null;
}

interface TimelineStage {
  step: string;
  title: string;
  badge: string;
  description: string;
  status: string;
  target?: string | null;
  isTool?: boolean;
}

export const AIInvestigationCard: React.FC<AIInvestigationCardProps> = ({ aiData }) => {
  if (!aiData) {
    return (
      <div className="surface-card p-6 border border-[#1e2430] text-center text-xs text-[#64748b] font-mono">
        NO AUTONOMOUS AI INVESTIGATION RECORD ATTACHED
      </div>
    );
  }

  const isAgent = aiData.source === 'ai_agent';

  // Build the vertical activity timeline from real observable stages and real tool calls
  const timelineStages: TimelineStage[] = [
    {
      step: '01',
      title: 'EMAIL INGESTED & PARSED',
      badge: 'PARSER',
      description: 'MIME RFC 822 structure decoded; transport headers and payload observables extracted.',
      status: 'VERIFIED',
    },
    {
      step: '02',
      title: 'AUTHENTICATION EVALUATED',
      badge: 'RFC 8601',
      description: 'Cryptographic authentication (SPF, DKIM, DMARC) and domain alignment evaluated.',
      status: 'VERIFIED',
    },
    // Dynamically insert tool calls
    ...aiData.tool_calls.map((tool, idx) => ({
      step: `0${idx + 3}`,
      title: `TOOL EXECUTION: ${tool.name}()`,
      badge: 'AUTONOMOUS TOOL',
      description: tool.result_summary || `Target: ${tool.target || 'Entity inspected in local sandbox.'}`,
      target: tool.target,
      status: tool.status.toUpperCase(),
      isTool: true,
    })),
    {
      step: `0${aiData.tool_calls.length + 3}`,
      title: 'CROSS-SIGNAL CORRELATION',
      badge: 'CORRELATOR',
      description: 'Correlated transport infrastructure, observables, and threat telemetry.',
      status: 'VERIFIED',
    },
    {
      step: `0${aiData.tool_calls.length + 4}`,
      title: 'ASSESSMENT FINALIZED',
      badge: 'SYNTHESIS',
      description: 'Synthesized evidence into final structured intelligence report.',
      status: 'COMPLETE',
    },
  ];

  return (
    <div className="surface-card p-6 border border-[#1e2430] space-y-6">
      {/* Standard Section Header */}
      <SectionHeader
        index="02"
        tag="AUTONOMOUS INVESTIGATION"
        title="Observable AI Investigation Activity"
        subtitle="Multi-turn forensic tool execution and autonomous reasoning trace"
        action={
          <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
            {isAgent ? (
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#1e1533] border border-[#432474] text-[#c4b5fd]">
                <Sparkles className="w-3.5 h-3.5 text-[#8b5cf6]" />
                <span>{(aiData.provider || 'AI AGENT').toUpperCase()}</span>
                {aiData.model && (
                  <span className="text-[10px] text-[#a78bfa] border-l border-[#432474] pl-1.5">{aiData.model}</span>
                )}
                <span className="text-[10px] text-[#94a3b8]">({aiData.iterations} ITERATIONS)</span>
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#261b0c] border border-[#5c3c12] text-[#fcd34d]">
                <Shield className="w-3.5 h-3.5" />
                <span>DETERMINISTIC FALLBACK</span>
              </span>
            )}
            <span className="px-2 py-1 rounded bg-[#171b23] border border-[#2a3242] text-[#6ee7b7] text-[11px] font-semibold">
              COMPLETE
            </span>
          </div>
        }
      />

      {/* Intelligence Briefing: Assessment & Why It Matters */}
      <div className="bg-[#0a0c10] border border-[#1e2430] rounded-lg p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-[#1e2430] pb-2 text-xs font-mono">
          <span className="text-[#8b5cf6] font-semibold tracking-wider uppercase flex items-center gap-1.5">
            <Terminal className="w-3.5 h-3.5" />
            INTELLIGENCE BRIEFING // ANALYST SYNTHESIS
          </span>
          <span className="text-[#64748b] text-[10px]">
            {isAgent
              ? `EXECUTION MODE: ${(aiData.provider || 'AI').toUpperCase()} AGENT (${aiData.model || 'BOUNDED'})`
              : 'EXECUTION MODE: DETERMINISTIC FALLBACK'}
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Assessment */}
          <div className="space-y-1.5">
            <span className="text-[10px] font-mono uppercase text-[#64748b] tracking-wider block">
              FORENSIC ASSESSMENT
            </span>
            <p className="text-xs text-[#f1f5f9] leading-relaxed font-sans">
              {aiData.summary}
            </p>
          </div>

          {/* Why It Matters */}
          <div className="space-y-1.5">
            <span className="text-[10px] font-mono uppercase text-[#64748b] tracking-wider block">
              EVIDENCE-GROUNDED RATIONALE
            </span>
            <p className="text-xs text-[#94a3b8] leading-relaxed font-sans">
              {aiData.reasoning}
            </p>
          </div>
        </div>
      </div>

      {/* AI Activity Timeline: Vertical Trace */}
      <div className="space-y-3">
        <div className="flex items-center justify-between text-xs font-mono text-[#64748b] px-1">
          <span className="uppercase tracking-wider">
            {isAgent ? 'AUTONOMOUS ACTIVITY TRACE' : 'DETERMINISTIC ANALYSIS TRACE'} ({timelineStages.length} PHASES)
          </span>
          <span className="text-[#10b981] text-[11px]">ALL OBSERVABLE ACTIONS LOGGED</span>
        </div>

        <div className="relative pl-6 space-y-3 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-[#1e2430]">
          {timelineStages.map((stage, idx) => (
            <div key={idx} className="relative group">
              {/* Step indicator dot */}
              <div className="absolute -left-6 top-1.5 w-5 h-5 rounded bg-[#0f1217] border border-[#2a3242] flex items-center justify-center -translate-x-1/2">
                <span className="text-[9px] font-mono text-[#8b5cf6] font-bold">
                  {stage.step}
                </span>
              </div>

              {/* Stage content box */}
              <div className={`p-3 rounded border transition-colors ${
                stage.isTool
                  ? 'bg-[#151221] border-[#432474]/70 hover:border-[#8b5cf6]'
                  : 'bg-[#12151b] border-[#1e2430] hover:border-[#2a3242]'
              }`}>
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 mb-1">
                  <div className="flex items-center space-x-2">
                    {stage.isTool && <Wrench className="w-3.5 h-3.5 text-[#8b5cf6]" />}
                    <span className="text-xs font-mono font-semibold text-[#f1f5f9]">
                      {stage.title}
                    </span>
                    <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-[#171b23] text-[#94a3b8] border border-[#2a3242]">
                      {stage.badge}
                    </span>
                  </div>

                  <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[#0e241b] text-[#6ee7b7] border border-[#164e3b] inline-flex items-center gap-1 self-start sm:self-auto">
                    <CheckCircle2 className="w-3 h-3" />
                    {stage.status}
                  </span>
                </div>

                <p className="text-[11px] text-[#94a3b8] font-sans">
                  {stage.description}
                </p>

                {stage.target && (
                  <div className="mt-1.5 pt-1.5 border-t border-[#1e2430] flex items-center gap-2 text-[10px] font-mono text-[#64748b]">
                    <span>TARGET OBSERVABLE:</span>
                    <code className="text-[#fca5a5] bg-[#0c0e12] px-1.5 py-0.5 rounded border border-[#1e2430]">
                      {stage.target}
                    </code>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Attribution Boundary Safeguard */}
      <div className="bg-[#0f1217] border border-[#1e2430] p-4 rounded-md space-y-2">
        <div className="flex items-center justify-between text-xs font-mono">
          <span className="flex items-center gap-1.5 text-[#67e8f9] font-semibold uppercase">
            <AlertOctagon className="w-3.5 h-3.5 text-[#06b6d4]" />
            INFRASTRUCTURE-LEVEL ATTRIBUTION
          </span>
          <span className="text-[10px] text-[#64748b]">
            CONFIDENCE: <strong className="text-[#94a3b8]">{aiData.attribution.confidence.toUpperCase()}</strong>
          </span>
        </div>

        <p className="text-xs text-[#f1f5f9] italic leading-relaxed font-sans">
          "{aiData.attribution.assessment}"
        </p>

        <div className="text-[10px] font-mono text-[#64748b] pt-1">
          Constraint: Observable infrastructure indicates malicious relay and credential hosting, but strictly precludes human actor, APT, affiliation, or intent attribution.
        </div>
      </div>
    </div>
  );
};
