import React, { useState } from 'react';
import { Sparkles, Terminal, CheckCircle2, Wrench, AlertOctagon, ChevronDown, ChevronRight } from 'lucide-react';
import type { AIInvestigationResult } from '../../types/investigation';
import { SectionHeader } from './SectionHeader';

interface AIInvestigationCardProps {
  aiData?: AIInvestigationResult | null;
  aiStatus?: string | null;
  aiError?: string | null;
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

export const AIInvestigationCard: React.FC<AIInvestigationCardProps> = ({ aiData, aiError }) => {
  const [isTraceExpanded, setIsTraceExpanded] = useState<boolean>(false);

  if (!aiData || aiData.source !== 'ai_agent' || !aiData.provider || aiData.provider.toLowerCase() === 'deterministic_fallback') {
    return (
      <div className="surface-card p-5 border border-[var(--border-subtle)] space-y-4">
        <SectionHeader
          index="03"
          title="AI forensic assessment"
          subtitle="Autonomous agent synthesis, evidence-grounded rationale, and tool activity trace."
          action={
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-[var(--surface-elevated)] border border-[var(--severity-high)] text-[var(--severity-high)] font-bold">
                <AlertOctagon className="w-3.5 h-3.5" />
                <span>AI ANALYSIS UNAVAILABLE / FAILED</span>
              </span>
            </div>
          }
        />
        <div className="border border-[var(--border-subtle)] rounded-lg p-5 space-y-3 bg-[var(--surface-subtle)]">
          <div className="flex items-center justify-between border-b border-[var(--border-subtle)] pb-2 text-xs font-mono">
            <span className="text-[var(--severity-high)] font-semibold tracking-wider uppercase flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5" />
              AI Analyst Status · Execution Halted
            </span>
            <span className="text-[var(--text-dim)] text-[10px]">
              STATUS: AI ANALYSIS FAILED / UNAVAILABLE
            </span>
          </div>
          <p className="text-xs text-[var(--text-muted)] font-sans leading-relaxed">
            {aiError || 'AI analysis unavailable — investigation could not be completed.'}
          </p>
          <div className="text-[11px] text-[var(--text-dim)] font-mono pt-1 border-t border-[var(--border-subtle)]">
            Forensic evidence extracted from email headers, transport infrastructure, authentication (SPF/DKIM/DMARC), and threat telemetry remains intact below.
          </div>
        </div>
      </div>
    );
  }

  // Build the vertical activity timeline from real observable stages and real tool calls
  const timelineStages: TimelineStage[] = [
    {
      step: '01',
      title: 'Email Ingested & Parsed',
      badge: 'PARSER',
      description: 'MIME RFC 822 structure decoded; transport headers and payload observables extracted.',
      status: 'VERIFIED',
    },
    {
      step: '02',
      title: 'Authentication Evaluated',
      badge: 'RFC 8601',
      description: 'Cryptographic authentication (SPF, DKIM, DMARC) and domain alignment evaluated.',
      status: 'VERIFIED',
    },
    // Dynamically insert tool calls
    ...aiData.tool_calls.map((tool, idx) => ({
      step: `0${idx + 3}`,
      title: `Tool Execution: ${tool.name}()`,
      badge: 'AUTONOMOUS TOOL',
      description: tool.result_summary || `Target: ${tool.target || 'Entity inspected in local sandbox.'}`,
      target: tool.target,
      status: tool.status.toUpperCase(),
      isTool: true,
    })),
    {
      step: `0${aiData.tool_calls.length + 3}`,
      title: 'Cross-Signal Correlation',
      badge: 'CORRELATOR',
      description: 'Correlated transport infrastructure, observables, and threat telemetry.',
      status: 'VERIFIED',
    },
    {
      step: `0${aiData.tool_calls.length + 4}`,
      title: 'Assessment Finalized',
      badge: 'SYNTHESIS',
      description: 'Synthesized evidence into final structured intelligence report.',
      status: 'COMPLETE',
    },
  ];

  return (
    <div className="surface-card p-5 border border-[var(--border-subtle)] space-y-5">
      {/* Standard Section Header */}
      <SectionHeader
        index="03"
        title="AI forensic assessment"
        subtitle="Autonomous agent synthesis, evidence-grounded rationale, and tool activity trace."
        action={
          <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded badge-ai font-bold">
              <Sparkles className="w-3.5 h-3.5 text-[var(--ai)]" />
              <span>{(aiData.provider || 'AI AGENT').toUpperCase()}</span>
              {aiData.model && (
                <span className="text-[10px] text-[var(--text-muted)] border-l border-[var(--border-subtle)] pl-1.5">{aiData.model}</span>
              )}
              <span className="text-[10px] text-[var(--text-dim)]">({aiData.iterations} ITERATIONS)</span>
            </span>
            <span className="px-2 py-1 rounded bg-[var(--surface-elevated)] border border-[var(--border-subtle)] text-[var(--state-pass)] text-[11px] font-semibold">
              COMPLETE
            </span>
          </div>
        }
      />

      {/* Intelligence Briefing: Assessment & Evidence-Grounded Rationale */}
      <div className="border border-[var(--border-subtle)] rounded-lg p-5 space-y-4 bg-[var(--surface-subtle)]">
        <div className="flex items-center justify-between border-b border-[var(--border-subtle)] pb-2 text-xs font-mono">
          <span className="text-[var(--ai)] font-semibold tracking-wider uppercase flex items-center gap-1.5">
            <Terminal className="w-3.5 h-3.5" />
            Intelligence Briefing · Analyst Synthesis
          </span>
          <span className="text-[var(--text-dim)] text-[10px]">
            {`EXECUTION MODE: ${(aiData.provider || 'AI').toUpperCase()} AGENT (${aiData.model || 'BOUNDED'})`}
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {/* Assessment */}
          <div className="space-y-1.5">
            <span className="text-[10px] font-mono uppercase text-[var(--text-dim)] tracking-wider block">
              Forensic Assessment
            </span>
            <p className="text-xs text-[var(--text)] leading-relaxed font-sans font-medium">
              {aiData.summary}
            </p>
          </div>

          {/* Rationale */}
          <div className="space-y-1.5">
            <span className="text-[10px] font-mono uppercase text-[var(--text-dim)] tracking-wider block">
              Evidence-Grounded Rationale
            </span>
            <p className="text-xs text-[var(--text-muted)] leading-relaxed font-sans">
              {aiData.reasoning}
            </p>
          </div>
        </div>

        {/* AI Specific Findings (Reserved Purple Accent Area) */}
        {aiData.key_findings && aiData.key_findings.length > 0 && (
          <div className="pt-3 border-t border-[var(--border-subtle)] space-y-2">
            <span className="text-[10px] font-mono uppercase text-[var(--ai)] tracking-wider block">
              AI-Generated Key Findings ({aiData.key_findings.length})
            </span>
            <div className="space-y-2">
              {aiData.key_findings.map((finding, idx) => (
                <div
                  key={`ai-finding-${idx}`}
                  className="p-3 rounded border border-[var(--border-subtle)] bg-[var(--surface)] space-y-1"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-xs text-[var(--text)] font-sans">
                      {finding.title}
                    </span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded badge-ai">
                      {finding.severity}
                    </span>
                  </div>
                  <p className="text-[11px] text-[var(--text-muted)] font-sans leading-relaxed">
                    {finding.explanation}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* AI Activity Trace Accordion */}
      <div className="border border-[var(--border-subtle)] rounded-lg overflow-hidden bg-[var(--surface)]">
        <button
          type="button"
          onClick={() => setIsTraceExpanded(!isTraceExpanded)}
          className="w-full px-4 py-3 bg-[var(--surface-subtle)] hover:bg-[var(--surface-hover)] flex items-center justify-between text-xs font-mono transition-colors cursor-pointer"
        >
          <div className="flex items-center space-x-2 text-[var(--text)]">
            {isTraceExpanded ? (
              <ChevronDown className="w-4 h-4 text-[var(--ai)]" />
            ) : (
              <ChevronRight className="w-4 h-4 text-[var(--ai)]" />
            )}
            <span className="font-semibold">AI investigation trace</span>
            <span className="text-[var(--text-dim)]">({timelineStages.length} phases)</span>
          </div>
          <span className="text-[10px] text-[var(--text-dim)]">
            {isTraceExpanded ? 'Hide execution details' : 'Show execution details'}
          </span>
        </button>

        {isTraceExpanded && (
          <div className="p-4 space-y-3 border-t border-[var(--border-subtle)]">
            <div className="relative pl-6 space-y-3 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-[var(--border-subtle)]">
              {timelineStages.map((stage, idx) => (
                <div key={idx} className="relative group">
                  <div className="absolute -left-6 top-1.5 w-5 h-5 rounded bg-[var(--surface)] border border-[var(--border-subtle)] flex items-center justify-center -translate-x-1/2">
                    <span className="text-[9px] font-mono text-[var(--ai)] font-bold">
                      {stage.step}
                    </span>
                  </div>

                  <div className={`p-3 rounded border transition-colors ${
                    stage.isTool
                      ? 'bg-[var(--surface-subtle)] border-[var(--border-subtle)]'
                      : 'bg-[var(--surface)] border-[var(--border-subtle)]'
                  }`}>
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 mb-1">
                      <div className="flex items-center space-x-2">
                        {stage.isTool && <Wrench className="w-3.5 h-3.5 text-[var(--ai)]" />}
                        <span className="text-xs font-mono font-semibold text-[var(--text)]">
                          {stage.title}
                        </span>
                        <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-[var(--surface-elevated)] text-[var(--text-muted)] border border-[var(--border-subtle)]">
                          {stage.badge}
                        </span>
                      </div>

                      <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[var(--surface-elevated)] text-[var(--state-pass)] border border-[var(--border-subtle)] inline-flex items-center gap-1 self-start sm:self-auto font-bold">
                        <CheckCircle2 className="w-3 h-3" />
                        {stage.status}
                      </span>
                    </div>

                    <p className="text-[11px] text-[var(--text-muted)] font-sans">
                      {stage.description}
                    </p>

                    {stage.target && (
                      <div className="mt-1.5 pt-1.5 border-t border-[var(--border-subtle)] flex items-center gap-2 text-[10px] font-mono text-[var(--text-dim)]">
                        <span>TARGET OBSERVABLE:</span>
                        <code className="text-[var(--identifier)] bg-[var(--surface)] px-1.5 py-0.5 rounded border border-[var(--border-subtle)]">
                          {stage.target}
                        </code>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Attribution Boundary Safeguard */}
      <div className="border border-[var(--border-subtle)] p-4 rounded-md bg-[var(--surface-subtle)] space-y-2">
        <div className="flex items-center justify-between text-xs font-mono">
          <span className="flex items-center gap-1.5 text-[var(--identifier)] font-semibold uppercase">
            <AlertOctagon className="w-3.5 h-3.5" />
            Infrastructure-only attribution
          </span>
          <span className="text-[10px] text-[var(--text-dim)]">
            CONFIDENCE: <strong className="text-[var(--text-muted)]">{aiData.attribution.confidence.toUpperCase()}</strong>
          </span>
        </div>

        <p className="text-xs text-[var(--text)] italic leading-relaxed font-sans">
          "{aiData.attribution.assessment}"
        </p>

        <div className="text-[10px] font-mono text-[var(--text-dim)] pt-1">
          Constraint: Shared infrastructure indicates suspicious routing and payload distribution, but does not establish human actor attribution, affiliation, or intent.
        </div>
      </div>
    </div>
  );
};
