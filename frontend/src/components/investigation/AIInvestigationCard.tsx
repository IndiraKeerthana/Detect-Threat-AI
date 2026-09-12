import React from 'react';
import {
  Sparkles,
  Terminal,
  AlertOctagon,
  Mail,
  Target,
} from 'lucide-react';
import type { AIInvestigationResult } from '../../types/investigation';
import { SectionHeader } from './SectionHeader';

interface AIInvestigationCardProps {
  aiData?: AIInvestigationResult | null;
  aiStatus?: string | null;
  aiError?: string | null;
}

export const AIInvestigationCard: React.FC<AIInvestigationCardProps> = ({ aiData, aiError }) => {
  const isPrecomputed = aiData?.provider === 'precomputed';
  if (!aiData || aiData.source !== 'ai_agent' || (!aiData.provider && !isPrecomputed) || aiData.provider?.toLowerCase() === 'deterministic_fallback') {
    return (
      <div className="surface-card p-5 border border-[var(--border-subtle)] space-y-4">
        <SectionHeader
          index="03"
          title="AI forensic assessment"
          subtitle="Autonomous agent synthesis, content intent investigation, and forensic correlation."
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

  return (
    <div className="surface-card p-5 border border-[var(--border-subtle)] space-y-5">
      {/* Standard Section Header */}
      <SectionHeader
        index="03"
        title="AI forensic assessment"
        subtitle="Autonomous agent synthesis, content intent investigation, and forensic correlation."
        action={
          <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded badge-ai font-bold">
              <Sparkles className="w-3.5 h-3.5 text-[var(--ai)]" />
              <span>{isPrecomputed ? 'CONTENT ASSESSMENT' : (aiData.provider || 'AI AGENT').toUpperCase()}</span>
              {!isPrecomputed && aiData.model && (
                <span className="text-[10px] text-[var(--text-muted)] border-l border-[var(--border-subtle)] pl-1.5">{aiData.model}</span>
              )}
              {!isPrecomputed && (
                <span className="text-[10px] text-[var(--text-dim)]">({aiData.iterations} ITERATIONS)</span>
              )}
            </span>
            <span className="px-2 py-1 rounded bg-[var(--surface-elevated)] border border-[var(--border-subtle)] text-[var(--state-pass)] text-[11px] font-semibold">
              COMPLETE
            </span>
          </div>
        }
      />

      {/* 1. EMAIL INTENT & CLAIMED IDENTITY (Content Investigation Hero) */}
      {(aiData.email_intent || aiData.claimed_identity || aiData.requested_action) && (
        <div className="border border-[var(--border-subtle)] rounded-lg p-4 bg-[var(--surface-subtle)] space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border-subtle)] pb-2 text-xs font-mono">
            <span className="text-[var(--ai)] font-semibold tracking-wider uppercase flex items-center gap-1.5">
              <Mail className="w-3.5 h-3.5" />
              Email Intent & Claimed Identity
            </span>
            {aiData.claimed_identity && (
              <span className="px-2 py-0.5 rounded bg-[var(--surface-elevated)] border border-[var(--border-subtle)] text-[10px] font-mono text-[var(--identifier)]">
                CLAIMED: <strong>{aiData.claimed_identity}</strong>
              </span>
            )}
          </div>

          {aiData.email_intent && (
            <div className="space-y-1">
              <span className="text-[10px] font-mono uppercase text-[var(--text-dim)] tracking-wider block">
                What this email claims to be
              </span>
              <p className="text-xs text-[var(--text)] leading-relaxed font-sans font-medium">
                {aiData.email_intent}
              </p>
            </div>
          )}

          {aiData.requested_action && (
            <div className="p-2.5 rounded bg-[var(--surface)] border border-[var(--border-subtle)] flex items-start gap-2.5">
              <Target className="w-4 h-4 text-[var(--severity-high)] shrink-0 mt-0.5" />
              <div className="space-y-0.5">
                <span className="text-[10px] font-mono uppercase text-[var(--severity-high)] font-bold tracking-wider block">
                  Action Attempted on Recipient
                </span>
                <p className="text-xs text-[var(--text)] font-sans leading-relaxed">
                  {aiData.requested_action}
                </p>
              </div>
            </div>
          )}
        </div>
      )}

      {/* 2. WHAT THE AI FOUND FISHY (Concrete Content Observations) */}
      {aiData.suspicious_content_findings && aiData.suspicious_content_findings.length > 0 && (
        <div className="border border-[var(--border-subtle)] rounded-lg p-4 bg-[var(--surface-subtle)] space-y-3">
          <div className="flex items-center justify-between border-b border-[var(--border-subtle)] pb-2 text-xs font-mono">
            <span className="text-[var(--severity-high)] font-semibold tracking-wider uppercase flex items-center gap-1.5">
              <AlertOctagon className="w-3.5 h-3.5" />
              What The AI Found Fishy (Content Observations)
            </span>
            <span className="text-[10px] font-mono text-[var(--text-dim)]">
              {aiData.suspicious_content_findings.length} OBSERVATION{aiData.suspicious_content_findings.length > 1 ? 'S' : ''}
            </span>
          </div>
          <div className="space-y-2">
            {aiData.suspicious_content_findings.map((finding, idx) => (
              <div
                key={`content-fishy-${idx}`}
                className="p-3 rounded bg-[var(--surface)] border border-[var(--border-subtle)] text-xs text-[var(--text)] font-sans leading-relaxed flex items-start gap-2.5"
              >
                <span className="w-5 h-5 rounded bg-[var(--surface-elevated)] border border-[var(--border-subtle)] text-[10px] font-mono font-bold text-[var(--ai)] flex items-center justify-center shrink-0 mt-0.5">
                  {idx + 1}
                </span>
                <p className="flex-1">{finding}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
