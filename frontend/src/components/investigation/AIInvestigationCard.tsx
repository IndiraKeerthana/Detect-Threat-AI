import React from 'react';
import { Sparkles, AlertOctagon, Mail, Target, Info } from 'lucide-react';
import type { AIInvestigationResult } from '../../types/investigation';
import { SectionHeader } from './SectionHeader';

interface AIInvestigationCardProps {
  aiData?: AIInvestigationResult | null;
  aiStatus?: string | null;
  aiError?: string | null;
}

export const AIInvestigationCard: React.FC<AIInvestigationCardProps> = ({ aiData, aiError }) => {
  const isPrecomputed = aiData?.provider === 'precomputed';

  if (
    !aiData ||
    aiData.source !== 'ai_agent' ||
    (!aiData.provider && !isPrecomputed) ||
    aiData.provider?.toLowerCase() === 'deterministic_fallback'
  ) {
    return (
      <div className="surface-card p-5 border border-[var(--border-subtle)] rounded-2xl space-y-4 font-sans">
        <SectionHeader
          index={3}
          title="AI Safety Assessment"
          subtitle="Smart content intent analysis and sender verification."
          action={
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs font-semibold">
              <AlertOctagon className="w-3.5 h-3.5" />
              <span>AI analysis is currently unavailable</span>
            </span>
          }
        />
        <div className="border border-[var(--border-subtle)] rounded-xl p-4 space-y-2 bg-[var(--surface-subtle)] text-xs text-[var(--text-muted)]">
          <p className="font-medium text-[var(--text)]">
            {aiError || 'AI analysis is currently unavailable for this email.'}
          </p>
          <p className="text-[11px] text-[var(--text-dim)]">
            All deterministic safety checks, email security seals, links, and sender location details remain available in the other sections below.
          </p>
        </div>
      </div>
    );
  }

  const suspiciousFindings =
    aiData.suspicious_content_findings ||
    ((aiData as any).suspicious_content ? [(aiData as any).suspicious_content] : []);

  return (
    <div className="surface-card p-5 border border-[var(--border-subtle)] rounded-2xl space-y-5 font-sans">
      {/* Section Header */}
      <SectionHeader
        index={3}
        title="AI Safety Assessment"
        subtitle="Smart content intent analysis and sender verification."
        action={
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full badge-ai font-semibold">
              <Sparkles className="w-3.5 h-3.5 text-[var(--ai)]" />
              <span>{isPrecomputed ? 'Smart Content Review' : (aiData.provider || 'AI Analysis').toUpperCase()}</span>
            </span>
            <span className="px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-xs font-semibold">
              Complete
            </span>
          </div>
        }
      />

      {/* 1. EMAIL INTENT & CLAIMED IDENTITY */}
      {(aiData.email_intent || aiData.claimed_identity || aiData.requested_action || aiData.summary) && (
        <div className="border border-[var(--border-subtle)] rounded-xl p-4 bg-[var(--surface-subtle)] space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border-subtle)] pb-2 text-xs">
            <span className="text-[var(--ai)] font-semibold flex items-center gap-1.5">
              <Mail className="w-4 h-4" />
              Email Purpose &amp; Claimed Sender
            </span>
            {aiData.claimed_identity && (
              <span className="px-2.5 py-0.5 rounded-full bg-[var(--surface-elevated)] border border-[var(--border-subtle)] text-xs text-[var(--identifier)]">
                Claimed Identity: <strong>{aiData.claimed_identity}</strong>
              </span>
            )}
          </div>

          {aiData.email_intent && (
            <div className="space-y-1">
              <span className="text-xs font-semibold text-[var(--text-muted)] uppercase tracking-wider block font-mono">
                Email Intent &mdash; What is this email trying to make you do?
              </span>
              <p className="text-xs text-[var(--text)] leading-relaxed font-medium">
                {aiData.email_intent}
              </p>
            </div>
          )}

          {aiData.summary && !aiData.email_intent && (
            <div className="space-y-1">
              <span className="text-xs font-semibold text-[var(--text-muted)] uppercase tracking-wider block font-mono">
                Email Summary
              </span>
              <p className="text-xs text-[var(--text)] leading-relaxed font-medium">
                {aiData.summary}
              </p>
            </div>
          )}

          {aiData.requested_action && (
            <div className="p-3 rounded-lg bg-[var(--surface)] border border-[var(--border-subtle)] flex items-start gap-2.5">
              <Target className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <div className="space-y-0.5">
                <span className="text-xs font-semibold text-amber-400 uppercase tracking-wider block font-mono">
                  Action Requested from Recipient
                </span>
                <p className="text-xs text-[var(--text)] leading-relaxed">
                  {aiData.requested_action}
                </p>
              </div>
            </div>
          )}
        </div>
      )}

      {/* 2. WHAT THE AI FOUND SUSPICIOUS */}
      {suspiciousFindings.length > 0 && (
        <div className="border border-[var(--border-subtle)] rounded-xl p-4 bg-[var(--surface-subtle)] space-y-3">
          <div className="flex items-center justify-between border-b border-[var(--border-subtle)] pb-2 text-xs">
            <span className="text-amber-400 font-semibold flex items-center gap-1.5">
              <Info className="w-4 h-4 text-amber-400" />
              What the AI Found Suspicious &mdash; What looks unusual or risky in the email?
            </span>
            <span className="text-[11px] text-[var(--text-dim)] font-mono">
              {suspiciousFindings.length} Observation{suspiciousFindings.length > 1 ? 's' : ''}
            </span>
          </div>
          <div className="space-y-2">
            {suspiciousFindings.map((finding: string, idx: number) => (
              <div
                key={`content-fishy-${idx}`}
                className="p-3 rounded-lg bg-[var(--surface)] border border-[var(--border-subtle)] text-xs text-[var(--text)] leading-relaxed flex items-start gap-2.5"
              >
                <span className="w-5 h-5 rounded-full bg-[var(--surface-elevated)] border border-[var(--border-subtle)] text-[10px] font-mono font-bold text-[var(--ai)] flex items-center justify-center shrink-0 mt-0.5">
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
