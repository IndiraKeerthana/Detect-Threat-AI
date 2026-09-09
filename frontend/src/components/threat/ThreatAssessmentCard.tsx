import React from 'react';
import { ShieldAlert, Activity, CheckCircle2, Layers } from 'lucide-react';
import type { RiskAssessment, EmailAnalysisResponse } from '../../types/investigation';
import { SectionHeader } from '../investigation/SectionHeader';
import { deriveEmailCategory } from '../../services/investigationAdapter';

interface ThreatAssessmentCardProps {
  assessment?: RiskAssessment | null;
  correlationCount?: number;
  data?: EmailAnalysisResponse | null;
}

export const ThreatAssessmentCard: React.FC<ThreatAssessmentCardProps> = ({
  assessment,
  data,
}) => {
  if (!assessment) {
    return (
      <div className="surface-card p-5 border border-[var(--border-subtle)] text-center text-xs text-[var(--text-dim)] font-mono">
        NO DETERMINISTIC THREAT ASSESSMENT AVAILABLE
      </div>
    );
  }

  const score = assessment.score;
  const level = assessment.level.toUpperCase();
  const confidence = assessment.confidence?.level?.toUpperCase() || 'UNKNOWN';
  const evidenceCount = assessment.confidence?.evidence_count ?? (assessment.factors?.length ?? 0);

  // Derive explicit Email Category & Related Categories from evidence
  const categories = deriveEmailCategory(data || ({ risk_assessment: assessment } as EmailAnalysisResponse));

  const totalTicks = 24;
  const activeTicks = Math.round((score / 100) * totalTicks);

  return (
    <div className="surface-card p-5 border border-[var(--border-subtle)] space-y-5">
      {/* Section Header */}
      <SectionHeader
        index="01"
        title="Threat posture"
        subtitle="Multi-factor risk score computed from RFC authentication, telemetry feeds, and correlated evidence."
        action={
          <div className="flex items-center space-x-2 text-xs font-mono text-[var(--text-muted)]">
            <span className="px-2.5 py-1 rounded bg-[var(--surface-elevated)] border border-[var(--border-subtle)]">
              ENGINE: DETERMINISTIC SCORER v2
            </span>
          </div>
        }
      />

      {/* Visual Hero Composition */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center bg-[var(--surface-subtle)] border border-[var(--border-subtle)] p-5 rounded-lg">
        {/* Left 5 Cols: Score Arc Instrument */}
        <div className="lg:col-span-5 flex flex-col items-center justify-center p-2 text-center border-b lg:border-b-0 lg:border-r border-[var(--border-subtle)] pb-6 lg:pb-0 lg:pr-6">
          <div className="relative w-52 h-44 flex items-center justify-center">
            <svg className="w-48 h-48 -rotate-90 transform" viewBox="0 0 160 160">
              {Array.from({ length: totalTicks }).map((_, i) => {
                const angle = (i / (totalTicks - 1)) * 240 - 210;
                const rad = (angle * Math.PI) / 180;
                const r1 = 62;
                const r2 = 72;
                const x1 = 80 + r1 * Math.cos(rad);
                const y1 = 80 + r1 * Math.sin(rad);
                const x2 = 80 + r2 * Math.cos(rad);
                const y2 = 80 + r2 * Math.sin(rad);
                const isActive = i < activeTicks;

                let strokeColor = 'var(--border-subtle)';
                if (isActive) {
                  if (i < 8) strokeColor = 'var(--severity-low)';
                  else if (i < 16) strokeColor = 'var(--severity-medium)';
                  else strokeColor = 'var(--severity-critical)';
                }

                return (
                  <line
                    key={i}
                    x1={x1}
                    y1={y1}
                    x2={x2}
                    y2={y2}
                    stroke={strokeColor}
                    strokeWidth={isActive ? 2.5 : 1.5}
                    strokeLinecap="round"
                    className="transition-all duration-300"
                  />
                );
              })}
              <circle cx="80" cy="80" r="50" fill="none" stroke="var(--border-subtle)" strokeWidth="1" strokeDasharray="2 3" />
            </svg>

            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none select-none">
              <span className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-dim)]">
                RISK SCORE
              </span>
              <div className="text-4xl font-mono font-extrabold text-[var(--severity-critical)] tracking-tight leading-none mt-1">
                {score}
              </div>
              <span className="text-xs font-mono text-[var(--text-dim)] mt-0.5">
                / 100
              </span>
            </div>
          </div>

          <div className="w-full max-w-xs flex items-center justify-between text-[10px] font-mono text-[var(--text-dim)] pt-1">
            <span>0 BENIGN</span>
            <span>50 SUSPICIOUS</span>
            <span className="text-[var(--severity-critical)] font-semibold">100 CRITICAL</span>
          </div>
        </div>

        {/* Right 7 Cols: Telemetry Breakdown & Key Reasons */}
        <div className="lg:col-span-7 space-y-4">
          <div className="grid grid-cols-2 gap-3 text-xs font-mono">
            {/* Severity Band */}
            <div className="bg-[var(--surface)] border border-[var(--border-subtle)] p-3 rounded space-y-1">
              <span className="text-[10px] text-[var(--text-dim)] uppercase tracking-wider block">
                Severity
              </span>
              <div className="text-sm font-bold text-[var(--severity-critical)] flex items-center gap-2">
                <ShieldAlert className="w-4 h-4" />
                {level}
              </div>
              <span className="text-[10px] text-[var(--text-muted)] block font-sans">Score: {score}/100</span>
            </div>

            {/* Email Category (Replaces Classification: mixed) */}
            <div className="bg-[var(--surface)] border border-[var(--border-subtle)] p-3 rounded space-y-1">
              <span className="text-[10px] text-[var(--text-dim)] uppercase tracking-wider block">
                Email Category
              </span>
              <div className="text-sm font-bold text-[var(--text)] flex items-center gap-2 font-sans truncate">
                <Layers className="w-4 h-4 text-[var(--identifier)] shrink-0" />
                <span className="truncate" title={categories.primaryCategory}>{categories.primaryCategory}</span>
              </div>
              {categories.relatedCategories.length > 0 ? (
                <span className="text-[10px] text-[var(--text-muted)] block font-sans truncate" title={`Related: ${categories.relatedCategories.join(' · ')}`}>
                  Related: {categories.relatedCategories.join(' · ')}
                </span>
              ) : (
                <span className="text-[10px] text-[var(--text-muted)] block font-sans">Primary taxonomy</span>
              )}
            </div>

            {/* Confidence Level */}
            <div className="bg-[var(--surface)] border border-[var(--border-subtle)] p-3 rounded space-y-1">
              <span className="text-[10px] text-[var(--text-dim)] uppercase tracking-wider block">
                Confidence
              </span>
              <div className="text-sm font-bold text-[var(--state-pass)] flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-[var(--state-pass)]" />
                {confidence}
              </div>
              <span className="text-[10px] text-[var(--text-muted)] block font-sans">Evidence consistency</span>
            </div>

            {/* Observables (Indicator Count ONLY - "5 correlations" removed) */}
            <div className="bg-[var(--surface)] border border-[var(--border-subtle)] p-3 rounded space-y-1">
              <span className="text-[10px] text-[var(--text-dim)] uppercase tracking-wider block">
                Observables
              </span>
              <div className="text-sm font-bold text-[var(--identifier)] flex items-center gap-2">
                <Activity className="w-4 h-4 text-[var(--identifier)]" />
                {evidenceCount} INDICATORS
              </div>
              <span className="text-[10px] text-[var(--text-muted)] block font-sans">Evidence signals</span>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
};
