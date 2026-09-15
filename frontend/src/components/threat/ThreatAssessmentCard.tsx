import React from 'react';
import { ShieldAlert, Activity, CheckCircle2, Layers, ShieldCheck } from 'lucide-react';
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
      <div className="surface-card p-5 border border-[var(--border-subtle)] rounded-2xl text-center text-xs text-[var(--text-muted)] font-sans">
        No risk score calculation available.
      </div>
    );
  }

  const score = assessment.score;
  const level = assessment.level.toUpperCase();
  const confidence = assessment.confidence?.level?.toUpperCase() || 'UNKNOWN';
  const evidenceCount = assessment.confidence?.evidence_count ?? (assessment.factors?.length ?? 0);

  const categories = deriveEmailCategory(data || ({ risk_assessment: assessment } as EmailAnalysisResponse));

  const totalTicks = 24;
  const activeTicks = Math.round((score / 100) * totalTicks);

  const getBadgeClass = () => {
    if (score >= 70 || level === 'CRITICAL' || level === 'HIGH') {
      return 'bg-rose-500/10 text-rose-400 border-rose-500/20';
    }
    if (score >= 40 || level === 'MEDIUM') {
      return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
    }
    return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
  };

  return (
    <div className="surface-card p-5 border border-[var(--border-subtle)] rounded-2xl space-y-5 font-sans">
      {/* Section Header */}
      <SectionHeader
        index={1}
        title="Overall Risk Score & Classification"
        subtitle="Automated overall score calculated from email seals, links, and content checks."
        action={
          <span className={`px-3 py-1 rounded-full text-xs font-bold border uppercase flex items-center gap-1.5 ${getBadgeClass()}`}>
            {score >= 70 ? <ShieldAlert className="w-3.5 h-3.5 text-rose-400" /> : <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />}
            {level} RISK ({score}/100)
          </span>
        }
      />

      {/* Score Hero Composition */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center bg-[var(--surface-subtle)] border border-[var(--border-subtle)] p-5 rounded-xl">
        {/* Left 5 Cols: Score Arc Meter */}
        <div className="lg:col-span-5 flex flex-col items-center justify-center p-2 text-center border-b lg:border-b-0 lg:border-r border-[var(--border-subtle)] pb-6 lg:pb-0 lg:pr-6">
          <div className="relative w-48 h-40 flex items-center justify-center">
            <svg className="w-44 h-44 -rotate-90 transform" viewBox="0 0 160 160">
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
                  if (i < 8) strokeColor = '#10b981';
                  else if (i < 16) strokeColor = '#f59e0b';
                  else strokeColor = '#f43f5e';
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
              <div className="text-4xl font-mono font-extrabold text-[var(--text)] tracking-tight leading-none mt-1">
                {score}
              </div>
              <span className="text-xs font-mono text-[var(--text-dim)] mt-0.5">
                / 100
              </span>
            </div>
          </div>

          <div className="w-full max-w-xs flex items-center justify-between text-[10px] font-mono text-[var(--text-dim)] pt-1">
            <span>0 SAFE</span>
            <span>50 WARNING</span>
            <span className="text-rose-400 font-semibold">100 HIGH RISK</span>
          </div>
        </div>

        {/* Right 7 Cols: Classification & Summary Cards */}
        <div className="lg:col-span-7 space-y-4">
          <div className="grid grid-cols-2 gap-3 text-xs">
            {/* Risk Rating */}
            <div className="bg-[var(--surface)] border border-[var(--border-subtle)] p-3.5 rounded-xl space-y-1">
              <span className="text-[10px] text-[var(--text-dim)] uppercase font-mono block">
                Risk Rating
              </span>
              <div className="text-sm font-bold text-[var(--text)] flex items-center gap-2">
                {score >= 70 ? <ShieldAlert className="w-4 h-4 text-rose-400" /> : <ShieldCheck className="w-4 h-4 text-emerald-400" />}
                {level}
              </div>
              <span className="text-[11px] text-[var(--text-muted)] block font-sans">Score: {score}/100</span>
            </div>

            {/* Email Classification */}
            <div className="bg-[var(--surface)] border border-[var(--border-subtle)] p-3.5 rounded-xl space-y-1">
              <span className="text-[10px] text-[var(--text-dim)] uppercase font-mono block">
                Email Classification
              </span>
              <div className="text-sm font-bold text-[var(--text)] flex items-center gap-2 truncate">
                <Layers className="w-4 h-4 text-[var(--identifier)] shrink-0" />
                <span className="truncate" title={categories.primaryCategory}>{categories.primaryCategory}</span>
              </div>
              <span className="text-[11px] text-[var(--text-muted)] block truncate">Taxonomy classification</span>
            </div>

            {/* Confidence */}
            <div className="bg-[var(--surface)] border border-[var(--border-subtle)] p-3.5 rounded-xl space-y-1">
              <span className="text-[10px] text-[var(--text-dim)] uppercase font-mono block">
                Confidence
              </span>
              <div className="text-sm font-bold text-emerald-400 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                {confidence}
              </div>
              <span className="text-[11px] text-[var(--text-muted)] block">Verified evidence</span>
            </div>

            {/* Warning Signals */}
            <div className="bg-[var(--surface)] border border-[var(--border-subtle)] p-3.5 rounded-xl space-y-1">
              <span className="text-[10px] text-[var(--text-dim)] uppercase font-mono block">
                Warning Signals
              </span>
              <div className="text-sm font-bold text-[var(--identifier)] flex items-center gap-2">
                <Activity className="w-4 h-4 text-[var(--identifier)]" />
                {evidenceCount} SIGNALS
              </div>
              <span className="text-[11px] text-[var(--text-muted)] block">Active findings</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
