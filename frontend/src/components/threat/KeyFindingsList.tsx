import React from 'react';
import { AlertCircle, AlertTriangle, CheckCircle, ShieldAlert } from 'lucide-react';
import type { SecurityIndicator } from '../../types/investigation';
import { SectionHeader } from '../investigation/SectionHeader';

interface KeyFindingsListProps {
  indicators?: SecurityIndicator[];
}

export const KeyFindingsList: React.FC<KeyFindingsListProps> = ({ indicators = [] }) => {
  const getSeverityPill = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
        return {
          icon: ShieldAlert,
          badgeClass: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
          indicatorBar: 'bg-rose-500',
        };
      case 'high':
        return {
          icon: AlertCircle,
          badgeClass: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
          indicatorBar: 'bg-rose-500',
        };
      case 'medium':
        return {
          icon: AlertTriangle,
          badgeClass: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
          indicatorBar: 'bg-amber-500',
        };
      default:
        return {
          icon: CheckCircle,
          badgeClass: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
          indicatorBar: 'bg-emerald-500',
        };
    }
  };

  return (
    <div className="surface-card p-5 border border-[var(--border-subtle)] rounded-2xl space-y-4 font-sans">
      {/* Section Header */}
      <SectionHeader
        index={2}
        title="Why This Email Was Flagged"
        subtitle="Key warning signs and security findings detected in the email."
        action={
          <span className="text-xs text-[var(--text-muted)] font-mono">
            Active Warning Signals: <strong className="text-[var(--text)]">{indicators.length}</strong>
          </span>
        }
      />

      {/* Directly Visible Findings List */}
      {indicators.length === 0 ? (
        <div className="p-6 text-center text-xs text-[var(--text-muted)] border border-[var(--border-subtle)] rounded-xl bg-[var(--surface-subtle)]">
          No suspicious indicators or warning signs were detected in this email.
        </div>
      ) : (
        <div className="border border-[var(--border-subtle)] rounded-xl bg-[var(--surface-subtle)] divide-y divide-[var(--border-subtle)] overflow-hidden">
          {indicators.map((ind) => {
            const pill = getSeverityPill(ind.severity);
            const Icon = pill.icon;

            return (
              <div
                key={ind.code}
                className="p-4 hover:bg-[var(--surface-hover)] transition-colors relative space-y-1.5"
              >
                {/* Left Severity Accent Bar */}
                <div className={`absolute left-0 top-0 bottom-0 w-1 ${pill.indicatorBar}`} />

                <div className="pl-3 space-y-1.5">
                  {/* Header Row */}
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center space-x-2.5 flex-1 min-w-0">
                      <span
                        className={`px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase border flex items-center gap-1 shrink-0 ${pill.badgeClass}`}
                      >
                        <Icon className="w-3.5 h-3.5" />
                        {ind.severity}
                      </span>

                      <span className="font-semibold text-sm text-[var(--text)] tracking-tight truncate">
                        {ind.title}
                      </span>
                    </div>

                    <span className="text-[11px] font-mono text-[var(--text-dim)] bg-[var(--surface-elevated)] border border-[var(--border-subtle)] px-2 py-0.5 rounded-md hidden sm:inline">
                      {ind.category}
                    </span>
                  </div>

                  {/* Human-Readable Explanation */}
                  <p className="text-xs text-[var(--text-muted)] leading-relaxed">
                    {ind.explanation}
                  </p>

                  {/* Observed Evidence */}
                  {ind.evidence && ind.evidence.length > 0 && (
                    <div className="flex flex-wrap items-center gap-1.5 pt-1">
                      <span className="text-[10px] font-mono text-[var(--text-dim)] uppercase">Evidence:</span>
                      {ind.evidence.map((ev, i) => (
                        <span
                          key={i}
                          className="font-mono text-[11px] px-2 py-0.5 bg-[var(--surface)] border border-[var(--border-subtle)] rounded-md text-[var(--identifier)] select-all"
                        >
                          {ev}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
