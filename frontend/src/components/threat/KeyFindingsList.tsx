import React, { useState } from 'react';
import { AlertCircle, AlertTriangle, CheckCircle, ShieldAlert, ChevronDown, ChevronUp } from 'lucide-react';
import type { SecurityIndicator } from '../../types/investigation';
import { SectionHeader } from '../investigation/SectionHeader';

interface KeyFindingsListProps {
  indicators?: SecurityIndicator[];
}

export const KeyFindingsList: React.FC<KeyFindingsListProps> = ({
  indicators = [],
}) => {
  const [expandedCodes, setExpandedCodes] = useState<Record<string, boolean>>({});

  const toggleExpand = (code: string) => {
    setExpandedCodes((prev) => ({ ...prev, [code]: !prev[code] }));
  };

  const getSeverityPill = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
        return {
          icon: ShieldAlert,
          badgeClass: 'text-[var(--severity-critical)] bg-[var(--surface-elevated)] border-[var(--border-subtle)]',
          indicatorBar: 'bg-[var(--severity-critical)]',
        };
      case 'high':
        return {
          icon: AlertCircle,
          badgeClass: 'text-[var(--severity-critical)] bg-[var(--surface-elevated)] border-[var(--border-subtle)]',
          indicatorBar: 'bg-[var(--severity-critical)]',
        };
      case 'medium':
        return {
          icon: AlertTriangle,
          badgeClass: 'text-[var(--severity-medium)] bg-[var(--surface-elevated)] border-[var(--border-subtle)]',
          indicatorBar: 'bg-[var(--severity-medium)]',
        };
      default:
        return {
          icon: CheckCircle,
          badgeClass: 'text-[var(--severity-low)] bg-[var(--surface-elevated)] border-[var(--border-subtle)]',
          indicatorBar: 'bg-[var(--severity-low)]',
        };
    }
  };

  return (
    <div className="surface-card p-5 border border-[var(--border-subtle)] space-y-4">
      {/* Section Header */}
      <SectionHeader
        index="02"
        title="Key forensic findings"
        subtitle="Ranked deterministic security indicators and anomalies detected across email headers, payload, and content."
        action={
          <span className="text-xs font-mono text-[var(--text-dim)]">
            ACTIVE FINDINGS: <strong className="text-[var(--text)]">{indicators.length}</strong>
          </span>
        }
      />

      {/* Single Consolidated Container with Hairline Rows */}
      {indicators.length === 0 ? (
        <div className="p-6 text-center text-xs font-mono text-[var(--text-dim)] border border-[var(--border-subtle)] rounded bg-[var(--surface-subtle)]">
          NO DETERMINISTIC FORENSIC ANOMALIES DETECTED
        </div>
      ) : (
        <div className="border border-[var(--border-subtle)] rounded bg-[var(--surface-subtle)] divide-y divide-[var(--border-subtle)] overflow-hidden">
          {indicators.map((ind) => {
            const pill = getSeverityPill(ind.severity);
            const Icon = pill.icon;
            const isExpanded = Boolean(expandedCodes[ind.code]);

            return (
              <div
                key={ind.code}
                className="p-3.5 hover:bg-[var(--surface-hover)] transition-colors relative"
              >
                {/* Left Severity Accent Bar */}
                <div className={`absolute left-0 top-0 bottom-0 w-1 ${pill.indicatorBar}`} />

                <div className="pl-2.5 space-y-1.5">
                  {/* Header Row: Severity Badge + Title + Category + Expand Button */}
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center space-x-2.5 flex-1 min-w-0">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border flex items-center gap-1 shrink-0 ${pill.badgeClass}`}
                      >
                        <Icon className="w-3 h-3" />
                        {ind.severity}
                      </span>

                      <span className="font-semibold text-xs text-[var(--text)] tracking-tight truncate">
                        {ind.title}
                      </span>
                    </div>

                    <div className="flex items-center space-x-2 shrink-0">
                      <span className="text-[10px] font-mono text-[var(--text-dim)] bg-[var(--surface)] border border-[var(--border-subtle)] px-1.5 py-0.5 rounded hidden sm:inline">
                        {ind.category.toUpperCase()} · {ind.code}
                      </span>
                      <button
                        type="button"
                        onClick={() => toggleExpand(ind.code)}
                        className="p-1 rounded text-[var(--text-dim)] hover:text-[var(--text)] hover:bg-[var(--surface-elevated)] transition-colors"
                        title={isExpanded ? 'Collapse evidence' : 'Expand evidence'}
                      >
                        {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>

                  {/* Short Explanation */}
                  <p className="text-[11px] text-[var(--text-muted)] leading-relaxed font-sans">
                    {ind.explanation}
                  </p>

                  {/* Expandable Evidence / Observables */}
                  {isExpanded && ind.evidence && ind.evidence.length > 0 && (
                    <div className="flex flex-wrap items-center gap-1.5 pt-2 border-t border-[var(--border-subtle)] mt-2">
                      <span className="text-[10px] font-mono text-[var(--text-dim)]">OBSERVABLE EVIDENCE:</span>
                      {ind.evidence.map((ev, i) => (
                        <span
                          key={i}
                          className="font-mono text-[10px] px-2 py-0.5 bg-[var(--surface)] border border-[var(--border-subtle)] rounded text-[var(--identifier)] select-all"
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
