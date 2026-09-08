import React from 'react';
import { AlertCircle, AlertTriangle, CheckCircle, ShieldAlert } from 'lucide-react';
import type { SecurityIndicator, AIFinding } from '../../types/investigation';
import { SectionHeader } from '../investigation/SectionHeader';

interface KeyFindingsListProps {
  indicators?: SecurityIndicator[];
  aiFindings?: AIFinding[];
}

export const KeyFindingsList: React.FC<KeyFindingsListProps> = ({
  indicators = [],
  aiFindings = [],
}) => {
  const combinedCount = indicators.length + aiFindings.length;

  const getSeverityPill = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
        return {
          icon: ShieldAlert,
          badgeClass: 'text-[#fca5a5] bg-[#261114] border-[#5c1d24]',
          indicatorBar: 'bg-[#ef4444]',
        };
      case 'high':
        return {
          icon: AlertCircle,
          badgeClass: 'text-[#fca5a5] bg-[#261114] border-[#5c1d24]',
          indicatorBar: 'bg-[#ef4444]',
        };
      case 'medium':
        return {
          icon: AlertTriangle,
          badgeClass: 'text-[#fcd34d] bg-[#261b0c] border-[#5c3c12]',
          indicatorBar: 'bg-[#f59e0b]',
        };
      default:
        return {
          icon: CheckCircle,
          badgeClass: 'text-[#6ee7b7] bg-[#0e241b] border-[#164e3b]',
          indicatorBar: 'bg-[#10b981]',
        };
    }
  };

  return (
    <div className="surface-card p-6 border border-[#1e2430] space-y-4">
      {/* Section Header */}
      <SectionHeader
        index="03A"
        tag="EVIDENCE LEDGER"
        title="Key Forensic Findings"
        subtitle="Ranked security indicators and anomalies detected across email headers, payload, and content"
        action={
          <span className="text-xs font-mono text-[#64748b]">
            ACTIVE FINDINGS: <strong className="text-[#f1f5f9]">{combinedCount}</strong>
          </span>
        }
      />

      {/* High-density Forensic Ledger */}
      <div className="space-y-2">
        {indicators.map((ind) => {
          const pill = getSeverityPill(ind.severity);
          const Icon = pill.icon;

          return (
            <div
              key={ind.code}
              className="bg-[#12151b] border border-[#1e2430] hover:border-[#2a3242] p-3.5 rounded-md transition-colors relative overflow-hidden group"
            >
              {/* Left Accent Indicator Bar */}
              <div className={`absolute left-0 top-0 bottom-0 w-1 ${pill.indicatorBar}`} />

              <div className="pl-2 space-y-1.5">
                {/* Header Row: Severity + Title + Category */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1.5">
                  <div className="flex items-center space-x-2">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border flex items-center gap-1 ${pill.badgeClass}`}
                    >
                      <Icon className="w-3 h-3" />
                      {ind.severity}
                    </span>

                    <span className="font-semibold text-xs text-[#f1f5f9] tracking-tight">
                      {ind.title}
                    </span>
                  </div>

                  <span className="text-[10px] font-mono text-[#64748b] bg-[#171b23] border border-[#2a3242] px-1.5 py-0.5 rounded self-start sm:self-auto">
                    {ind.category.toUpperCase()} // {ind.code}
                  </span>
                </div>

                {/* Explanation */}
                <p className="text-[11px] text-[#94a3b8] leading-relaxed font-sans">
                  {ind.explanation}
                </p>

                {/* Evidence Chips */}
                {ind.evidence && ind.evidence.length > 0 && (
                  <div className="flex flex-wrap items-center gap-1.5 pt-1">
                    <span className="text-[10px] font-mono text-[#64748b]">OBSERVABLE:</span>
                    {ind.evidence.map((ev, i) => (
                      <span
                        key={i}
                        className="font-mono text-[10px] px-1.5 py-0.2 bg-[#0a0c10] border border-[#1e2430] rounded text-[#67e8f9]"
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

        {/* AI Complementary Findings */}
        {aiFindings.map((finding, idx) => {
          const pill = getSeverityPill(finding.severity);

          return (
            <div
              key={`ai-${idx}`}
              className="bg-[#151221] border border-[#432474]/60 hover:border-[#8b5cf6] p-3.5 rounded-md transition-colors relative overflow-hidden group"
            >
              <div className="absolute left-0 top-0 bottom-0 w-1 bg-[#8b5cf6]" />

              <div className="pl-2 space-y-1.5">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1.5">
                  <div className="flex items-center space-x-2">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${pill.badgeClass}`}
                    >
                      {finding.severity}
                    </span>

                    <span className="font-semibold text-xs text-[#f1f5f9] tracking-tight">
                      {finding.title}
                    </span>
                  </div>

                  <span className="text-[10px] font-mono text-[#c4b5fd] bg-[#1e1533] border border-[#432474] px-1.5 py-0.5 rounded self-start sm:self-auto">
                    AUTONOMOUS AGENT FINDING
                  </span>
                </div>

                <p className="text-[11px] text-[#94a3b8] leading-relaxed font-sans">
                  {finding.explanation}
                </p>

                {finding.evidence && finding.evidence.length > 0 && (
                  <div className="flex flex-wrap items-center gap-1.5 pt-1">
                    <span className="text-[10px] font-mono text-[#64748b]">OBSERVABLE:</span>
                    {finding.evidence.map((ev, i) => (
                      <span
                        key={i}
                        className="font-mono text-[10px] px-1.5 py-0.2 bg-[#0a0c10] border border-[#1e2430] rounded text-[#c4b5fd]"
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
    </div>
  );
};
