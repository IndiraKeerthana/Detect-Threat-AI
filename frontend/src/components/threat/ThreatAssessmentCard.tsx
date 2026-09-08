import { Gauge } from 'lucide-react';
import type { RiskAssessment } from '../../types/investigation';

interface ThreatAssessmentCardProps {
  assessment?: RiskAssessment | null;
}

export const ThreatAssessmentCard: React.FC<ThreatAssessmentCardProps> = ({ assessment }) => {
  if (!assessment) {
    return (
      <div className="surface-card p-5 border border-[#1e2430] text-center text-xs text-[#64748b] font-mono">
        NO DETERMINISTIC THREAT ASSESSMENT AVAILABLE
      </div>
    );
  }

  const getSeverityBadge = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
        return 'text-[#fca5a5] bg-[#261114] border-[#5c1d24]';
      case 'high':
        return 'text-[#fca5a5] bg-[#261114] border-[#5c1d24]';
      case 'medium':
        return 'text-[#fcd34d] bg-[#261b0c] border-[#5c3c12]';
      default:
        return 'text-[#6ee7b7] bg-[#0e241b] border-[#164e3b]';
    }
  };

  return (
    <div className="surface-card p-5 border border-[#1e2430] space-y-4">
      {/* Title & Score */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-3 border-b border-[#1e2430]">
        <div className="flex items-center space-x-2.5">
          <div className="w-7 h-7 rounded bg-[#171b23] border border-[#2a3242] flex items-center justify-center text-[#ef4444]">
            <Gauge className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-[#f1f5f9] tracking-tight">
              Deterministic Threat Assessment
            </h3>
            <p className="text-[11px] text-[#64748b] font-mono">
              Calculated from RFC verification, correlation graph & telemetry
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-4">
          <div className="text-right">
            <div className="text-[10px] font-mono text-[#64748b] uppercase">Forensic Score</div>
            <div className="text-xl font-mono font-bold text-[#ef4444]">
              {assessment.score}
              <span className="text-xs text-[#64748b] font-normal">/100</span>
            </div>
          </div>
          <div className="text-right">
            <div className="text-[10px] font-mono text-[#64748b] uppercase">Classification</div>
            <div className="text-sm font-mono uppercase font-semibold text-[#f1f5f9]">
              {assessment.classification}
            </div>
          </div>
        </div>
      </div>

      {/* Rationale */}
      <div className="text-xs text-[#94a3b8] bg-[#0f1217] border border-[#1e2430] p-3 rounded leading-relaxed">
        <span className="font-mono text-[#64748b] uppercase text-[10px] block mb-1">
          Scoring Rationale
        </span>
        {assessment.rationale}
      </div>

      {/* Contributing Risk Factors Breakdown */}
      <div className="space-y-2">
        <div className="flex items-center justify-between text-[11px] font-mono text-[#64748b]">
          <span>CONTRIBUTING RISK FACTORS ({assessment.factors.length})</span>
          <span>WEIGHT CONTRIBUTION</span>
        </div>

        <div className="space-y-1.5">
          {assessment.factors.map((factor) => (
            <div
              key={factor.code}
              className="bg-[#171b23] border border-[#2a3242] p-3 rounded text-xs space-y-1 hover:border-[#3e485e] transition-colors"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <span className={`px-1.5 py-0.2 rounded text-[10px] font-mono font-semibold border ${getSeverityBadge(factor.severity)}`}>
                    {factor.severity.toUpperCase()}
                  </span>
                  <span className="font-medium text-[#f1f5f9]">{factor.title}</span>
                </div>
                <span className="font-mono text-[#f1f5f9] text-[11px]">
                  +{factor.contribution} pts
                </span>
              </div>
              <p className="text-[11px] text-[#94a3b8]">{factor.explanation}</p>
              {factor.evidence.length > 0 && (
                <div className="flex flex-wrap gap-1.5 pt-1">
                  {factor.evidence.map((ev, i) => (
                    <span
                      key={i}
                      className="px-1.5 py-0.2 rounded bg-[#0f1217] border border-[#1e2430] font-mono text-[10px] text-[#64748b]"
                    >
                      {ev}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
