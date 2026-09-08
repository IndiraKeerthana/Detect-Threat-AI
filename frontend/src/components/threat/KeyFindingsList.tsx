import { FileSearch } from 'lucide-react';
import type { SecurityIndicator, AIFinding } from '../../types/investigation';

interface KeyFindingsListProps {
  indicators?: SecurityIndicator[];
  aiFindings?: AIFinding[];
}

export const KeyFindingsList: React.FC<KeyFindingsListProps> = ({
  indicators = [],
  aiFindings = [],
}) => {
  const combinedCount = indicators.length + aiFindings.length;

  if (combinedCount === 0) {
    return (
      <div className="surface-card p-5 border border-[#1e2430] text-center text-xs text-[#64748b] font-mono">
        NO SECURITY FINDINGS IDENTIFIED
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
    <div className="surface-card p-5 border border-[#1e2430] space-y-3">
      <div className="flex items-center justify-between pb-3 border-b border-[#1e2430]">
        <div className="flex items-center space-x-2">
          <FileSearch className="w-4 h-4 text-[#8b5cf6]" />
          <h3 className="text-sm font-semibold text-[#f1f5f9] tracking-tight">
            Key Forensic Findings
          </h3>
        </div>
        <span className="text-xs font-mono text-[#64748b]">
          TOTAL FINDINGS: <span className="text-[#f1f5f9]">{combinedCount}</span>
        </span>
      </div>

      <div className="space-y-2">
        {/* Render Security Indicators */}
        {indicators.map((ind) => (
          <div
            key={ind.code}
            className="bg-[#12151b] border border-[#1e2430] hover:border-[#2a3242] p-3 rounded text-xs space-y-1.5 transition-colors"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <span className={`px-1.5 py-0.2 rounded text-[10px] font-mono font-semibold border ${getSeverityBadge(ind.severity)}`}>
                  {ind.severity.toUpperCase()}
                </span>
                <span className="font-semibold text-[#f1f5f9]">{ind.title}</span>
              </div>
              <span className="text-[10px] font-mono text-[#64748b]">
                {ind.category.toUpperCase()}
              </span>
            </div>

            <p className="text-[#94a3b8] text-[11px] leading-relaxed">
              {ind.explanation}
            </p>

            {ind.evidence && ind.evidence.length > 0 && (
              <div className="flex flex-wrap gap-1.5 pt-1">
                {ind.evidence.map((ev, i) => (
                  <span
                    key={i}
                    className="font-mono text-[10px] px-1.5 py-0.2 bg-[#0c0e12] border border-[#1e2430] rounded text-[#67e8f9]"
                  >
                    {ev}
                  </span>
                ))}
              </div>
            )}
          </div>
        ))}

        {/* Render AI Agent Findings if any complementary */}
        {aiFindings.map((finding, idx) => (
          <div
            key={`ai-${idx}`}
            className="bg-[#171424] border border-[#432474]/50 p-3 rounded text-xs space-y-1.5"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <span className={`px-1.5 py-0.2 rounded text-[10px] font-mono font-semibold border ${getSeverityBadge(finding.severity)}`}>
                  {finding.severity.toUpperCase()}
                </span>
                <span className="font-semibold text-[#f1f5f9]">{finding.title}</span>
              </div>
              <span className="text-[10px] font-mono text-[#c4b5fd] bg-[#1e1533] px-1 rounded border border-[#432474]">
                AI AGENT
              </span>
            </div>

            <p className="text-[#94a3b8] text-[11px] leading-relaxed">
              {finding.explanation}
            </p>

            {finding.evidence && finding.evidence.length > 0 && (
              <div className="flex flex-wrap gap-1.5 pt-1">
                {finding.evidence.map((ev, i) => (
                  <span
                    key={i}
                    className="font-mono text-[10px] px-1.5 py-0.2 bg-[#0c0e12] border border-[#1e2430] rounded text-[#c4b5fd]"
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
  );
};
