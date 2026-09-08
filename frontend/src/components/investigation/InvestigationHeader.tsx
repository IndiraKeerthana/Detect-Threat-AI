import React from 'react';
import { Copy, Check } from 'lucide-react';
import type { EmailAnalysisResponse } from '../../types/investigation';

interface InvestigationHeaderProps {
  data: EmailAnalysisResponse;
}

export const InvestigationHeader: React.FC<InvestigationHeaderProps> = ({ data }) => {
  const [copied, setCopied] = React.useState(false);

  const riskLevel = data.risk_assessment?.level || data.ai_investigation?.risk_level || 'unknown';
  const classification = data.risk_assessment?.classification || data.ai_investigation?.classification || 'unclassified';
  const score = data.risk_assessment?.score ?? 0;

  const copyMessageId = () => {
    if (data.message_id) {
      navigator.clipboard.writeText(data.message_id);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const getRiskBadgeClass = (level: string) => {
    switch (level.toLowerCase()) {
      case 'critical':
        return 'badge-critical';
      case 'high':
        return 'badge-critical';
      case 'medium':
        return 'badge-warning';
      case 'low':
      case 'benign':
        return 'badge-success';
      default:
        return 'badge-neutral';
    }
  };

  return (
    <div className="surface-card p-5 border border-[#1e2430]">
      {/* Top Meta Line: Badges & Actions */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-[#1e2430]">
        <div className="flex flex-wrap items-center gap-2">
          <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-semibold uppercase tracking-wider ${getRiskBadgeClass(riskLevel)}`}>
            {riskLevel} RISK ({score}/100)
          </span>

          <span className="px-2 py-0.5 rounded text-xs font-mono uppercase bg-[#171b23] border border-[#2a3242] text-[#c4b5fd]">
            {classification}
          </span>

          {data.ai_investigation?.source === 'ai_agent' && (
            <span className="px-2 py-0.5 rounded text-xs font-mono bg-[#1e1533] border border-[#432474] text-[#c4b5fd] flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-[#8b5cf6] animate-pulse" />
              GROQ AUTONOMOUS ({data.ai_investigation.iterations} ITERATIONS)
            </span>
          )}
        </div>

        <div className="text-xs font-mono text-[#64748b]">
          CASE ID: <span className="text-[#f1f5f9]">SIH-2026-LIVE</span>
        </div>
      </div>

      {/* Main Subject & Sender */}
      <div className="mt-4 space-y-3">
        <h1 className="text-xl font-semibold text-[#f1f5f9] tracking-tight">
          {data.subject || '(No Subject Provided)'}
        </h1>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 text-xs">
          <div className="bg-[#0f1217] border border-[#1e2430] p-2.5 rounded">
            <span className="text-[10px] font-mono text-[#64748b] block uppercase">From (RFC 5322)</span>
            <span className="font-mono text-[#f1f5f9] truncate block mt-0.5" title={data.from || ''}>
              {data.from || 'None'}
            </span>
          </div>

          <div className="bg-[#0f1217] border border-[#1e2430] p-2.5 rounded">
            <span className="text-[10px] font-mono text-[#64748b] block uppercase">Recipient (To)</span>
            <span className="font-mono text-[#f1f5f9] truncate block mt-0.5" title={data.to || ''}>
              {data.to || 'None'}
            </span>
          </div>

          <div className="bg-[#0f1217] border border-[#1e2430] p-2.5 rounded">
            <span className="text-[10px] font-mono text-[#64748b] block uppercase">Date Received</span>
            <span className="font-mono text-[#f1f5f9] truncate block mt-0.5">
              {data.date || 'Unspecified'}
            </span>
          </div>
        </div>

        {/* Secondary Routing Details */}
        <div className="flex flex-wrap items-center gap-4 text-xs font-mono text-[#94a3b8] pt-1">
          {data.reply_to && (
            <div>
              <span className="text-[#64748b]">Reply-To:</span>{' '}
              <span className="text-[#fca5a5]">{data.reply_to}</span>
            </div>
          )}
          {data.return_path && (
            <div>
              <span className="text-[#64748b]">Return-Path:</span>{' '}
              <span className="text-[#f1f5f9]">{data.return_path}</span>
            </div>
          )}
          {data.message_id && (
            <div className="flex items-center gap-1.5">
              <span className="text-[#64748b]">Message-ID:</span>{' '}
              <span className="text-[#f1f5f9] max-w-xs truncate">{data.message_id}</span>
              <button
                onClick={copyMessageId}
                className="text-[#64748b] hover:text-[#f1f5f9] p-0.5 rounded"
                title="Copy Message-ID"
              >
                {copied ? <Check className="w-3 h-3 text-[#10b981]" /> : <Copy className="w-3 h-3" />}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
