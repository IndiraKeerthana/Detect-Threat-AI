import React, { useState } from 'react';
import {
  Copy,
  Check,
  ArrowLeft,
  ChevronDown,
  Download,
  Loader2,
  ShieldCheck,
  AlertTriangle,
  ShieldAlert,
} from 'lucide-react';
import type { EmailAnalysisResponse } from '../../types/investigation';
import type { CaseRecord, CaseStatus } from '../../services/caseStore';
import { formatISTTimestamp } from '../../utils/dateFormatter';
import { downloadForensicReportPdf } from '../../services/api';

interface InvestigationHeaderProps {
  data: EmailAnalysisResponse;
  caseId?: string;
  caseRecord?: CaseRecord;
  onStatusChange?: (newStatus: CaseStatus) => void;
  onViewReport?: () => void;
  onNavigateBack?: () => void;
}

export const InvestigationHeader: React.FC<InvestigationHeaderProps> = ({
  data,
  caseId = 'CASE-UNASSIGNED',
  caseRecord,
  onStatusChange,
  onNavigateBack,
}) => {
  const [copied, setCopied] = useState(false);
  const [statusDropdownOpen, setStatusDropdownOpen] = useState(false);
  const [downloading, setDownloading] = useState(false);

  const activeId = caseRecord?.id || caseId;
  const currentStatus: CaseStatus = caseRecord?.status || 'OPEN';
  const riskLevel = (caseRecord?.severity || data.risk_assessment?.level || data.ai_investigation?.risk_level || 'low').toLowerCase();
  const score = caseRecord?.riskScore ?? (data.risk_assessment?.score ?? 0);
  const createdTimestampIST = formatISTTimestamp(caseRecord?.createdAt, 'Unrecorded');

  const copyMessageId = () => {
    if (data.message_id) {
      navigator.clipboard.writeText(data.message_id);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    }
  };

  const handleDownloadReport = async () => {
    setDownloading(true);
    try {
      const blob = await downloadForensicReportPdf(data, activeId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `Email_Safety_Report_${activeId}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch {
      window.print();
    } finally {
      setDownloading(false);
    }
  };

  const statuses: CaseStatus[] = ['OPEN', 'IN REVIEW', 'CONTAINED', 'CLOSED'];

  const handleSelectStatus = (st: CaseStatus) => {
    if (onStatusChange) {
      onStatusChange(st);
    }
    setStatusDropdownOpen(false);
  };

  // Verdict Banner configuration
  const getVerdictConfig = () => {
    if (score >= 70 || riskLevel === 'critical' || riskLevel === 'high') {
      return {
        bannerClass: 'bg-rose-500/10 border-rose-500/20 text-rose-400',
        icon: ShieldAlert,
        headline: '🚨 Your email looks suspicious',
        badgeClass: 'bg-rose-500/20 text-rose-300 border-rose-500/30',
        badgeText: `High Risk (${score}/100)`,
      };
    }
    if (score >= 40 || riskLevel === 'medium') {
      return {
        bannerClass: 'bg-amber-500/10 border-amber-500/20 text-amber-400',
        icon: AlertTriangle,
        headline: '⚠️ Some warning signs were found',
        badgeClass: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
        badgeText: `Moderate Warning (${score}/100)`,
      };
    }
    return {
      bannerClass: 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400',
      icon: ShieldCheck,
      headline: '✅ This email appears safe',
      badgeClass: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
      badgeText: `Low Risk (${score}/100)`,
    };
  };

  const verdict = getVerdictConfig();
  const VerdictIcon = verdict.icon;

  return (
    <div className="surface-card p-5 border border-[var(--border-subtle)] rounded-2xl space-y-4 font-sans">
      {/* Navigation & Actions Top Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-[var(--border-subtle)]">
        <div className="flex items-center space-x-3">
          {onNavigateBack && (
            <button
              type="button"
              onClick={onNavigateBack}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--surface-elevated)] hover:bg-[var(--surface-hover)] text-[var(--text-muted)] hover:text-[var(--text)] border border-[var(--border-subtle)] text-xs transition-colors cursor-pointer"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Back to Overview</span>
            </button>
          )}

          <div className="flex items-center space-x-2 text-xs font-mono">
            <span className="px-2.5 py-0.5 rounded-md bg-[var(--surface-elevated)] border border-[var(--border-subtle)] text-[var(--identifier)] font-bold">
              {activeId}
            </span>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2.5 text-xs">
          {/* Case Status Dropdown */}
          <div className="relative">
            <button
              type="button"
              onClick={() => setStatusDropdownOpen(!statusDropdownOpen)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--surface-elevated)] hover:bg-[var(--surface-hover)] border border-[var(--border-subtle)] text-xs text-[var(--text)] font-medium transition-colors cursor-pointer"
            >
              <span className="w-2 h-2 rounded-full bg-[var(--identifier)]" />
              <span>Status: {currentStatus}</span>
              <ChevronDown className="w-3.5 h-3.5 opacity-70" />
            </button>

            {statusDropdownOpen && (
              <div className="absolute right-0 mt-1 w-44 bg-[var(--surface)] border border-[var(--border)] rounded-xl shadow-xl py-1 z-30 text-xs">
                <div className="px-3 py-1 text-[11px] text-[var(--text-dim)] uppercase border-b border-[var(--border-subtle)] font-mono">
                  Update Status
                </div>
                {statuses.map((st) => (
                  <button
                    key={st}
                    type="button"
                    onClick={() => handleSelectStatus(st)}
                    className={`w-full text-left px-3 py-1.5 flex items-center justify-between hover:bg-[var(--surface-hover)] transition-colors cursor-pointer ${
                      currentStatus === st ? 'text-[var(--text)] font-bold' : 'text-[var(--text-muted)]'
                    }`}
                  >
                    <span>{st}</span>
                    {currentStatus === st && <Check className="w-3.5 h-3.5 text-emerald-400" />}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Download PDF Report */}
          <button
            type="button"
            onClick={handleDownloadReport}
            disabled={downloading}
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-[var(--surface-elevated)] hover:bg-[var(--surface-hover)] text-[var(--text)] border border-[var(--border-subtle)] text-xs font-semibold transition-colors cursor-pointer disabled:opacity-50"
          >
            {downloading ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Download className="w-3.5 h-3.5 text-[var(--identifier)]" />
            )}
            <span>{downloading ? 'Downloading...' : 'Download PDF Report'}</span>
          </button>
        </div>
      </div>

      {/* Top Verdict Banner */}
      <div className={`p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${verdict.bannerClass}`}>
        <div className="flex items-center gap-3">
          <VerdictIcon className="w-6 h-6 shrink-0" />
          <div>
            <h2 className="text-lg font-bold tracking-tight leading-snug">{verdict.headline}</h2>
            <p className="text-xs opacity-90 font-mono">Subject: {caseRecord?.title || data.subject || '(No Subject Provided)'}</p>
          </div>
        </div>

        <span className={`px-3 py-1 rounded-full text-xs font-bold border uppercase shrink-0 font-mono ${verdict.badgeClass}`}>
          {verdict.badgeText}
        </span>
      </div>

      {/* Email Header Details Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 bg-[var(--surface-subtle)] p-4 rounded-xl border border-[var(--border-subtle)] text-xs">
        <div className="space-y-1.5">
          <div>
            <span className="text-[11px] text-[var(--text-dim)] uppercase font-mono block">From (Sender):</span>
            <span className="font-mono text-[var(--identifier)] font-semibold break-all">{data.from || 'Unspecified'}</span>
          </div>
          <div>
            <span className="text-[11px] text-[var(--text-dim)] uppercase font-mono block">To (Recipient):</span>
            <span className="font-mono text-[var(--text)] break-all">{data.to || 'Unspecified'}</span>
          </div>
        </div>

        <div className="space-y-1.5">
          <div>
            <span className="text-[11px] text-[var(--text-dim)] uppercase font-mono block">Subject Line:</span>
            <span className="text-[var(--text)] font-medium">{data.subject || '(No Subject)'}</span>
          </div>
          <div className="flex items-center justify-between pt-1">
            <span className="text-[11px] text-[var(--text-dim)] font-mono">Date Checked: {createdTimestampIST}</span>
            {data.message_id && (
              <button
                type="button"
                onClick={copyMessageId}
                className="text-[11px] text-[var(--text-muted)] hover:text-[var(--text)] font-mono inline-flex items-center gap-1 cursor-pointer"
              >
                {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copied ? 'Copied' : 'Copy Email ID'}</span>
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
