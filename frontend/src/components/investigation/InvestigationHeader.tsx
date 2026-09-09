import React, { useState } from 'react';
import {
  Copy,
  Check,
  ArrowLeft,
  ShieldAlert,
  Fingerprint,
  FileText,
  ChevronDown,
  Download,
  Loader2,
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
  onViewReport,
  onNavigateBack,
}) => {
  const [copied, setCopied] = useState(false);
  const [statusDropdownOpen, setStatusDropdownOpen] = useState(false);
  const [downloading, setDownloading] = useState(false);

  const activeId = caseRecord?.id || caseId;
  const currentStatus: CaseStatus = caseRecord?.status || 'OPEN';
  const riskLevel = caseRecord?.severity || data.risk_assessment?.level || data.ai_investigation?.risk_level || 'low';
  const classification = caseRecord?.classification || data.risk_assessment?.classification || data.ai_investigation?.classification || 'unclassified';
  const score = caseRecord?.riskScore ?? (data.risk_assessment?.score ?? 0);
  const confidence = caseRecord?.confidence || data.confidence?.level || 'unknown';
  const createdTimestamp = caseRecord?.createdAt || 'Unrecorded';
  const updatedTimestamp = caseRecord?.updatedAt || 'Unrecorded';
  const createdTimestampIST = formatISTTimestamp(caseRecord?.createdAt, 'Unrecorded');
  const updatedTimestampIST = formatISTTimestamp(caseRecord?.updatedAt, 'Unrecorded');

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
      a.download = `Forensic_Investigation_Report_${activeId}.pdf`;
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

  const getRiskBadgeClass = (level: string) => {
    switch (level.toLowerCase()) {
      case 'critical':
      case 'high':
        return 'text-[var(--severity-critical)] bg-[var(--surface-elevated)] border-[var(--border-subtle)]';
      case 'medium':
        return 'text-[var(--severity-medium)] bg-[var(--surface-elevated)] border-[var(--border-subtle)]';
      case 'low':
      case 'benign':
        return 'text-[var(--severity-low)] bg-[var(--surface-elevated)] border-[var(--border-subtle)]';
      default:
        return 'text-[var(--text-muted)] bg-[var(--surface-elevated)] border-[var(--border-subtle)]';
    }
  };

  const getStatusColor = (st: CaseStatus) => {
    switch (st) {
      case 'OPEN':
        return 'text-[var(--identifier)] bg-[var(--surface-elevated)] border-[var(--border-subtle)]';
      case 'IN REVIEW':
        return 'text-[var(--severity-medium)] bg-[var(--surface-elevated)] border-[var(--border-subtle)]';
      case 'CONTAINED':
        return 'text-[var(--state-pass)] bg-[var(--surface-elevated)] border-[var(--border-subtle)]';
      case 'CLOSED':
      default:
        return 'text-[var(--text-muted)] bg-[var(--surface-elevated)] border-[var(--border-subtle)]';
    }
  };

  const statuses: CaseStatus[] = ['OPEN', 'IN REVIEW', 'CONTAINED', 'CLOSED'];

  const handleSelectStatus = (st: CaseStatus) => {
    if (onStatusChange) {
      onStatusChange(st);
    }
    setStatusDropdownOpen(false);
  };

  return (
    <div className="surface-card p-5 border border-[var(--border-subtle)] space-y-4">
      {/* 1. Top Action & Navigation Row */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-[var(--border-subtle)]">
        <div className="flex items-center space-x-3">
          {onNavigateBack && (
            <button
              type="button"
              onClick={onNavigateBack}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-[var(--surface-elevated)] hover:bg-[var(--surface-hover)] text-[var(--text-muted)] hover:text-[var(--text)] border border-[var(--border-subtle)] text-xs font-mono transition-colors cursor-pointer"
              title="Return to Ingestion Console"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Overview</span>
            </button>
          )}

          <div className="flex items-center space-x-2 text-xs font-mono">
            <span className="px-2 py-0.5 rounded bg-[var(--surface-elevated)] border border-[var(--border-subtle)] text-[var(--identifier)] font-bold">
              {activeId}
            </span>
            <span className="text-[var(--text-dim)]">/</span>
            <span className="text-[var(--text-muted)]">Investigation</span>
          </div>
        </div>

        {/* Status Workflow Selector, View Report & Risk Badge */}
        <div className="flex flex-wrap items-center gap-2.5 text-xs font-mono">
          {/* Interactive Case Status Control */}
          <div className="relative">
            <button
              type="button"
              onClick={() => setStatusDropdownOpen(!statusDropdownOpen)}
              className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded border text-xs font-mono font-semibold transition-colors cursor-pointer ${getStatusColor(
                currentStatus
              )}`}
              title="Change Case Workflow Status"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-current" />
              <span>STATUS: {currentStatus}</span>
              <ChevronDown className="w-3 h-3 opacity-70" />
            </button>

            {statusDropdownOpen && (
              <div className="absolute right-0 mt-1 w-40 bg-[var(--surface)] border border-[var(--border)] rounded shadow-xl py-1 z-30 font-mono text-xs">
                <div className="px-3 py-1 text-[10px] text-[var(--text-dim)] uppercase border-b border-[var(--border-subtle)] font-sans">
                  Set Case Status
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
                    {currentStatus === st && <Check className="w-3 h-3 text-[var(--state-pass)]" />}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* DOWNLOAD FORENSIC REPORT PDF ACTION (Solid Flat Button) */}
          <button
            type="button"
            onClick={handleDownloadReport}
            disabled={downloading}
            className="inline-flex items-center gap-1.5 px-3 py-1 rounded bg-[var(--surface-elevated)] hover:bg-[var(--surface-hover)] text-[var(--text)] border border-[var(--border)] text-xs font-mono font-medium transition-colors shadow-sm disabled:opacity-50 cursor-pointer"
            title="Download complete PDF forensic investigation report"
          >
            {downloading ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Download className="w-3.5 h-3.5 text-[var(--text-muted)]" />
            )}
            <span>{downloading ? 'GENERATING PDF...' : 'DOWNLOAD REPORT'}</span>
          </button>

          {/* VIEW FORENSIC REPORT ACTION */}
          {onViewReport && (
            <button
              type="button"
              onClick={onViewReport}
              className="inline-flex items-center gap-1.5 px-3 py-1 rounded bg-[var(--surface-elevated)] hover:bg-[var(--surface-hover)] text-[var(--text)] border border-[var(--border-subtle)] text-xs font-mono font-medium transition-colors shadow-sm cursor-pointer"
              title="Generate and review structured forensic dossier"
            >
              <FileText className="w-3.5 h-3.5 text-[var(--text-dim)]" />
              <span>VIEW REPORT</span>
            </button>
          )}

          {/* Calibrated Risk Score Pill */}
          <span className={`px-2.5 py-1 rounded font-bold uppercase tracking-wide border ${getRiskBadgeClass(String(riskLevel))}`}>
            {riskLevel} • {score}/100
          </span>
        </div>
      </div>

      {/* 2. Main Forensic Identification & Metadata Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
        {/* Left 7 Cols: Incident Title & Message-ID */}
        <div className="lg:col-span-7 space-y-2.5">
          <div className="flex items-start gap-2.5">
            <ShieldAlert className="w-5 h-5 text-[var(--severity-critical)] shrink-0 mt-0.5" />
            <div>
              <h1 className="text-lg font-semibold text-[var(--text)] tracking-tight leading-snug font-sans">
                {caseRecord?.title || data.subject || '(No Subject Provided)'}
              </h1>
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-[var(--text-muted)] mt-1 font-sans">
                <span>
                  From:{' '}
                  <span className="font-mono text-[var(--identifier)] font-medium">
                    {data.from || 'Unspecified'}
                  </span>
                </span>
                <span className="text-[var(--text-dim)]">•</span>
                <span>
                  To:{' '}
                  <span className="font-mono text-[var(--text)]">
                    {data.to || 'Unspecified'}
                  </span>
                </span>
              </div>
            </div>
          </div>

          {/* Monospace Bar for Message-ID */}
          <div className="bg-[var(--surface-subtle)] border border-[var(--border-subtle)] rounded p-2.5 flex items-center justify-between gap-3 text-xs font-mono">
            <div className="flex items-center space-x-2 truncate">
              <Fingerprint className="w-3.5 h-3.5 text-[var(--identifier)] shrink-0" />
              <span className="text-[10px] uppercase text-[var(--text-dim)] tracking-wider shrink-0 font-sans">
                RFC 5322 Message-ID
              </span>
              <span
                className="text-[var(--identifier)] truncate select-all px-1.5 py-0.5 rounded bg-[var(--surface)] border border-[var(--border-subtle)]"
                title={data.message_id || 'None'}
              >
                {data.message_id || 'None'}
              </span>
            </div>

            {data.message_id && (
              <button
                type="button"
                onClick={copyMessageId}
                className="px-2 py-0.5 rounded bg-[var(--surface)] hover:bg-[var(--surface-hover)] text-[var(--text-muted)] hover:text-[var(--text)] border border-[var(--border-subtle)] text-[10px] font-mono shrink-0 transition-colors flex items-center gap-1 cursor-pointer"
                title="Copy technical identifier to clipboard"
              >
                {copied ? (
                  <>
                    <Check className="w-3 h-3 text-[var(--state-pass)]" />
                    <span className="text-[var(--state-pass)]">COPIED</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" />
                    <span>COPY ID</span>
                  </>
                )}
              </button>
            )}
          </div>
        </div>

        {/* Right 5 Cols: Forensic Case Metadata Panel */}
        <div className="lg:col-span-5 bg-[var(--surface-subtle)] border border-[var(--border-subtle)] p-3 rounded space-y-1.5 text-xs font-mono">
          <div className="text-[10px] text-[var(--text-dim)] uppercase tracking-wider pb-1 border-b border-[var(--border-subtle)] flex items-center justify-between font-sans">
            <span>Forensic Case Metadata</span>
            <span className="text-[var(--identifier)] font-mono">{activeId}</span>
          </div>

          <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 pt-1">
            <div className="flex items-center justify-between">
              <span className="text-[var(--text-dim)] text-[10px] font-sans">Classification:</span>
              <span className="text-[var(--text)] font-semibold font-sans">{classification}</span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-[var(--text-dim)] text-[10px] font-sans">Confidence:</span>
              <span className="text-[var(--text-muted)] font-medium font-sans">{confidence}</span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-[var(--text-dim)] text-[10px] font-sans">Created:</span>
              <span className="text-[var(--text-muted)] text-[10px]" title={createdTimestamp}>
                {createdTimestampIST}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-[var(--text-dim)] text-[10px] font-sans">Updated:</span>
              <span className="text-[var(--text-muted)] text-[10px]" title={updatedTimestamp}>
                {updatedTimestampIST}
              </span>
            </div>

            <div className="flex items-center justify-between col-span-2 pt-1 border-t border-[var(--border-subtle)]">
              <span className="text-[var(--text-dim)] text-[10px] font-sans">Origin host:</span>
              <span className="text-[var(--identifier)] font-medium text-[11px] truncate">
                {caseRecord?.sourceIp || data.relay_analysis?.probable_source_infrastructure?.address || 'Unavailable'}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
