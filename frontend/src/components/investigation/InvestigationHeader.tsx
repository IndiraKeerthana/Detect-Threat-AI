import React, { useState } from 'react';
import {
  Copy,
  Check,
  ArrowLeft,
  ShieldAlert,
  Fingerprint,
  FileText,
  ChevronDown,
} from 'lucide-react';
import type { EmailAnalysisResponse } from '../../types/investigation';
import type { CaseRecord, CaseStatus } from '../../services/caseStore';

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

  const activeId = caseRecord?.id || caseId;
  const currentStatus: CaseStatus = caseRecord?.status || 'OPEN';
  const riskLevel = caseRecord?.severity || data.risk_assessment?.level || data.ai_investigation?.risk_level || 'low';
  const classification = caseRecord?.classification || data.risk_assessment?.classification || data.ai_investigation?.classification || 'unclassified';
  const score = caseRecord?.riskScore ?? (data.risk_assessment?.score ?? 0);
  const confidence = caseRecord?.confidence || data.confidence?.level || 'unknown';
  const createdTimestamp = caseRecord?.createdAt || 'Unrecorded';
  const updatedTimestamp = caseRecord?.updatedAt || 'Unrecorded';

  const copyMessageId = () => {
    if (data.message_id) {
      navigator.clipboard.writeText(data.message_id);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
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

  const getStatusColor = (st: CaseStatus) => {
    switch (st) {
      case 'OPEN':
        return 'text-[#38bdf8] bg-[#0c202d] border-[#164e63]';
      case 'IN REVIEW':
        return 'text-[#fcd34d] bg-[#261b0c] border-[#5c3c12]';
      case 'CONTAINED':
        return 'text-[#6ee7b7] bg-[#0e241b] border-[#164e3b]';
      case 'CLOSED':
      default:
        return 'text-[#94a3b8] bg-[#171b23] border-[#2a3242]';
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
    <div className="surface-card p-5 border border-[#1e2430] space-y-4">
      {/* 1. Top Action & Navigation Row */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-[#1e2430]">
        <div className="flex items-center space-x-3">
          {onNavigateBack && (
            <button
              onClick={onNavigateBack}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#171b23] hover:bg-[#1e232e] text-[#94a3b8] hover:text-[#f1f5f9] border border-[#2a3242] text-xs font-mono transition-colors"
              title="Return to Ingestion Console"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>OVERVIEW</span>
            </button>
          )}

          <div className="flex items-center space-x-2 text-xs font-mono">
            <span className="px-2 py-0.5 rounded bg-[#171b23] border border-[#2a3242] text-[#06b6d4] font-bold">
              {activeId}
            </span>
            <span className="text-[#64748b]">/</span>
            <span className="text-[#94a3b8]">SUSPICIOUS EMAIL INVESTIGATION</span>
          </div>
        </div>

        {/* Status Workflow Selector, View Report & Risk Badge */}
        <div className="flex flex-wrap items-center gap-2.5 text-xs font-mono">
          {/* Interactive Case Status Control */}
          <div className="relative">
            <button
              type="button"
              onClick={() => setStatusDropdownOpen(!statusDropdownOpen)}
              className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded border text-xs font-mono font-semibold transition-colors ${getStatusColor(
                currentStatus
              )}`}
              title="Change Case Workflow Status"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-current" />
              <span>STATUS: {currentStatus}</span>
              <ChevronDown className="w-3 h-3 opacity-70" />
            </button>

            {statusDropdownOpen && (
              <div className="absolute right-0 mt-1 w-40 bg-[#0f1217] border border-[#2a3242] rounded shadow-xl py-1 z-30 font-mono text-xs">
                <div className="px-3 py-1 text-[10px] text-[#64748b] uppercase border-b border-[#1e2430]">
                  Set Case Status
                </div>
                {statuses.map((st) => (
                  <button
                    key={st}
                    onClick={() => handleSelectStatus(st)}
                    className={`w-full text-left px-3 py-1.5 flex items-center justify-between hover:bg-[#171b23] transition-colors ${
                      currentStatus === st ? 'text-[#f1f5f9] font-bold' : 'text-[#94a3b8]'
                    }`}
                  >
                    <span>{st}</span>
                    {currentStatus === st && <Check className="w-3 h-3 text-[#10b981]" />}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* VIEW FORENSIC REPORT ACTION */}
          {onViewReport && (
            <button
              type="button"
              onClick={onViewReport}
              className="inline-flex items-center gap-1.5 px-3 py-1 rounded bg-[#171b23] hover:bg-[#8b5cf6] text-[#c4b5fd] hover:text-white border border-[#3e485e] hover:border-[#8b5cf6] text-xs font-mono font-medium transition-colors shadow-sm"
              title="Generate and review structured forensic dossier"
            >
              <FileText className="w-3.5 h-3.5" />
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
        {/* Left 7 Cols: Incident Title, Identities & RFC Message-ID */}
        <div className="lg:col-span-7 space-y-2.5">
          <div className="flex items-start gap-2.5">
            <ShieldAlert className="w-5 h-5 text-[#ef4444] shrink-0 mt-0.5" />
            <div>
              <h1 className="text-lg font-semibold text-[#f1f5f9] tracking-tight leading-snug">
                {caseRecord?.title || data.subject || '(No Subject Provided)'}
              </h1>
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-[#94a3b8] mt-1 font-sans">
                <span>
                  From:{' '}
                  <span className="font-mono text-[#f1f5f9] font-medium">
                    {data.from || 'Unspecified'}
                  </span>
                </span>
                <span className="text-[#3e485e]">•</span>
                <span>
                  To:{' '}
                  <span className="font-mono text-[#f1f5f9]">
                    {data.to || 'Unspecified'}
                  </span>
                </span>
              </div>
            </div>
          </div>

          {/* Monospace Bar for Message-ID */}
          <div className="bg-[#0a0c10] border border-[#1e2430] rounded p-2.5 flex items-center justify-between gap-3 text-xs font-mono">
            <div className="flex items-center space-x-2 truncate">
              <Fingerprint className="w-3.5 h-3.5 text-[#8b5cf6] shrink-0" />
              <span className="text-[10px] uppercase text-[#64748b] tracking-wider shrink-0">
                RFC 5322 MESSAGE-ID
              </span>
              <span
                className="text-[#06b6d4] truncate select-all px-1.5 py-0.5 rounded bg-[#12151b] border border-[#1e2430]"
                title={data.message_id || 'None'}
              >
                {data.message_id || 'None'}
              </span>
            </div>

            {data.message_id && (
              <button
                onClick={copyMessageId}
                className="px-2 py-0.5 rounded bg-[#171b23] hover:bg-[#1e232e] text-[#94a3b8] hover:text-[#f1f5f9] border border-[#2a3242] text-[10px] font-mono shrink-0 transition-colors flex items-center gap-1"
                title="Copy technical identifier to clipboard"
              >
                {copied ? (
                  <>
                    <Check className="w-3 h-3 text-[#10b981]" />
                    <span className="text-[#10b981]">COPIED</span>
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
        <div className="lg:col-span-5 bg-[#0f1217] border border-[#1e2430] p-3 rounded space-y-1.5 text-xs font-mono">
          <div className="text-[10px] text-[#64748b] uppercase tracking-wider pb-1 border-b border-[#1e2430] flex items-center justify-between">
            <span>FORENSIC CASE METADATA</span>
            <span className="text-[#06b6d4]">{activeId}</span>
          </div>

          <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 pt-1">
            <div className="flex items-center justify-between">
              <span className="text-[#64748b] text-[10px] uppercase">CLASSIFICATION</span>
              <span className="text-[#c4b5fd] font-semibold uppercase">{classification}</span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-[#64748b] text-[10px] uppercase">CONFIDENCE</span>
              <span className="text-[#f1f5f9] font-medium uppercase">{confidence}</span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-[#64748b] text-[10px] uppercase">CREATED</span>
              <span className="text-[#94a3b8] text-[10px]" title={createdTimestamp}>
                {createdTimestamp.split(' ')[0]}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-[#64748b] text-[10px] uppercase">UPDATED</span>
              <span className="text-[#94a3b8] text-[10px]" title={updatedTimestamp}>
                {updatedTimestamp.split(' ')[0]}
              </span>
            </div>

            <div className="flex items-center justify-between col-span-2 pt-1 border-t border-[#1e2430]">
              <span className="text-[#64748b] text-[10px] uppercase">ORIGIN HOST</span>
              <span className="text-[#06b6d4] font-medium text-[11px] truncate">
                {caseRecord?.sourceIp || data.relay_analysis?.probable_source_infrastructure?.address || 'Unavailable'}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
