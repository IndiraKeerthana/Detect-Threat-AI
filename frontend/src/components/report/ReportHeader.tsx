import React, { useState } from 'react';
import { Printer, Download, Shield, Loader2 } from 'lucide-react';
import type { EmailAnalysisResponse } from '../../types/investigation';
import type { CaseRecord } from '../../services/caseStore';
import { formatISTTimestamp } from '../../utils/dateFormatter';
import { downloadForensicReportPdf } from '../../services/api';

interface ReportHeaderProps {
  data: EmailAnalysisResponse;
  caseRecord?: CaseRecord;
}

export const ReportHeader: React.FC<ReportHeaderProps> = ({ data, caseRecord }) => {
  const [downloading, setDownloading] = useState(false);
  const activeId = caseRecord?.id || 'CASE-UNASSIGNED';
  const riskLevel = caseRecord?.severity || data.risk_assessment?.level || 'low';
  const score = caseRecord?.riskScore ?? (data.risk_assessment?.score ?? 0);
  const status = caseRecord?.status || 'OPEN';

  const handlePrint = () => {
    window.print();
  };

  const handleDownload = async () => {
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

  return (
    <div className="surface-card p-6 border border-[#1e2430] space-y-4">
      {/* Top Dossier Title & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#1e2430]">
        <div>
          <div className="flex items-center space-x-2 text-xs font-mono text-[#64748b] mb-1">
            <Shield className="w-3.5 h-3.5 text-[#8b5cf6]" />
            <span>FORENSIC INTELLIGENCE RECORD</span>
            <span>•</span>
            <span>NIST SP 800-86 SPECIFICATION</span>
          </div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-bold text-[#f1f5f9] tracking-tight font-mono">
              REPORT
            </h1>
            {/* REPORT READY Indicator */}
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded bg-[#0e241b] border border-[#164e3b] text-[#6ee7b7] text-xs font-mono font-semibold">
              <span className="w-1.5 h-1.5 rounded-full bg-[#10b981] animate-pulse" />
              REPORT READY
            </span>
          </div>
          <p className="text-xs text-[#94a3b8] font-sans mt-0.5">
            Structured forensic intelligence record.
          </p>
        </div>

        <div className="flex items-center space-x-2.5">
          {/* Active Action: DOWNLOAD FORENSIC REPORT PDF */}
          <button
            onClick={handleDownload}
            disabled={downloading}
            className="px-3.5 py-1.5 bg-[#8b5cf6] hover:bg-[#7c3aed] text-white border border-[#9d7aea] text-xs font-mono font-medium rounded flex items-center gap-1.5 transition-colors shadow-sm disabled:opacity-50"
            title="Download complete PDF forensic investigation report"
          >
            {downloading ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Download className="w-3.5 h-3.5" />
            )}
            <span>{downloading ? 'GENERATING PDF...' : 'DOWNLOAD FORENSIC REPORT'}</span>
          </button>

          {/* Printable Action */}
          <button
            onClick={handlePrint}
            className="px-3 py-1.5 bg-[#171b23] hover:bg-[#1e232e] text-[#f1f5f9] border border-[#2a3242] text-xs font-mono rounded flex items-center gap-1.5 transition-colors shadow-sm"
          >
            <Printer className="w-3.5 h-3.5 text-[#94a3b8]" />
            <span>PRINT DOSSIER</span>
          </button>
        </div>
      </div>

      {/* Structured Forensic Metadata Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
        <div className="bg-[#0f1217] p-2.5 rounded border border-[#1e2430]">
          <span className="text-[10px] text-[#64748b] block uppercase">CASE REFERENCE</span>
          <span className="text-[#06b6d4] font-semibold">{activeId}</span>
        </div>

        <div className="bg-[#0f1217] p-2.5 rounded border border-[#1e2430]">
          <span className="text-[10px] text-[#64748b] block uppercase">THREAT ASSESSMENT</span>
          <span className="text-[#ef4444] font-bold uppercase">
            {riskLevel} ({score}/100)
          </span>
        </div>

        <div className="bg-[#0f1217] p-2.5 rounded border border-[#1e2430]">
          <span className="text-[10px] text-[#64748b] block uppercase">WORKFLOW STATUS</span>
          <span className="text-[#fcd34d] font-semibold uppercase">{status}</span>
        </div>

        <div className="bg-[#0f1217] p-2.5 rounded border border-[#1e2430]">
          <span className="text-[10px] text-[#64748b] block uppercase">DATE GENERATED</span>
          <span className="text-[#f1f5f9]">{formatISTTimestamp(new Date())}</span>
        </div>
      </div>
    </div>
  );
};

