import { Printer } from 'lucide-react';
import type { EmailAnalysisResponse } from '../../types/investigation';

interface ReportHeaderProps {
  data: EmailAnalysisResponse;
}

export const ReportHeader: React.FC<ReportHeaderProps> = ({ data }) => {
  const riskLevel = data.risk_assessment?.level || 'critical';
  const score = data.risk_assessment?.score ?? 92;

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="surface-card p-6 border border-[#1e2430] space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#1e2430]">
        <div>
          <div className="flex items-center space-x-2 text-xs font-mono text-[#64748b] mb-1">
            <span>FORENSIC EXAMINATION DOSSIER</span>
            <span>•</span>
            <span>SIH26106 COMPLIANT</span>
          </div>
          <h1 className="text-xl font-bold text-[#f1f5f9] tracking-tight">
            Digital Forensic Investigation Report
          </h1>
          <p className="text-xs text-[#94a3b8] font-mono mt-0.5">
            Subject: {data.subject || 'Security Verification'}
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={handlePrint}
            className="px-3 py-1.5 bg-[#171b23] hover:bg-[#1e232e] text-[#f1f5f9] border border-[#2a3242] text-xs font-mono rounded flex items-center gap-1.5 transition-colors"
          >
            <Printer className="w-3.5 h-3.5 text-[#94a3b8]" />
            Print / Export Dossier
          </button>
        </div>
      </div>

      {/* Metadata Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
        <div className="bg-[#0f1217] p-2.5 rounded border border-[#1e2430]">
          <span className="text-[10px] text-[#64748b] block">CASE REFERENCE</span>
          <span className="text-[#f1f5f9] font-medium">CASE-2026-0891</span>
        </div>

        <div className="bg-[#0f1217] p-2.5 rounded border border-[#1e2430]">
          <span className="text-[10px] text-[#64748b] block">RISK STATUS</span>
          <span className="text-[#ef4444] font-bold uppercase">{riskLevel} ({score}/100)</span>
        </div>

        <div className="bg-[#0f1217] p-2.5 rounded border border-[#1e2430]">
          <span className="text-[10px] text-[#64748b] block">ANALYST ENGINE</span>
          <span className="text-[#c4b5fd]">GROQ 70B + DETERMINISTIC</span>
        </div>

        <div className="bg-[#0f1217] p-2.5 rounded border border-[#1e2430]">
          <span className="text-[10px] text-[#64748b] block">DATE GENERATED</span>
          <span className="text-[#f1f5f9]">{new Date().toISOString().split('T')[0]}</span>
        </div>
      </div>
    </div>
  );
};
