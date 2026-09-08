import React from 'react';
import { ShieldCheck, Check, X, Minus } from 'lucide-react';
import type { AuthenticationResultsAnalysis, AuthStatus } from '../../types/investigation';

interface AuthenticationSectionProps {
  auth?: AuthenticationResultsAnalysis | null;
}

export const AuthenticationSection: React.FC<AuthenticationSectionProps> = ({ auth }) => {
  if (!auth) {
    return (
      <div className="surface-card p-5 border border-[#1e2430] text-center text-xs text-[#64748b] font-mono">
        NO RFC 8601 AUTHENTICATION DATA
      </div>
    );
  }

  const getStatusBadge = (status?: AuthStatus | null) => {
    const s = (status || 'unknown').toLowerCase();
    switch (s) {
      case 'pass':
        return {
          icon: Check,
          className: 'bg-[#0e241b] text-[#6ee7b7] border-[#164e3b]',
          text: 'PASS',
        };
      case 'fail':
      case 'permerror':
        return {
          icon: X,
          className: 'bg-[#261114] text-[#fca5a5] border-[#5c1d24]',
          text: s.toUpperCase(),
        };
      case 'softfail':
      case 'neutral':
        return {
          icon: Minus,
          className: 'bg-[#261b0c] text-[#fcd34d] border-[#5c3c12]',
          text: s.toUpperCase(),
        };
      default:
        return {
          icon: Minus,
          className: 'bg-[#171b23] text-[#94a3b8] border-[#2a3242]',
          text: s.toUpperCase(),
        };
    }
  };

  const spfBadge = getStatusBadge(auth.spf?.result);
  const dkimBadge = getStatusBadge(auth.dkim?.result);
  const dmarcBadge = getStatusBadge(auth.dmarc?.result);

  return (
    <div className="surface-card p-5 border border-[#1e2430] space-y-4">
      {/* Title */}
      <div className="flex items-center justify-between pb-3 border-b border-[#1e2430]">
        <div className="flex items-center space-x-2">
          <ShieldCheck className="w-4 h-4 text-[#10b981]" />
          <h3 className="text-sm font-semibold text-[#f1f5f9] tracking-tight">
            Email Authentication Results (RFC 8601)
          </h3>
        </div>
        <span className="text-xs font-mono text-[#64748b]">
          AUTHSERV ID: <span className="text-[#f1f5f9]">{auth.authserv_ids[0] || 'Unknown'}</span>
        </span>
      </div>

      {/* 3-Column Protocol Matrix */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {/* SPF */}
        <div className="bg-[#12151b] border border-[#1e2430] p-3.5 rounded space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-semibold text-[#f1f5f9]">SPF (RFC 7208)</span>
            <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border flex items-center gap-1 ${spfBadge.className}`}>
              <spfBadge.icon className="w-3 h-3" />
              {spfBadge.text}
            </span>
          </div>
          <div className="text-[11px] font-mono text-[#94a3b8] truncate">
            Domain: <span className="text-[#f1f5f9]">{auth.spf?.domain || auth.from_domain || 'None'}</span>
          </div>
          <div className="text-[10px] font-mono text-[#64748b] truncate">
            {auth.spf?.raw || 'No SPF record evaluated'}
          </div>
        </div>

        {/* DKIM */}
        <div className="bg-[#12151b] border border-[#1e2430] p-3.5 rounded space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-semibold text-[#f1f5f9]">DKIM (RFC 6376)</span>
            <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border flex items-center gap-1 ${dkimBadge.className}`}>
              <dkimBadge.icon className="w-3 h-3" />
              {dkimBadge.text}
            </span>
          </div>
          <div className="text-[11px] font-mono text-[#94a3b8] truncate">
            Domain: <span className="text-[#f1f5f9]">{auth.dkim?.domain || 'None'}</span>
          </div>
          <div className="text-[10px] font-mono text-[#64748b] truncate">
            {auth.dkim?.raw || 'No DKIM signature present'}
          </div>
        </div>

        {/* DMARC */}
        <div className="bg-[#12151b] border border-[#1e2430] p-3.5 rounded space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-semibold text-[#f1f5f9]">DMARC (RFC 7489)</span>
            <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border flex items-center gap-1 ${dmarcBadge.className}`}>
              <dmarcBadge.icon className="w-3 h-3" />
              {dmarcBadge.text}
            </span>
          </div>
          <div className="text-[11px] font-mono text-[#94a3b8] truncate">
            Domain: <span className="text-[#f1f5f9]">{auth.dmarc?.domain || auth.from_domain || 'None'}</span>
          </div>
          <div className="text-[10px] font-mono text-[#64748b] truncate">
            {auth.dmarc?.raw || 'No DMARC record evaluated'}
          </div>
        </div>
      </div>

      {/* Alignment Notes */}
      {auth.alignment_notes && auth.alignment_notes.length > 0 && (
        <div className="p-3 bg-[#0f1217] border border-[#1e2430] rounded space-y-1">
          <div className="text-[10px] font-mono uppercase text-[#64748b]">
            Alignment & Verification Diagnostic Notes
          </div>
          <ul className="text-xs text-[#94a3b8] space-y-1 list-disc list-inside">
            {auth.alignment_notes.map((note, idx) => (
              <li key={idx} className="font-mono text-[11px]">
                {note}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};
