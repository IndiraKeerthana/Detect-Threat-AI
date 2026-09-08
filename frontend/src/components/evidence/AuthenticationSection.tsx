import React from 'react';
import { Check, X, Minus, AlertTriangle, ShieldCheck } from 'lucide-react';
import type { AuthenticationResultsAnalysis, AuthStatus } from '../../types/investigation';
import { SectionHeader } from '../investigation/SectionHeader';

interface AuthenticationSectionProps {
  auth?: AuthenticationResultsAnalysis | null;
}

export const AuthenticationSection: React.FC<AuthenticationSectionProps> = ({ auth }) => {
  if (!auth) {
    return (
      <div className="surface-card p-6 border border-[#1e2430] text-center text-xs text-[#64748b] font-mono">
        NO RFC 8601 AUTHENTICATION DATA PRESENT
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
      case 'none':
        return {
          icon: Minus,
          className: 'bg-[#171b23] text-[#94a3b8] border-[#2a3242]',
          text: 'NONE',
        };
      default:
        return {
          icon: Minus,
          className: 'bg-[#171b23] text-[#64748b] border-[#1e2430]',
          text: s.toUpperCase(),
        };
    }
  };

  const spfBadge = getStatusBadge(auth.spf?.result);
  const dkimBadge = getStatusBadge(auth.dkim?.result);
  const dmarcBadge = getStatusBadge(auth.dmarc?.result);

  const SpfIcon = spfBadge.icon;
  const DkimIcon = dkimBadge.icon;
  const DmarcIcon = dmarcBadge.icon;

  const hasReplyToMismatch =
    auth.reply_to_domain &&
    auth.from_domain &&
    auth.reply_to_domain.toLowerCase() !== auth.from_domain.toLowerCase();

  const hasReturnPathMismatch =
    auth.return_path_domain &&
    auth.from_domain &&
    auth.return_path_domain.toLowerCase() !== auth.from_domain.toLowerCase();

  return (
    <div className="surface-card p-6 border border-[#1e2430] space-y-4">
      {/* Section Header */}
      <SectionHeader
        index="03B"
        tag="AUTHENTICATION MATRIX"
        title="RFC 8601 Verification & Domain Alignment"
        subtitle="Cryptographic verification of sender SPF policy, DKIM digital signatures, and DMARC enforcement"
        action={
          <div className="flex items-center space-x-2 text-[10px] font-mono text-[#64748b]">
            <ShieldCheck className="w-3.5 h-3.5 text-[#10b981]" />
            <span>AUTHSERV: <strong className="text-[#f1f5f9]">{auth.authserv_ids[0] || 'None'}</strong></span>
          </div>
        }
      />

      {/* 3-Protocol Matrix Rows */}
      <div className="space-y-2.5">
        {/* SPF */}
        <div className="bg-[#0f1217] border border-[#1e2430] p-3.5 rounded-md space-y-2 text-xs font-mono">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <span className="font-semibold text-[#f1f5f9]">SPF</span>
              <span className="text-[10px] text-[#64748b]">RFC 7208</span>
            </div>

            <span className={`px-2 py-0.5 rounded text-[10px] font-bold border flex items-center gap-1 ${spfBadge.className}`}>
              <SpfIcon className="w-3 h-3" />
              {spfBadge.text}
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] pt-1 border-t border-[#1e2430]">
            <div>
              <span className="text-[#64748b]">Evaluating Domain: </span>
              <span className="text-[#f1f5f9]">{auth.spf?.domain || auth.from_domain || 'None'}</span>
            </div>
            <div>
              <span className="text-[#64748b]">Evaluated Raw: </span>
              <span className="text-[#fca5a5]">{auth.spf?.raw || 'None'}</span>
            </div>
          </div>
        </div>

        {/* DKIM */}
        <div className="bg-[#0f1217] border border-[#1e2430] p-3.5 rounded-md space-y-2 text-xs font-mono">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <span className="font-semibold text-[#f1f5f9]">DKIM</span>
              <span className="text-[10px] text-[#64748b]">RFC 6376</span>
            </div>

            <span className={`px-2 py-0.5 rounded text-[10px] font-bold border flex items-center gap-1 ${dkimBadge.className}`}>
              <DkimIcon className="w-3 h-3" />
              {dkimBadge.text}
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] pt-1 border-t border-[#1e2430]">
            <div>
              <span className="text-[#64748b]">Signing Domain: </span>
              <span className="text-[#94a3b8]">{auth.dkim?.domain || 'None (No signature present)'}</span>
            </div>
            <div>
              <span className="text-[#64748b]">Signature Status: </span>
              <span className="text-[#94a3b8]">{auth.dkim?.raw || 'None'}</span>
            </div>
          </div>
        </div>

        {/* DMARC */}
        <div className="bg-[#0f1217] border border-[#1e2430] p-3.5 rounded-md space-y-2 text-xs font-mono">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <span className="font-semibold text-[#f1f5f9]">DMARC</span>
              <span className="text-[10px] text-[#64748b]">RFC 7489</span>
            </div>

            <span className={`px-2 py-0.5 rounded text-[10px] font-bold border flex items-center gap-1 ${dmarcBadge.className}`}>
              <DmarcIcon className="w-3 h-3" />
              {dmarcBadge.text}
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] pt-1 border-t border-[#1e2430]">
            <div>
              <span className="text-[#64748b]">Policy Target: </span>
              <span className="text-[#f1f5f9]">{auth.dmarc?.domain || auth.from_domain || 'None'}</span>
            </div>
            <div>
              <span className="text-[#64748b]">Policy Action: </span>
              <span className="text-[#fca5a5] font-semibold">{auth.dmarc?.raw || 'None'}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Header Domain Alignment Diagnostics */}
      <div className="bg-[#12151b] border border-[#1e2430] p-3.5 rounded-md space-y-2 text-xs font-mono">
        <div className="text-[10px] uppercase text-[#64748b] tracking-wider">
          DOMAIN ALIGNMENT & IDENTITY VERIFICATION
        </div>

        <div className="space-y-1.5">
          <div className="flex items-center justify-between py-1 border-b border-[#1e2430]">
            <span className="text-[#94a3b8]">RFC 5322 From Domain:</span>
            <span className="text-[#f1f5f9] font-medium">{auth.from_domain || 'None'}</span>
          </div>

          <div className="flex items-center justify-between py-1 border-b border-[#1e2430]">
            <span className="text-[#94a3b8]">Reply-To Header Domain:</span>
            <div className="flex items-center gap-2">
              <span className={hasReplyToMismatch ? 'text-[#fca5a5]' : 'text-[#f1f5f9]'}>
                {auth.reply_to_domain || 'None'}
              </span>
              {hasReplyToMismatch && (
                <span className="px-1.5 py-0.2 rounded bg-[#261114] text-[#fca5a5] border border-[#5c1d24] text-[9px] font-bold flex items-center gap-1">
                  <AlertTriangle className="w-2.5 h-2.5" />
                  MISMATCH
                </span>
              )}
            </div>
          </div>

          <div className="flex items-center justify-between py-1">
            <span className="text-[#94a3b8]">Return-Path Domain:</span>
            <div className="flex items-center gap-2">
              <span className={hasReturnPathMismatch ? 'text-[#fcd34d]' : 'text-[#f1f5f9]'}>
                {auth.return_path_domain || 'None'}
              </span>
              {hasReturnPathMismatch && (
                <span className="px-1.5 py-0.2 rounded bg-[#261b0c] text-[#fcd34d] border border-[#5c3c12] text-[9px] font-bold flex items-center gap-1">
                  <AlertTriangle className="w-2.5 h-2.5" />
                  MISMATCH
                </span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Alignment Diagnostic Notes */}
      {auth.alignment_notes && auth.alignment_notes.length > 0 && (
        <div className="p-3 bg-[#0a0c10] border border-[#1e2430] rounded space-y-1">
          <div className="text-[10px] font-mono uppercase text-[#64748b]">
            ALIGNMENT & VERIFICATION DIAGNOSTIC NOTES
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
