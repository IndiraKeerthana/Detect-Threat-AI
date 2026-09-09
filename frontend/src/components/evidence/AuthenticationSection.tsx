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
      <div className="surface-card p-5 border border-[var(--border-subtle)] text-center text-xs text-[var(--text-dim)] font-mono">
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
          className: 'bg-[var(--surface-elevated)] text-[var(--state-pass)] border-[var(--border-subtle)]',
          text: 'PASS',
        };
      case 'fail':
      case 'permerror':
        return {
          icon: X,
          className: 'bg-[var(--surface-elevated)] text-[var(--state-fail)] border-[var(--border-subtle)]',
          text: s.toUpperCase(),
        };
      case 'softfail':
      case 'neutral':
        return {
          icon: Minus,
          className: 'bg-[var(--surface-elevated)] text-[var(--severity-medium)] border-[var(--border-subtle)]',
          text: s.toUpperCase(),
        };
      case 'none':
        return {
          icon: Minus,
          className: 'bg-[var(--surface-elevated)] text-[var(--text-muted)] border-[var(--border-subtle)]',
          text: 'NONE',
        };
      default:
        return {
          icon: Minus,
          className: 'bg-[var(--surface-elevated)] text-[var(--text-dim)] border-[var(--border-subtle)]',
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
    <div className="surface-card p-5 border border-[var(--border-subtle)] space-y-4">
      {/* Section Header */}
      <SectionHeader
        index="02"
        title="Email authentication"
        subtitle="RFC 8601 sender SPF policy, DKIM signatures, and DMARC enforcement."
        action={
          <div className="flex items-center space-x-2 text-[10px] font-mono text-[var(--text-dim)]">
            <ShieldCheck className="w-3.5 h-3.5 text-[var(--state-pass)]" />
            <span>AUTHSERV: <strong className="text-[var(--text)]">{auth.authserv_ids[0] || 'None'}</strong></span>
          </div>
        }
      />

      {/* Single Consolidated Container with Hairline Dividers */}
      <div className="border border-[var(--border-subtle)] rounded bg-[var(--surface-subtle)] divide-y divide-[var(--border-subtle)]">
        {/* SPF Row */}
        <div className="p-3.5 space-y-1.5 text-xs font-mono">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <span className="font-semibold text-[var(--text)]">SPF</span>
              <span className="text-[10px] text-[var(--text-dim)] font-sans">RFC 7208</span>
            </div>
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold border flex items-center gap-1 ${spfBadge.className}`}>
              <SpfIcon className="w-3 h-3" />
              {spfBadge.text}
            </span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] text-[var(--text-muted)] font-sans pt-1">
            <div>Evaluating domain: <span className="font-mono text-[var(--identifier)]">{auth.spf?.domain || auth.from_domain || 'None'}</span></div>
            <div>Raw result: <span className="font-mono text-[var(--text)]">{auth.spf?.raw || 'None'}</span></div>
          </div>
        </div>

        {/* DKIM Row */}
        <div className="p-3.5 space-y-1.5 text-xs font-mono">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <span className="font-semibold text-[var(--text)]">DKIM</span>
              <span className="text-[10px] text-[var(--text-dim)] font-sans">RFC 6376</span>
            </div>
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold border flex items-center gap-1 ${dkimBadge.className}`}>
              <DkimIcon className="w-3 h-3" />
              {dkimBadge.text}
            </span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] text-[var(--text-muted)] font-sans pt-1">
            <div>Signing domain: <span className="font-mono text-[var(--identifier)]">{auth.dkim?.domain || 'None (No signature)'}</span></div>
            <div>Status: <span className="font-mono text-[var(--text)]">{auth.dkim?.raw || 'None'}</span></div>
          </div>
        </div>

        {/* DMARC Row */}
        <div className="p-3.5 space-y-1.5 text-xs font-mono">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <span className="font-semibold text-[var(--text)]">DMARC</span>
              <span className="text-[10px] text-[var(--text-dim)] font-sans">RFC 7489</span>
            </div>
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold border flex items-center gap-1 ${dmarcBadge.className}`}>
              <DmarcIcon className="w-3 h-3" />
              {dmarcBadge.text}
            </span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] text-[var(--text-muted)] font-sans pt-1">
            <div>Policy target: <span className="font-mono text-[var(--identifier)]">{auth.dmarc?.domain || auth.from_domain || 'None'}</span></div>
            <div>Policy action: <span className="font-mono text-[var(--state-fail)] font-semibold">{auth.dmarc?.raw || 'None'}</span></div>
          </div>
        </div>
      </div>

      {/* Domain Alignment & Identity Diagnostics */}
      <div className="border border-[var(--border-subtle)] rounded p-3.5 bg-[var(--surface)] space-y-2 text-xs font-mono">
        <div className="text-[10px] uppercase text-[var(--text-dim)] tracking-wider">
          Domain alignment & identity verification
        </div>

        <div className="space-y-1.5 divide-y divide-[var(--border-subtle)]">
          <div className="flex items-center justify-between py-1">
            <span className="text-[var(--text-muted)] font-sans text-[11px]">RFC 5322 From domain:</span>
            <span className="text-[var(--identifier)] font-mono">{auth.from_domain || 'None'}</span>
          </div>

          <div className="flex items-center justify-between py-1 pt-1.5">
            <span className="text-[var(--text-muted)] font-sans text-[11px]">Reply-To header domain:</span>
            <div className="flex items-center gap-2">
              <span className={`font-mono ${hasReplyToMismatch ? 'text-[var(--state-fail)]' : 'text-[var(--identifier)]'}`}>
                {auth.reply_to_domain || 'None'}
              </span>
              {hasReplyToMismatch && (
                <span className="px-1.5 py-0.2 rounded bg-[var(--surface-elevated)] text-[var(--state-fail)] border border-[var(--border-subtle)] text-[9px] font-bold flex items-center gap-1">
                  <AlertTriangle className="w-2.5 h-2.5" />
                  MISMATCH
                </span>
              )}
            </div>
          </div>

          <div className="flex items-center justify-between py-1 pt-1.5">
            <span className="text-[var(--text-muted)] font-sans text-[11px]">Return-Path domain:</span>
            <div className="flex items-center gap-2">
              <span className={`font-mono ${hasReturnPathMismatch ? 'text-[var(--severity-medium)]' : 'text-[var(--identifier)]'}`}>
                {auth.return_path_domain || 'None'}
              </span>
              {hasReturnPathMismatch && (
                <span className="px-1.5 py-0.2 rounded bg-[var(--surface-elevated)] text-[var(--severity-medium)] border border-[var(--border-subtle)] text-[9px] font-bold flex items-center gap-1">
                  <AlertTriangle className="w-2.5 h-2.5" />
                  MISMATCH
                </span>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
