import React, { useState } from 'react';
import { Check, X, Minus, AlertTriangle, ShieldCheck, ChevronDown, ChevronUp } from 'lucide-react';
import type { AuthenticationResultsAnalysis, AuthStatus } from '../../types/investigation';
import { SectionHeader } from '../investigation/SectionHeader';

interface AuthenticationSectionProps {
  auth?: AuthenticationResultsAnalysis | null;
}

export const AuthenticationSection: React.FC<AuthenticationSectionProps> = ({ auth }) => {
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);

  if (!auth) {
    return (
      <div className="surface-card p-5 border border-[var(--border-subtle)] rounded-2xl text-center text-xs text-[var(--text-muted)] font-sans">
        No email security check data found in email headers.
      </div>
    );
  }

  const getStatusBadge = (status?: AuthStatus | null) => {
    const s = (status || 'unknown').toLowerCase();
    switch (s) {
      case 'pass':
        return {
          icon: Check,
          className: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
          text: 'PASS',
        };
      case 'fail':
      case 'permerror':
        return {
          icon: X,
          className: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
          text: s.toUpperCase(),
        };
      case 'softfail':
      case 'neutral':
        return {
          icon: Minus,
          className: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
          text: s.toUpperCase(),
        };
      case 'none':
      default:
        return {
          icon: Minus,
          className: 'bg-[var(--surface-elevated)] text-[var(--text-muted)] border-[var(--border-subtle)]',
          text: 'NONE',
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
    <div className="surface-card p-5 border border-[var(--border-subtle)] rounded-2xl space-y-4 font-sans">
      {/* Section Header */}
      <SectionHeader
        index="05"
        title="Email Security Checks"
        subtitle="Verifies whether the email was authorized by the domain owner and passes authentication seals."
        action={
          <div className="flex items-center space-x-2 text-xs text-[var(--text-muted)]">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>Security Seals Checked</span>
          </div>
        }
      />

      {/* Main Security Seals Grid */}
      <div className="border border-[var(--border-subtle)] rounded-xl bg-[var(--surface-subtle)] divide-y divide-[var(--border-subtle)]">
        {/* SPF */}
        <div className="p-4 space-y-1.5">
          <div className="flex items-center justify-between">
            <div>
              <span className="font-semibold text-sm text-[var(--text)]">Sender Authorization Seal (SPF)</span>
              <p className="text-xs text-[var(--text-muted)]">Checks if the sending server is authorized to send email for this domain.</p>
            </div>
            <span className={`px-2.5 py-1 rounded-full text-xs font-semibold border flex items-center gap-1 shrink-0 ${spfBadge.className}`}>
              <SpfIcon className="w-3.5 h-3.5" />
              {spfBadge.text}
            </span>
          </div>
        </div>

        {/* DKIM */}
        <div className="p-4 space-y-1.5">
          <div className="flex items-center justify-between">
            <div>
              <span className="font-semibold text-sm text-[var(--text)] font-sans">Digital Signature Seal (DKIM)</span>
              <p className="text-xs text-[var(--text-muted)]">Verifies that the email message was not altered in transit.</p>
            </div>
            <span className={`px-2.5 py-1 rounded-full text-xs font-semibold border flex items-center gap-1 shrink-0 ${dkimBadge.className}`}>
              <DkimIcon className="w-3.5 h-3.5" />
              {dkimBadge.text}
            </span>
          </div>
        </div>

        {/* DMARC */}
        <div className="p-4 space-y-1.5">
          <div className="flex items-center justify-between">
            <div>
              <span className="font-semibold text-sm text-[var(--text)]">Domain Protection Seal (DMARC)</span>
              <p className="text-xs text-[var(--text-muted)]">Ensures the email matches domain owner policies and prevents impersonation.</p>
            </div>
            <span className={`px-2.5 py-1 rounded-full text-xs font-semibold border flex items-center gap-1 shrink-0 ${dmarcBadge.className}`}>
              <DmarcIcon className="w-3.5 h-3.5" />
              {dmarcBadge.text}
            </span>
          </div>
        </div>
      </div>

      {/* Domain Alignment Alert */}
      {(hasReplyToMismatch || hasReturnPathMismatch) && (
        <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/20 text-xs space-y-2">
          <div className="flex items-center gap-2 font-semibold text-amber-400">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>Sender Address Discrepancy Detected</span>
          </div>
          <p className="text-[var(--text-muted)] leading-relaxed">
            The sender domain does not match the reply address or technical return path. Scammers often use a different reply address to trick recipients.
          </p>
          <div className="space-y-1 pt-1 font-mono text-[11px]">
            {hasReplyToMismatch && (
              <div>Reply-To Address: <strong className="text-rose-400">{auth.reply_to_domain}</strong> (Sender: {auth.from_domain})</div>
            )}
            {hasReturnPathMismatch && (
              <div>Technical Return Path: <strong className="text-amber-400">{auth.return_path_domain}</strong></div>
            )}
          </div>
        </div>
      )}

      {/* Technical Details Accordion */}
      <div className="pt-2">
        <button
          type="button"
          onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
          className="px-3 py-1.5 rounded-lg bg-[var(--surface)] hover:bg-[var(--surface-elevated)] border border-[var(--border-subtle)] text-xs text-[var(--text-muted)] hover:text-[var(--text)] transition-colors flex items-center gap-1.5 cursor-pointer"
        >
          <span>{showTechnicalDetails ? 'Hide Technical RFC Details' : 'Show Technical RFC Details'}</span>
          {showTechnicalDetails ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </button>

        {showTechnicalDetails && (
          <div className="mt-3 p-4 rounded-xl bg-[var(--surface-subtle)] border border-[var(--border-subtle)] space-y-2 text-xs font-mono">
            <div>SPF Domain: <span className="text-[var(--identifier)]">{auth.spf?.domain || 'N/A'}</span></div>
            <div>SPF Raw: <span className="text-[var(--text)]">{auth.spf?.raw || 'N/A'}</span></div>
            <div>DKIM Domain: <span className="text-[var(--identifier)]">{auth.dkim?.domain || 'N/A'}</span></div>
            <div>DKIM Raw: <span className="text-[var(--text)]">{auth.dkim?.raw || 'N/A'}</span></div>
            <div>DMARC Domain: <span className="text-[var(--identifier)]">{auth.dmarc?.domain || 'N/A'}</span></div>
            <div>DMARC Raw: <span className="text-[var(--text)]">{auth.dmarc?.raw || 'N/A'}</span></div>
          </div>
        )}
      </div>
    </div>
  );
};
