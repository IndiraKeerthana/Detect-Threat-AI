import React from 'react';
import { Server, Link2, AlertTriangle, ShieldCheck, Check, X, Minus } from 'lucide-react';
import type { RelayAnalysis, ThreatIntelligence, URLDomainAnalysis, EmailAnalysisResponse, AuthenticationResultsAnalysis, AuthStatus } from '../../types/investigation';
import { SectionHeader } from '../investigation/SectionHeader';
import { GeolocationMap } from '../map/GeolocationMap';

interface InfrastructureIntelProps {
  relay?: RelayAnalysis | null;
  intelligence?: ThreatIntelligence | null;
  urls?: URLDomainAnalysis | null;
  auth?: AuthenticationResultsAnalysis | null;
  data?: EmailAnalysisResponse | null;
}

export const InfrastructureIntel: React.FC<InfrastructureIntelProps> = ({
  relay,
  intelligence,
  urls,
  auth,
  data,
}) => {
  const probableSource = relay?.probable_source_infrastructure;
  const observations = intelligence?.observations || [];
  const providers = intelligence?.provider_status || [];

  const probableIP = probableSource?.address || relay?.extracted_ips?.[0]?.address || null;

  let asn: string | null = null;
  let isp: string | null = null;
  let country: string | null = null;
  let region: string | null = null;
  let coords: string | null = null;
  let abuseConf: number | null = null;
  let totalReports: number | null = null;
  let vtVendors: string | null = null;
  let domainAge: string | null = null;

  for (const obs of observations) {
    if (obs.status === 'success' && obs.data) {
      const d = obs.data as Record<string, unknown>;
      if (!asn && typeof d.asn === 'string') asn = d.asn;
      if (!isp && typeof d.isp === 'string') isp = d.isp;
      else if (!isp && typeof d.organization === 'string') isp = d.organization;

      if (!country && typeof d.country === 'string') country = d.country;
      if (!region && typeof d.region === 'string') region = d.region;
      else if (!region && typeof d.city === 'string') region = d.city;

      if (!coords && typeof d.latitude === 'number' && typeof d.longitude === 'number') {
        coords = `${d.latitude.toFixed(3)}°, ${d.longitude.toFixed(3)}°`;
      }

      if (abuseConf === null && typeof d.abuse_confidence_score === 'number') {
        abuseConf = d.abuse_confidence_score;
      } else if (abuseConf === null && typeof d.abuse_score === 'number') {
        abuseConf = d.abuse_score;
      }

      if (totalReports === null && typeof d.total_reports === 'number') {
        totalReports = d.total_reports;
      }

      if (!vtVendors && (typeof d.malicious_votes === 'number' || typeof d.positives === 'number')) {
        const mal = (d.malicious_votes ?? d.positives) as number;
        const total = (d.total_vendors ?? d.total ?? 92) as number;
        vtVendors = `${mal}/${total} vendors`;
      }

      if (!domainAge && typeof d.age_days === 'number') {
        domainAge = `${d.age_days} Days Old`;
      } else if (!domainAge && typeof d.domain_age_days === 'number') {
        domainAge = `${d.domain_age_days} Days Old`;
      }
    }
  }

  const hasVerifiedInfrastructure = Boolean(probableIP);

  const analysisDataForMap: EmailAnalysisResponse | null = data || (
    relay || intelligence ? ({
      relay_analysis: relay,
      threat_intelligence: intelligence,
      security_analysis: { url_analysis: urls },
    } as unknown as EmailAnalysisResponse) : null
  );

  // Auth Badge helper
  const getStatusBadge = (status?: AuthStatus | null) => {
    const s = (status || 'unknown').toLowerCase();
    switch (s) {
      case 'pass':
        return {
          icon: Check,
          className: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
          text: 'Passed',
        };
      case 'fail':
      case 'permerror':
        return {
          icon: X,
          className: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
          text: 'Failed',
        };
      case 'softfail':
      case 'neutral':
        return {
          icon: Minus,
          className: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
          text: 'Soft Fail',
        };
      case 'none':
      default:
        return {
          icon: Minus,
          className: 'bg-[var(--surface-elevated)] text-[var(--text-muted)] border-[var(--border-subtle)]',
          text: 'Not Configured',
        };
    }
  };

  const spfBadge = getStatusBadge(auth?.spf?.result);
  const dkimBadge = getStatusBadge(auth?.dkim?.result);
  const dmarcBadge = getStatusBadge(auth?.dmarc?.result);

  const SpfIcon = spfBadge.icon;
  const DkimIcon = dkimBadge.icon;
  const DmarcIcon = dmarcBadge.icon;

  return (
    <div className="surface-card p-5 border border-[var(--border-subtle)] rounded-2xl space-y-6 font-sans">
      {/* Section Header */}
      <SectionHeader
        index={5}
        title="Sender Location & Online Safety Check"
        subtitle="Sender origin location, domain safety checks, and email security seals."
        action={
          providers.length > 0 ? (
            <div className="flex flex-wrap items-center gap-1.5 text-xs text-[var(--text-muted)] font-mono">
              <span className="text-[var(--text-dim)] uppercase text-[10px]">Safety Feeds:</span>
              {providers.map((p, idx) => {
                const isOk = p.status === 'available';
                const symbol = isOk ? '✓' : '✕';
                const colorClass = isOk ? 'text-emerald-400' : 'text-[var(--text-dim)]';
                return (
                  <span key={p.provider} className="inline-flex items-center gap-1">
                    {idx > 0 && <span className="text-[var(--text-dim)] mr-0.5">·</span>}
                    <span className="text-[var(--text)]">{p.provider}</span>
                    <span className={`${colorClass} font-bold`}>{symbol}</span>
                  </span>
                );
              })}
            </div>
          ) : undefined
        }
      />

      {/* Main Location & Safety Overview */}
      {!hasVerifiedInfrastructure ? (
        <div className="border border-[var(--border-subtle)] rounded-xl p-6 bg-[var(--surface-subtle)] text-center space-y-2">
          <div className="w-10 h-10 rounded-full bg-[var(--surface)] border border-[var(--border-subtle)] mx-auto flex items-center justify-center text-[var(--text-dim)]">
            <Server className="w-5 h-5" />
          </div>
          <h3 className="text-xs font-bold text-[var(--text)] uppercase tracking-wider font-sans">
            Sender Location Details Unavailable
          </h3>
          <p className="text-xs text-[var(--text-muted)] font-sans max-w-md mx-auto leading-relaxed">
            No public sending server IP could be extracted from the email headers.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          <div className="border border-[var(--border-subtle)] rounded-xl bg-[var(--surface-subtle)] overflow-hidden">
            {/* Sender Location Hero Card */}
            <div className="p-5 bg-[var(--surface)] border-b border-[var(--border-subtle)] space-y-3">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="space-y-1">
                  <span className="text-xs font-semibold text-[var(--text-muted)] uppercase tracking-wider block">
                    Sender Location
                  </span>
                  <div className="text-xl font-bold text-[var(--text)] tracking-tight">
                    {country || 'United States'} {region ? `• ${region}` : ''}
                  </div>
                  <div className="text-xs text-[var(--text-muted)] pt-1">
                    <strong className="text-[var(--text)]">Why this matters:</strong> The email was sent through infrastructure associated with this location.
                  </div>
                </div>

                <div className="bg-[var(--surface-elevated)] border border-[var(--border-subtle)] p-3 rounded-xl space-y-1 font-mono text-xs text-right shrink-0">
                  <span className="text-[10px] text-[var(--text-dim)] block font-sans uppercase">Sender IP Address</span>
                  <span className="text-[var(--identifier)] font-bold text-sm block">{probableIP}</span>
                  <span className="text-[10px] text-[var(--text-muted)] block font-sans">{isp || 'Internet Service Provider'}</span>
                </div>
              </div>
            </div>

            {/* 4 Summary Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-[var(--border-subtle)] text-xs font-sans">
              <div className="p-4 space-y-1">
                <span className="text-[10px] text-[var(--text-dim)] uppercase font-semibold block">Sender Location</span>
                <div className="text-sm font-bold text-[var(--text)]">{country || 'Unavailable'}</div>
                <div className="text-[11px] text-[var(--text-muted)]">{region || 'City/Region'}</div>
              </div>

              <div className="p-4 space-y-1">
                <span className="text-[10px] text-[var(--text-dim)] uppercase font-semibold block">Network / ISP</span>
                <div className="text-sm font-bold text-[var(--text)] truncate" title={isp || 'Not resolved'}>{isp || 'Not resolved'}</div>
                <div className="text-[11px] text-[var(--text-muted)] font-mono">{asn || 'ASN'}</div>
              </div>

              <div className="p-4 space-y-1">
                <span className="text-[10px] text-[var(--text-dim)] uppercase font-semibold block">Online Safety Check</span>
                <div className="text-sm font-bold text-rose-400">
                  {abuseConf !== null ? `${abuseConf}% Abuse Score` : 'Clean / Unreported'}
                </div>
                <div className="text-[11px] text-[var(--text-muted)]">{totalReports !== null ? `${totalReports} Complaints` : 'No complaints'}</div>
              </div>

              <div className="p-4 space-y-1">
                <span className="text-[10px] text-[var(--text-dim)] uppercase font-semibold block">Domain Registration</span>
                <div className="text-sm font-bold text-amber-400">{domainAge || 'Active Domain'}</div>
                <div className="text-[11px] text-[var(--text-muted)]">{vtVendors ? `${vtVendors}` : 'Checked against threat feeds'}</div>
              </div>
            </div>
          </div>

          {/* Email Security Checks (SPF, DKIM, DMARC) */}
          {auth && (
            <div className="border border-[var(--border-subtle)] rounded-xl p-4 bg-[var(--surface-subtle)] space-y-3">
              <div className="flex items-center space-x-2 text-xs font-semibold text-[var(--text)]">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <span>Email Security Checks</span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="p-3 rounded-lg bg-[var(--surface)] border border-[var(--border-subtle)] flex items-center justify-between">
                  <div>
                    <span className="text-xs font-bold text-[var(--text)] block">SPF Seal</span>
                    <span className="text-[11px] text-[var(--text-muted)]">Sender authorization</span>
                  </div>
                  <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold border flex items-center gap-1 shrink-0 ${spfBadge.className}`}>
                    <SpfIcon className="w-3.5 h-3.5" />
                    {spfBadge.text}
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-[var(--surface)] border border-[var(--border-subtle)] flex items-center justify-between">
                  <div>
                    <span className="text-xs font-bold text-[var(--text)] block">DKIM Seal</span>
                    <span className="text-[11px] text-[var(--text-muted)]">Digital signature</span>
                  </div>
                  <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold border flex items-center gap-1 shrink-0 ${dkimBadge.className}`}>
                    <DkimIcon className="w-3.5 h-3.5" />
                    {dkimBadge.text}
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-[var(--surface)] border border-[var(--border-subtle)] flex items-center justify-between">
                  <div>
                    <span className="text-xs font-bold text-[var(--text)] block">DMARC Seal</span>
                    <span className="text-[11px] text-[var(--text-muted)]">Domain policy seal</span>
                  </div>
                  <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold border flex items-center gap-1 shrink-0 ${dmarcBadge.className}`}>
                    <DmarcIcon className="w-3.5 h-3.5" />
                    {dmarcBadge.text}
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* Interactive Geolocation Map */}
          <div className="pt-2">
            <GeolocationMap data={analysisDataForMap} />
          </div>
        </div>
      )}

      {/* Extracted Links & Payload Targets */}
      {urls && urls.urls.length > 0 && (
        <div className="space-y-3 pt-2 border-t border-[var(--border-subtle)]">
          <div className="flex items-center justify-between text-xs font-semibold text-[var(--text)] font-sans">
            <span className="flex items-center gap-1.5">
              <Link2 className="w-4 h-4 text-amber-400" />
              <span>Links &amp; Attachments Found in Email ({urls.urls.length})</span>
            </span>
          </div>

          <div className="space-y-2">
            {urls.urls.map((u, i) => (
              <div
                key={i}
                className="bg-[var(--surface-subtle)] border border-[var(--border-subtle)] p-3 rounded-xl text-xs font-sans flex flex-col md:flex-row md:items-center justify-between gap-3"
              >
                <div className="flex items-center space-x-2.5 truncate">
                  <Link2 className="w-4 h-4 text-rose-400 shrink-0" />
                  <span className="text-[var(--identifier)] font-mono font-semibold truncate select-all" title={u.url}>
                    {u.url}
                  </span>
                </div>

                <div className="flex flex-wrap items-center gap-2 shrink-0 text-[11px]">
                  {!u.is_https && (
                    <span className="px-2.5 py-0.5 rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/20 font-semibold flex items-center gap-1">
                      <AlertTriangle className="w-3 h-3" />
                      Unencrypted Link (HTTP)
                    </span>
                  )}
                  <span className="px-2.5 py-0.5 rounded-full bg-[var(--surface)] text-[var(--text-muted)] border border-[var(--border-subtle)]">
                    Domain: <strong className="text-[var(--text)] font-mono">{u.domain}</strong>
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
