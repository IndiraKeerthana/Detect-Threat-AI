import React from 'react';
import { Server, Link2, Globe, Network, Activity, AlertTriangle } from 'lucide-react';
import type { RelayAnalysis, ThreatIntelligence, URLDomainAnalysis, EmailAnalysisResponse } from '../../types/investigation';
import { SectionHeader } from '../investigation/SectionHeader';
import { GeolocationMap } from '../map/GeolocationMap';

interface InfrastructureIntelProps {
  relay?: RelayAnalysis | null;
  intelligence?: ThreatIntelligence | null;
  urls?: URLDomainAnalysis | null;
  data?: EmailAnalysisResponse | null;
}

export const InfrastructureIntel: React.FC<InfrastructureIntelProps> = ({
  relay,
  intelligence,
  urls,
  data,
}) => {
  const probableSource = relay?.probable_source_infrastructure;
  const observations = intelligence?.observations || [];
  const providers = intelligence?.provider_status || [];

  const probableIP = probableSource?.address || relay?.extracted_ips?.[0]?.address || null;
  const targetIpObj = relay?.extracted_ips?.find((ip) => ip.address === probableIP);
  const probableHop = relay?.relay_hops?.find((h) =>
    h.extracted_ips?.some((ip) => ip.address === probableIP)
  );
  const hopPosition = probableHop ? `Hop #${probableHop.hop_number}` : (probableIP ? 'Perimeter Entry' : 'Unknown');
  const reverseDns = probableHop?.hostnames?.[0] || 'Not resolved';
  const ipClassification = targetIpObj?.classification || (probableIP ? 'Public Relay' : 'Unavailable');
  const scope = targetIpObj?.is_public_source_candidate ? 'External Ingress' : (probableIP ? 'Internal / Boundary' : 'Unavailable');
  const reconstructedHops = relay?.relay_hops?.length ? `${relay.relay_hops.length} Hops` : 'None';

  let asn: string | null = null;
  let isp: string | null = null;
  let prefix: string | null = null;
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
      if (!prefix && typeof d.cidr === 'string') prefix = d.cidr;
      else if (!prefix && typeof d.network === 'string') prefix = d.network;

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

  // Synthesize EmailAnalysisResponse structure for GeolocationMap if full object isn't passed directly
  const analysisDataForMap: EmailAnalysisResponse | null = data || (
    relay || intelligence ? ({
      relay_analysis: relay,
      threat_intelligence: intelligence,
      security_analysis: { url_analysis: urls },
    } as unknown as EmailAnalysisResponse) : null
  );

  return (
    <div className="surface-card p-5 border border-[var(--border-subtle)] space-y-6">
      {/* Section Header with Compact Provider Status Strip */}
      <SectionHeader
        index="05"
        title="Infrastructure intelligence"
        subtitle="Correlated autonomous systems, IP relays, threat reputation feeds, and payload entities."
        action={
          providers.length > 0 ? (
            <div className="flex flex-wrap items-center gap-1.5 text-xs font-mono text-[var(--text-muted)]">
              <span className="text-[var(--text-dim)] uppercase tracking-wider text-[10px]">Provider status:</span>
              {providers.map((p, idx) => {
                const isOk = p.status === 'available';
                const isDegraded = p.status === 'degraded';
                const symbol = isOk ? '✓' : isDegraded ? '~' : '✕';
                const colorClass = isOk ? 'text-[var(--state-pass)]' : isDegraded ? 'text-[var(--severity-medium)]' : 'text-[var(--text-dim)]';
                return (
                  <span key={p.provider} className="inline-flex items-center gap-1">
                    {idx > 0 && <span className="text-[var(--text-dim)] mr-0.5">·</span>}
                    <span className="text-[var(--text)] font-medium">{p.provider}</span>
                    <span className={`${colorClass} font-bold`}>{symbol}</span>
                  </span>
                );
              })}
            </div>
          ) : undefined
        }
      />

      {/* Single Consolidated 4-Column Infrastructure Summary */}
      {!hasVerifiedInfrastructure ? (
        <div className="border border-[var(--border-subtle)] rounded-lg p-6 bg-[var(--surface-subtle)] text-center space-y-2">
          <div className="w-10 h-10 rounded-full bg-[var(--surface)] border border-[var(--border-subtle)] mx-auto flex items-center justify-center text-[var(--text-dim)]">
            <Server className="w-5 h-5" />
          </div>
          <h3 className="text-xs font-bold text-[var(--text)] uppercase tracking-wider font-sans">
            NO VERIFIED ORIGIN INFRASTRUCTURE
          </h3>
          <p className="text-xs text-[var(--text-muted)] font-sans max-w-md mx-auto leading-relaxed">
            No public source IP address could be established from the available Received header chain. The system does not infer or fabricate location, ASN, hosting provider, or attacker identity.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          <div className="border border-[var(--border-subtle)] rounded-lg bg-[var(--surface-subtle)] overflow-hidden">
            {/* Probable Source Banner */}
            {probableSource && (
              <div className="p-4 bg-[var(--surface)] border-b border-[var(--border-subtle)] flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="space-y-1">
                  <div className="flex items-center space-x-2 text-[10px] font-sans text-[var(--text-dim)] uppercase tracking-wider">
                    <Server className="w-3.5 h-3.5 text-[var(--identifier)]" />
                    <span>Probable origin relay infrastructure</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-lg font-mono font-bold text-[var(--identifier)] tracking-tight">
                      {probableSource.address}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[var(--surface-elevated)] text-[var(--text)] border border-[var(--border-subtle)] font-bold">
                      CONFIDENCE: {probableSource.confidence.toUpperCase()}
                    </span>
                  </div>
                  <p className="text-xs text-[var(--text-muted)] font-sans">
                    {probableSource.reason}
                  </p>
                </div>

                <div className="flex items-center gap-3 self-start md:self-auto text-xs font-sans">
                  <div className="bg-[var(--surface-elevated)] border border-[var(--border-subtle)] px-3 py-1.5 rounded text-right">
                    <span className="text-[10px] text-[var(--text-dim)] uppercase block font-sans">Relay position</span>
                    <span className="text-[var(--text)] font-semibold font-mono">{hopPosition}</span>
                  </div>
                  <div className="bg-[var(--surface-elevated)] border border-[var(--border-subtle)] px-3 py-1.5 rounded text-right">
                    <span className="text-[10px] text-[var(--text-dim)] uppercase block font-sans">Reverse DNS</span>
                    <span className="text-[var(--identifier)] font-mono truncate block max-w-xs">{reverseDns}</span>
                  </div>
                </div>
              </div>
            )}

            {/* 4 Internal Columns with Hairline Vertical Dividers */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-[var(--border-subtle)] text-xs font-sans">
              {/* 1. IDENTITY */}
              <div className="p-4 space-y-2.5">
                <div className="flex items-center justify-between text-[10px] uppercase text-[var(--text-dim)] pb-1.5 border-b border-[var(--border-subtle)] font-sans">
                  <span className="flex items-center gap-1.5 font-bold text-[var(--identifier)]">
                    <Server className="w-3.5 h-3.5" />
                    Identity
                  </span>
                  <span>HOST</span>
                </div>
                <div className="space-y-1.5 text-[11px]">
                  <div className="flex justify-between"><span className="text-[var(--text-muted)]">IP address:</span><span className="text-[var(--identifier)] font-mono font-bold">{probableIP || 'Unavailable'}</span></div>
                  <div className="flex justify-between"><span className="text-[var(--text-muted)]">Classification:</span><span className="text-[var(--text)]">{ipClassification}</span></div>
                  <div className="flex justify-between"><span className="text-[var(--text-muted)]">Reverse DNS:</span><span className="text-[var(--identifier)] font-mono truncate max-w-[110px]" title={reverseDns}>{reverseDns}</span></div>
                  <div className="flex justify-between"><span className="text-[var(--text-muted)]">Scope:</span><span className="text-[var(--text)]">{scope}</span></div>
                </div>
              </div>

              {/* 2. NETWORK */}
              <div className="p-4 space-y-2.5">
                <div className="flex items-center justify-between text-[10px] uppercase text-[var(--text-dim)] pb-1.5 border-b border-[var(--border-subtle)] font-sans">
                  <span className="flex items-center gap-1.5 font-bold text-[var(--identifier)]">
                    <Network className="w-3.5 h-3.5" />
                    Network
                  </span>
                  <span>ROUTING</span>
                </div>
                <div className="space-y-1.5 text-[11px]">
                  <div className="flex justify-between"><span className="text-[var(--text-muted)]">Autonomous system:</span><span className="text-[var(--identifier)] font-mono font-bold">{asn || 'Not resolved'}</span></div>
                  <div className="flex justify-between"><span className="text-[var(--text-muted)]">ISP / Organization:</span><span className="text-[var(--text)] truncate max-w-[110px]" title={isp || 'Not resolved'}>{isp || 'Not resolved'}</span></div>
                  <div className="flex justify-between"><span className="text-[var(--text-muted)]">Prefix / CIDR:</span><span className="text-[var(--text)] font-mono">{prefix || 'Not resolved'}</span></div>
                  <div className="flex justify-between"><span className="text-[var(--text-muted)]">Reconstructed hops:</span><span className="text-[var(--text)] font-bold">{reconstructedHops}</span></div>
                </div>
              </div>

              {/* 3. GEOLOCATION */}
              <div className="p-4 space-y-2.5">
                <div className="flex items-center justify-between text-[10px] uppercase text-[var(--text-dim)] pb-1.5 border-b border-[var(--border-subtle)] font-sans">
                  <span className="flex items-center gap-1.5 font-bold text-[var(--identifier)]">
                    <Globe className="w-3.5 h-3.5" />
                    Geolocation
                  </span>
                  <span>TELEMETRY</span>
                </div>
                <div className="space-y-1.5 text-[11px]">
                  <div className="flex justify-between"><span className="text-[var(--text-muted)]">Country:</span><span className="text-[var(--text)] font-bold">{country || 'Unavailable'}</span></div>
                  <div className="flex justify-between"><span className="text-[var(--text-muted)]">Region / City:</span><span className="text-[var(--text-muted)]">{region || 'Unavailable'}</span></div>
                  <div className="flex justify-between"><span className="text-[var(--text-muted)]">Coordinates:</span><span className="text-[var(--identifier)] font-mono">{coords || 'Unavailable'}</span></div>
                  <div className="flex justify-between"><span className="text-[var(--text-muted)]">ISP allocation:</span><span className="text-[var(--text)]">{isp ? 'Verified' : 'Unavailable'}</span></div>
                </div>
              </div>

              {/* 4. REPUTATION */}
              <div className="p-4 space-y-2.5">
                <div className="flex items-center justify-between text-[10px] uppercase text-[var(--text-dim)] pb-1.5 border-b border-[var(--border-subtle)] font-sans">
                  <span className="flex items-center gap-1.5 font-bold text-[var(--severity-high)]">
                    <Activity className="w-3.5 h-3.5" />
                    Reputation
                  </span>
                  <span>FEEDS</span>
                </div>
                <div className="space-y-1.5 text-[11px]">
                  <div className="flex justify-between"><span className="text-[var(--text-muted)]">AbuseIPDB:</span><span className="text-[var(--severity-critical)] font-bold">{abuseConf !== null ? `${abuseConf}% abuse score` : 'Not evaluated'}</span></div>
                  <div className="flex justify-between"><span className="text-[var(--text-muted)]">Reports count:</span><span className="text-[var(--text)]">{totalReports !== null ? `${totalReports} reports` : 'None recorded'}</span></div>
                  <div className="flex justify-between"><span className="text-[var(--text-muted)]">VirusTotal:</span><span className="text-[var(--severity-critical)] font-bold">{vtVendors || 'Not evaluated'}</span></div>
                  <div className="flex justify-between"><span className="text-[var(--text-muted)]">Domain age (RDAP):</span><span className="text-[var(--severity-medium)] font-bold">{domainAge || 'Unavailable'}</span></div>
                </div>
              </div>
            </div>
          </div>

          {/* Integrated Geolocation Map Area directly below summary */}
          <div className="pt-2">
            <GeolocationMap data={analysisDataForMap} />
          </div>
        </div>
      )}

      {/* Extracted URLs & Payload Targets */}
      {urls && urls.urls.length > 0 && (
        <div className="space-y-2 pt-2 border-t border-[var(--border-subtle)]">
          <div className="text-xs font-semibold text-[var(--text)] font-sans">
            Extracted payload targets & normalized URL entities ({urls.urls.length})
          </div>

          <div className="space-y-2">
            {urls.urls.map((u, i) => (
              <div
                key={i}
                className="bg-[var(--surface-subtle)] border border-[var(--border-subtle)] p-3 rounded text-xs font-sans flex flex-col md:flex-row md:items-center justify-between gap-3"
              >
                <div className="flex items-center space-x-2.5 truncate">
                  <Link2 className="w-4 h-4 text-[var(--severity-critical)] shrink-0" />
                  <span className="text-[var(--identifier)] font-mono font-semibold truncate select-all" title={u.url}>
                    {u.url}
                  </span>
                </div>

                <div className="flex flex-wrap items-center gap-2 shrink-0 text-[10px]">
                  {!u.is_https && (
                    <span className="px-2 py-0.5 rounded bg-[var(--surface-elevated)] text-[var(--severity-critical)] border border-[var(--border-subtle)] font-bold flex items-center gap-1 font-mono">
                      <AlertTriangle className="w-2.5 h-2.5" />
                      UNENCRYPTED (HTTP)
                    </span>
                  )}
                  {/^(\d{1,3}\.){3}\d{1,3}$/.test(u.domain) && (
                    <span className="px-2 py-0.5 rounded bg-[var(--surface-elevated)] text-[var(--severity-critical)] border border-[var(--border-subtle)] font-bold font-mono">
                      BARE IP-LITERAL
                    </span>
                  )}
                  <span className="px-2 py-0.5 rounded bg-[var(--surface)] text-[var(--text-muted)] border border-[var(--border-subtle)]">
                    Target domain: <strong className="text-[var(--text)] font-mono">{u.domain}</strong>
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
