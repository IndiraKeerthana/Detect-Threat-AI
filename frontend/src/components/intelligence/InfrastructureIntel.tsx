import React from 'react';
import { Server, Link2, ShieldAlert, Globe, Network, Activity, AlertTriangle } from 'lucide-react';
import type { RelayAnalysis, ThreatIntelligence, URLDomainAnalysis } from '../../types/investigation';
import { SectionHeader } from '../investigation/SectionHeader';

interface InfrastructureIntelProps {
  relay?: RelayAnalysis | null;
  intelligence?: ThreatIntelligence | null;
  urls?: URLDomainAnalysis | null;
}

export const InfrastructureIntel: React.FC<InfrastructureIntelProps> = ({
  relay,
  intelligence,
  urls,
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
        coords = `${d.latitude.toFixed(3)}, ${d.longitude.toFixed(3)}`;
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
        vtVendors = `${mal}/${total} VENDORS`;
      }

      if (!domainAge && typeof d.age_days === 'number') {
        domainAge = `${d.age_days} Days Old`;
      } else if (!domainAge && typeof d.domain_age_days === 'number') {
        domainAge = `${d.domain_age_days} Days Old`;
      }
    }
  }

  return (
    <div className="surface-card p-6 border border-[#1e2430] space-y-5">
      {/* Section Header */}
      <SectionHeader
        index="04"
        tag="INFRASTRUCTURE INTELLIGENCE"
        title="Probable Source Infrastructure & Multi-Provider Telemetry"
        subtitle="Correlated Autonomous Systems, IP relays, threat reputation feeds, and payload entities"
        action={
          <div className="flex flex-wrap items-center gap-2 text-[10px] font-mono">
            {providers.map((p) => (
              <span
                key={p.provider}
                className="px-2 py-0.5 rounded bg-[#0f1217] border border-[#1e2430] text-[#94a3b8] flex items-center gap-1"
              >
                <span className="w-1.5 h-1.5 rounded-full bg-[#10b981]" />
                <span>{p.provider}:</span>
                <span className="text-[#6ee7b7] font-semibold">{p.status.toUpperCase()}</span>
              </span>
            ))}
          </div>
        }
      />

      {/* Probable Source Relay Infrastructure Spotlight */}
      {probableSource && (
        <div className="bg-[#0a0c10] border border-[#1e2430] p-4 rounded-lg flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center space-x-2 text-[10px] font-mono text-[#64748b] uppercase">
              <Server className="w-3.5 h-3.5 text-[#06b6d4]" />
              <span>PROBABLE ORIGIN RELAY INFRASTRUCTURE</span>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-xl font-mono font-bold text-[#06b6d4] tracking-tight">
                {probableSource.address || 'Unknown'}
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#0c232c] text-[#67e8f9] border border-[#154c5e] font-bold">
                CONFIDENCE: {probableSource.confidence.toUpperCase()}
              </span>
            </div>
            <p className="text-xs text-[#94a3b8] font-sans">
              {probableSource.reason}
            </p>
          </div>

          <div className="flex items-center gap-3 self-start md:self-auto text-xs font-mono">
            <div className="bg-[#12151b] border border-[#1e2430] px-3 py-2 rounded text-right">
              <span className="text-[10px] text-[#64748b] uppercase block">RELAY POSITION</span>
              <span className="text-[#f1f5f9] font-semibold">{hopPosition}</span>
            </div>
            <div className="bg-[#12151b] border border-[#1e2430] px-3 py-2 rounded text-right">
              <span className="text-[10px] text-[#64748b] uppercase block">REVERSE DNS</span>
              <span className="text-[#94a3b8] truncate block max-w-xs">{reverseDns}</span>
            </div>
          </div>
        </div>
      )}

      {/* 4 Dense Forensic Quadrants */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono">
        {/* 1. IDENTITY */}
        <div className="bg-[#12151b] border border-[#1e2430] p-3.5 rounded space-y-2">
          <div className="flex items-center justify-between text-[10px] uppercase text-[#64748b] pb-1 border-b border-[#1e2430]">
            <span className="flex items-center gap-1 text-[#06b6d4]">
              <Server className="w-3 h-3" />
              01 // IDENTITY
            </span>
            <span>HOST</span>
          </div>

          <div className="space-y-1.5 text-[11px]">
            <div className="flex justify-between">
              <span className="text-[#64748b]">IP Address:</span>
              <span className="text-[#f1f5f9] font-bold">{probableIP || 'Unavailable'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#64748b]">Classification:</span>
              <span className="text-[#94a3b8]">{probableIP ? ipClassification : 'Unavailable'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#64748b]">Reverse DNS:</span>
              <span className="text-[#67e8f9] truncate max-w-[120px]" title={probableIP ? reverseDns : 'Unavailable'}>
                {probableIP ? reverseDns : 'Unavailable'}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#64748b]">Scope:</span>
              <span className="text-[#f1f5f9]">{probableIP ? scope : 'Unavailable'}</span>
            </div>
          </div>
        </div>

        {/* 2. NETWORK */}
        <div className="bg-[#12151b] border border-[#1e2430] p-3.5 rounded space-y-2">
          <div className="flex items-center justify-between text-[10px] uppercase text-[#64748b] pb-1 border-b border-[#1e2430]">
            <span className="flex items-center gap-1 text-[#06b6d4]">
              <Network className="w-3 h-3" />
              02 // NETWORK
            </span>
            <span>ROUTING</span>
          </div>

          <div className="space-y-1.5 text-[11px]">
            <div className="flex justify-between">
              <span className="text-[#64748b]">Autonomous Sys:</span>
              <span className="text-[#f1f5f9] font-bold">{asn || 'Not resolved'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#64748b]">ISP / Org:</span>
              <span className="text-[#94a3b8] truncate max-w-[120px]" title={isp || 'Not resolved'}>
                {isp || 'Not resolved'}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#64748b]">Prefix / CIDR:</span>
              <span className="text-[#f1f5f9]">{prefix || 'Not resolved'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#64748b]">Hops Reconstructed:</span>
              <span className="text-[#f1f5f9] font-bold">{reconstructedHops}</span>
            </div>
          </div>
        </div>

        {/* 3. GEOLOCATION */}
        <div className="bg-[#12151b] border border-[#1e2430] p-3.5 rounded space-y-2">
          <div className="flex items-center justify-between text-[10px] uppercase text-[#64748b] pb-1 border-b border-[#1e2430]">
            <span className="flex items-center gap-1 text-[#06b6d4]">
              <Globe className="w-3 h-3" />
              03 // GEOLOCATION
            </span>
            <span>TELEMETRY</span>
          </div>

          <div className="space-y-1.5 text-[11px]">
            <div className="flex justify-between">
              <span className="text-[#64748b]">Country:</span>
              <span className="text-[#f1f5f9] font-bold">{country || 'Unavailable'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#64748b]">Region / City:</span>
              <span className="text-[#94a3b8]">{region || 'Unavailable'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#64748b]">Coordinates:</span>
              <span className="text-[#67e8f9]">{coords || 'Unavailable'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#64748b]">ISP Allocation:</span>
              <span className="text-[#94a3b8]">{isp ? 'Verified' : 'Unavailable'}</span>
            </div>
          </div>
        </div>

        {/* 4. REPUTATION */}
        <div className="bg-[#12151b] border border-[#1e2430] p-3.5 rounded space-y-2">
          <div className="flex items-center justify-between text-[10px] uppercase text-[#64748b] pb-1 border-b border-[#1e2430]">
            <span className="flex items-center gap-1 text-[#ef4444]">
              <Activity className="w-3 h-3" />
              04 // REPUTATION
            </span>
            <span>FEEDS</span>
          </div>

          <div className="space-y-1.5 text-[11px]">
            <div className="flex justify-between">
              <span className="text-[#64748b]">AbuseIPDB:</span>
              <span className="text-[#ef4444] font-bold">
                {abuseConf !== null ? `${abuseConf}% ABUSE CONF` : 'Not evaluated'}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#64748b]">Reports Count:</span>
              <span className="text-[#fca5a5]">
                {totalReports !== null ? `${totalReports} Reports` : 'None recorded'}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#64748b]">VirusTotal:</span>
              <span className="text-[#ef4444] font-bold">{vtVendors || 'Not evaluated'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#64748b]">Domain Age (RDAP):</span>
              <span className="text-[#fcd34d] font-bold">{domainAge || 'Unavailable'}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Extracted URLs & Payload Targets Table */}
      {urls && urls.urls.length > 0 && (
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs font-mono text-[#64748b] px-1">
            <span className="uppercase tracking-wider">
              EXTRACTED PAYLOAD TARGETS & NORMALIZED URL ENTITIES ({urls.urls.length})
            </span>
            <span>HTTP / UNENCRYPTED TRANSPORT HIGHLIGHTED</span>
          </div>

          <div className="space-y-2">
            {urls.urls.map((u, i) => (
              <div
                key={i}
                className="bg-[#12151b] border border-[#1e2430] p-3 rounded-md text-xs font-mono flex flex-col md:flex-row md:items-center justify-between gap-3"
              >
                <div className="flex items-center space-x-2.5 truncate">
                  <Link2 className="w-4 h-4 text-[#ef4444] shrink-0" />
                  <span className="text-[#fca5a5] font-semibold truncate select-all" title={u.url}>
                    {u.url}
                  </span>
                </div>

                <div className="flex flex-wrap items-center gap-2 shrink-0 text-[10px]">
                  {!u.is_https && (
                    <span className="px-2 py-0.5 rounded bg-[#261114] text-[#fca5a5] border border-[#5c1d24] font-bold flex items-center gap-1">
                      <AlertTriangle className="w-2.5 h-2.5" />
                      UNENCRYPTED (HTTP)
                    </span>
                  )}
                  {/^(\d{1,3}\.){3}\d{1,3}$/.test(u.domain) && (
                    <span className="px-2 py-0.5 rounded bg-[#261114] text-[#fca5a5] border border-[#5c1d24] font-bold">
                      BARE IP-LITERAL
                    </span>
                  )}
                  <span className="px-2 py-0.5 rounded bg-[#171b23] text-[#94a3b8] border border-[#2a3242]">
                    TARGET DOMAIN: {u.domain}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Threat Provider Detailed Observations Ledger */}
      {observations.length > 0 && (
        <div className="space-y-2 pt-1">
          <div className="text-xs font-mono text-[#64748b] px-1 uppercase tracking-wider">
            RAW PROVIDER OBSERVATION SIGNALS ({observations.length})
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
            {observations.map((obs, idx) => (
              <div
                key={idx}
                className="bg-[#0f1217] border border-[#1e2430] p-3 rounded-md space-y-1.5"
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-[#f1f5f9] flex items-center gap-1.5">
                    <ShieldAlert className="w-3.5 h-3.5 text-[#06b6d4]" />
                    {obs.provider}
                  </span>
                  <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#171b23] text-[#94a3b8] border border-[#2a3242]">
                    {obs.kind}
                  </span>
                </div>

                <div className="text-[11px] text-[#06b6d4] truncate">
                  {obs.entity_type}: <span className="text-[#f1f5f9] font-medium">{obs.entity}</span>
                </div>

                <div className="space-y-0.5 pt-1 text-[11px] text-[#94a3b8] border-t border-[#1e2430]">
                  {obs.evidence.map((ev, i) => (
                    <div key={i} className="text-[10px] text-[#64748b] truncate">
                      • {ev}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
