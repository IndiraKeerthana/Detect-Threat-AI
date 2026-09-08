import { Server, Link2 } from 'lucide-react';
import type { RelayAnalysis, ThreatIntelligence, URLDomainAnalysis } from '../../types/investigation';

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

  return (
    <div className="surface-card p-5 border border-[#1e2430] space-y-4">
      {/* Title */}
      <div className="flex items-center justify-between pb-3 border-b border-[#1e2430]">
        <div className="flex items-center space-x-2">
          <Server className="w-4 h-4 text-[#06b6d4]" />
          <h3 className="text-sm font-semibold text-[#f1f5f9] tracking-tight">
            Infrastructure & Threat Intelligence Telemetry
          </h3>
        </div>
        <span className="text-xs font-mono text-[#64748b]">
          OBSERVATIONS: <span className="text-[#f1f5f9]">{intelligence?.observations?.length || 0}</span>
        </span>
      </div>

      {/* Probable Source Infrastructure Header */}
      {probableSource && (
        <div className="bg-[#0f1217] border border-[#1e2430] p-3.5 rounded flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="space-y-0.5">
            <span className="text-[10px] font-mono text-[#64748b] uppercase block">
              Probable Origin Relay Infrastructure
            </span>
            <div className="text-sm font-mono font-bold text-[#f1f5f9] flex items-center gap-2">
              <span className="text-[#06b6d4]">{probableSource.address || 'Unknown'}</span>
              <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[#0c232c] text-[#67e8f9] border border-[#154c5e]">
                CONFIDENCE: {probableSource.confidence.toUpperCase()}
              </span>
            </div>
            <p className="text-[11px] text-[#94a3b8] mt-0.5">{probableSource.reason}</p>
          </div>
        </div>
      )}

      {/* Extracted URLs Analysis */}
      {urls && urls.urls.length > 0 && (
        <div className="space-y-2">
          <div className="text-[11px] font-mono text-[#64748b] uppercase">
            Extracted URLs & Payload Targets ({urls.urls.length})
          </div>
          <div className="space-y-1.5">
            {urls.urls.map((u, i) => (
              <div
                key={i}
                className="bg-[#12151b] border border-[#1e2430] p-2.5 rounded text-xs font-mono flex flex-col sm:flex-row sm:items-center justify-between gap-2"
              >
                <div className="flex items-center space-x-2 truncate">
                  <Link2 className="w-3.5 h-3.5 text-[#64748b] shrink-0" />
                  <span className="text-[#fca5a5] truncate" title={u.url}>
                    {u.url}
                  </span>
                </div>
                <div className="flex items-center gap-2 shrink-0 text-[10px]">
                  {!u.is_https && (
                    <span className="px-1.5 py-0.2 rounded bg-[#261114] text-[#fca5a5] border border-[#5c1d24]">
                      HTTP (NO TLS)
                    </span>
                  )}
                  <span className="px-1.5 py-0.2 rounded bg-[#171b23] text-[#94a3b8] border border-[#2a3242]">
                    TARGET: {u.domain}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Threat Observations List */}
      {intelligence && intelligence.observations.length > 0 && (
        <div className="space-y-2">
          <div className="text-[11px] font-mono text-[#64748b] uppercase">
            Provider Observations & Live Signals
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
            {intelligence.observations.map((obs, idx) => (
              <div
                key={idx}
                className="bg-[#12151b] border border-[#1e2430] p-3 rounded text-xs space-y-1"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono font-semibold text-[#f1f5f9]">{obs.provider}</span>
                  <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[#171b23] text-[#94a3b8] border border-[#2a3242]">
                    {obs.kind}
                  </span>
                </div>
                <div className="text-[11px] font-mono text-[#06b6d4] truncate">
                  {obs.entity_type}: {obs.entity}
                </div>
                <div className="space-y-0.5 pt-1 text-[11px] text-[#94a3b8]">
                  {obs.evidence.map((ev, i) => (
                    <div key={i} className="font-mono text-[10px] text-[#64748b]">
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
