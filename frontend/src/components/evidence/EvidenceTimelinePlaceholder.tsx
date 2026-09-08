import React from 'react';
import { Clock } from 'lucide-react';
import type { RelayHop } from '../../types/investigation';

interface EvidenceTimelinePlaceholderProps {
  hops?: RelayHop[];
}

export const EvidenceTimelinePlaceholder: React.FC<EvidenceTimelinePlaceholderProps> = ({
  hops = [],
}) => {
  return (
    <div className="surface-card p-5 border border-[#1e2430] space-y-4">
      <div className="flex items-center justify-between pb-3 border-b border-[#1e2430]">
        <div className="flex items-center space-x-2">
          <Clock className="w-4 h-4 text-[#8b5cf6]" />
          <h3 className="text-sm font-semibold text-[#f1f5f9] tracking-tight">
            Relay Delivery Chronology (Received Headers)
          </h3>
        </div>
        <span className="text-xs font-mono text-[#64748b]">
          TOTAL HOPS: <span className="text-[#f1f5f9]">{hops.length}</span>
        </span>
      </div>

      {hops.length === 0 ? (
        <div className="text-xs font-mono text-[#64748b] p-3 text-center">
          No received relay headers reconstructed.
        </div>
      ) : (
        <div className="space-y-2 relative before:absolute before:left-3 before:top-2 before:bottom-2 before:w-0.5 before:bg-[#1e2430]">
          {hops.map((hop) => (
            <div key={hop.hop_number} className="relative pl-7 space-y-1">
              <span className="absolute left-1.5 top-2 w-3 h-3 rounded-full bg-[#12151b] border-2 border-[#8b5cf6] -translate-x-1/2" />
              <div className="bg-[#12151b] border border-[#1e2430] p-2.5 rounded text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[11px] font-semibold text-[#f1f5f9]">
                    Hop #{hop.hop_number}
                  </span>
                  <div className="flex items-center gap-1.5">
                    {hop.extracted_ips.map((ip) => (
                      <span
                        key={ip.address}
                        className="font-mono text-[10px] px-1.5 py-0.2 bg-[#171b23] border border-[#2a3242] rounded text-[#06b6d4]"
                      >
                        {ip.address}
                      </span>
                    ))}
                  </div>
                </div>
                <div className="text-[11px] font-mono text-[#94a3b8] truncate mt-0.5">
                  Hosts: {hop.hostnames.join(' → ') || 'Direct peer'}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
