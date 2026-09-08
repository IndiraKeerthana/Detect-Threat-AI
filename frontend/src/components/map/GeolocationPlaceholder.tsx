import { MapPin, Compass } from 'lucide-react';
import type { ExtractedIP } from '../../types/investigation';

interface GeolocationPlaceholderProps {
  ips?: ExtractedIP[];
  primaryIp?: string | null;
}

export const GeolocationPlaceholder: React.FC<GeolocationPlaceholderProps> = ({
  ips = [],
  primaryIp,
}) => {
  return (
    <div className="surface-card p-5 border border-[#1e2430] space-y-4">
      <div className="flex items-center justify-between pb-3 border-b border-[#1e2430]">
        <div className="flex items-center space-x-2">
          <MapPin className="w-4 h-4 text-[#06b6d4]" />
          <h3 className="text-sm font-semibold text-[#f1f5f9] tracking-tight">
            Relay Geolocation & Routing Origin
          </h3>
        </div>
        <div className="flex items-center space-x-2 text-[10px] font-mono">
          <span className="text-[#64748b]">IPS: <strong className="text-[#f1f5f9]">{ips.length || 1}</strong></span>
          <span className="px-1.5 py-0.2 rounded bg-[#171b23] text-[#94a3b8] border border-[#2a3242]">
            MAP ENGINE FOUNDATION
          </span>
        </div>
      </div>

      {/* Map Canvas Placeholder */}
      <div className="relative h-48 bg-[#0a0c10] border border-[#1e2430] rounded-md overflow-hidden flex flex-col items-center justify-center p-4 text-center">
        <div
          className="absolute inset-0 opacity-10"
          style={{
            backgroundImage: `radial-gradient(#06b6d4 1px, transparent 1px)`,
            backgroundSize: '16px 16px',
          }}
        />

        <div className="relative z-10 space-y-1.5 max-w-sm">
          <Compass className="w-6 h-6 text-[#06b6d4] mx-auto opacity-75" />
          <div className="text-xs font-mono font-medium text-[#f1f5f9]">
            Primary Ingress Origin: <span className="text-[#06b6d4]">{primaryIp || '198.51.100.10'}</span>
          </div>
          <p className="text-[11px] text-[#64748b]">
            Allocated to TEST-NET-2 • Autonomous System ASN59201 • United States [US]
          </p>
        </div>

        <div className="absolute bottom-2 left-3 text-[10px] font-mono text-[#475569]">
          Leaflet / MapLibre GL Integration Slot
        </div>
      </div>
    </div>
  );
};
