import { MapPin, Crosshair, Globe } from 'lucide-react';
import type { ExtractedIP } from '../../types/investigation';
import { SectionHeader } from '../investigation/SectionHeader';

interface GeolocationPlaceholderProps {
  ips?: ExtractedIP[];
  primaryIp?: string | null;
}

export const GeolocationPlaceholder: React.FC<GeolocationPlaceholderProps> = ({
  ips = [],
  primaryIp = 'IP Unavailable',
}) => {
  return (
    <div className="surface-card p-6 border border-[#1e2430] space-y-4">
      {/* Section Header */}
      <SectionHeader
        index="06A"
        tag="GEOLOCATION"
        title="Ingress Origin & Geolocation Telemetry"
        subtitle="Physical and Autonomous System routing coordinates mapped from untrusted ingress relays"
        action={
          <div className="flex items-center space-x-2 text-xs font-mono">
            <span className="text-[#64748b]">INGRESS IPS: <strong className="text-[#f1f5f9]">{ips.length || 0}</strong></span>
            <span className="px-2 py-0.5 rounded bg-[#0c232c] text-[#67e8f9] border border-[#154c5e] text-[10px] font-bold">
              STEP 8C ENGINE
            </span>
          </div>
        }
      />

      {/* Radar Target / Coordinate Canvas */}
      <div className="relative h-64 bg-[#08090d] border border-[#1e2430] rounded-lg overflow-hidden flex flex-col items-center justify-center p-6 text-center select-none">
        {/* Subtle coordinate grid lines */}
        <div
          className="absolute inset-0 opacity-15"
          style={{
            backgroundImage: `radial-gradient(#06b6d4 1px, transparent 1px)`,
            backgroundSize: '20px 20px',
          }}
        />

        {/* Reticle Target Animation / Compass */}
        <div className="relative z-10 space-y-3 max-w-sm">
          <div className="relative w-16 h-16 mx-auto flex items-center justify-center">
            <div className="absolute inset-0 border border-[#06b6d4]/40 rounded-full animate-pulse" />
            <div className="absolute inset-2 border border-[#06b6d4]/20 rounded-full" />
            <Crosshair className="w-8 h-8 text-[#06b6d4]" />
          </div>

          <div className="space-y-1">
            <div className="text-xs font-mono font-bold text-[#f1f5f9] flex items-center justify-center gap-2">
              <MapPin className="w-3.5 h-3.5 text-[#06b6d4]" />
              Target Host: <span className="text-[#06b6d4]">{primaryIp || 'IP Unavailable'}</span>
            </div>
            <p className="text-[11px] font-mono text-[#94a3b8]">
              Coordinates: None verified
            </p>
            <p className="text-[10px] font-mono text-[#64748b]">
              Autonomous System: Not resolved • Organization: Not resolved
            </p>
          </div>
        </div>

        {/* Engine Slot Footer */}
        <div className="absolute bottom-2.5 left-4 text-[10px] font-mono text-[#64748b] flex items-center gap-2">
          <Globe className="w-3 h-3 text-[#06b6d4]" />
          <span>Leaflet / MapLibre GL Vector Tile Foundation</span>
        </div>

        <div className="absolute bottom-2.5 right-4 text-[10px] font-mono text-[#475569]">
          RESOLUTION: Standard
        </div>
      </div>
    </div>
  );
};
