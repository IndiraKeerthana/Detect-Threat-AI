import React, { useEffect, useRef, useMemo } from 'react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { AlertTriangle, Server, Crosshair } from 'lucide-react';
import type { EmailAnalysisResponse } from '../../types/investigation';
import { normalizeMapLocation } from '../../services/investigationAdapter';
import { useInvestigationVisual } from '../../context/InvestigationVisualContext';
import { SectionHeader } from '../investigation/SectionHeader';

interface GeolocationMapProps {
  data: EmailAnalysisResponse;
}

export const GeolocationMap: React.FC<GeolocationMapProps> = ({ data }) => {
  const mapContainerRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);
  const markerRef = useRef<L.Marker | null>(null);

  const { mapHighlighted } = useInvestigationVisual();

  // Normalize map location using investigation adapter
  const location = useMemo(() => normalizeMapLocation(data), [data]);

  useEffect(() => {
    if (!mapContainerRef.current || !location) return;

    // Destroy existing instance if any
    if (mapInstanceRef.current) {
      mapInstanceRef.current.remove();
      mapInstanceRef.current = null;
    }

    const { latitude, longitude } = location;

    // Initialize Leaflet map
    const map = L.map(mapContainerRef.current, {
      center: [latitude, longitude],
      zoom: 4,
      minZoom: 2,
      maxZoom: 12,
      zoomControl: false,
      attributionControl: false,
    });

    // Add minimal zoom controls in top-right
    L.control.zoom({ position: 'topright' }).addTo(map);

    // CartoDB Dark Matter tile layer for restrained near-black forensic styling
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      maxZoom: 19,
      subdomains: 'abcd',
    }).addTo(map);

    // Custom forensic pin icon
    const customIcon = L.divIcon({
      className: 'forensic-marker-wrapper',
      html: `
        <div style="position: relative; display: flex; align-items: center; justify-content: center; width: 32px; height: 32px;">
          <div style="position: absolute; width: 28px; height: 28px; border-radius: 9999px; background: rgba(6, 182, 212, 0.15); border: 1px solid rgba(6, 182, 212, 0.5);"></div>
          <div style="width: 14px; height: 14px; border-radius: 9999px; background: #06b6d4; border: 2px solid #08090d; box-shadow: 0 0 6px rgba(6, 182, 212, 0.6);"></div>
        </div>
      `,
      iconSize: [32, 32],
      iconAnchor: [16, 16],
    });

    // Create marker
    const marker = L.marker([latitude, longitude], { icon: customIcon }).addTo(map);

    // Build dark popup content with verified fields
    const popupContent = `
      <div style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #f1f5f9; background: #0f1217; border: 1px solid #2a3242; padding: 10px; border-radius: 6px; min-width: 200px;">
        <div style="font-size: 10px; color: #06b6d4; text-transform: uppercase; font-weight: bold; margin-bottom: 4px;">
          PROBABLE ORIGIN RELAY
        </div>
        <div style="font-size: 13px; font-weight: bold; color: #f1f5f9; margin-bottom: 6px;">
          ${location.ip}
        </div>
        <div style="border-top: 1px solid #1e2430; padding-top: 4px; display: flex; flex-direction: column; gap: 2px; color: #94a3b8; font-size: 10px;">
          <div>Location: <strong style="color: #f1f5f9;">${location.city ? location.city + ', ' : ''}${location.country}</strong></div>
          <div>Coordinates: <strong style="color: #67e8f9;">${latitude.toFixed(4)}°, ${longitude.toFixed(4)}°</strong></div>
          <div>ASN: <strong style="color: #f1f5f9;">${location.asn || 'Unknown'}</strong></div>
          <div>Organization: <strong style="color: #f1f5f9;">${location.organization || 'Unknown'}</strong></div>
          <div>Abuse Score: <strong style="color: #ef4444;">${location.abuseScore ? location.abuseScore + '%' : 'N/A'}</strong></div>
        </div>
      </div>
    `;

    marker.bindPopup(popupContent, {
      className: 'forensic-dark-popup',
      closeButton: false,
    });

    markerRef.current = marker;
    mapInstanceRef.current = map;

    return () => {
      map.remove();
      mapInstanceRef.current = null;
    };
  }, [location]);

  // Handle external highlight trigger from Timeline / Context
  useEffect(() => {
    if (mapHighlighted && mapInstanceRef.current && markerRef.current && location) {
      mapInstanceRef.current.setView([location.latitude, location.longitude], 6, {
        animate: true,
      });
      markerRef.current.openPopup();
    }
  }, [mapHighlighted, location]);

  return (
    <div className="surface-card p-6 border border-[#1e2430] space-y-4">
      {/* Section Header */}
      <SectionHeader
        index="06A"
        tag="GEOLOCATION"
        title="Ingress Origin & Geolocation Telemetry"
        subtitle="Physical and Autonomous System coordinates mapped from verified external relay telemetry"
        action={
          location ? (
            <div className="flex items-center space-x-2 text-xs font-mono">
              <span className="text-[#64748b]">
                COORDINATES: <strong className="text-[#67e8f9]">{location.latitude.toFixed(3)}°, {location.longitude.toFixed(3)}°</strong>
              </span>
              <span className="px-2 py-0.5 rounded bg-[#0c232c] text-[#67e8f9] border border-[#154c5e] text-[10px] font-bold">
                LEAFLET DARK
              </span>
            </div>
          ) : (
            <span className="px-2 py-0.5 rounded bg-[#261114] text-[#fca5a5] border border-[#5c1d24] text-[10px] font-bold">
              UNAVAILABLE
            </span>
          )
        }
      />

      {/* Map or Failure State */}
      {!location ? (
        // Required Strict Failure State if coordinates cannot be verified
        <div className="h-64 bg-[#08090d] border border-[#1e2430] rounded-lg flex flex-col items-center justify-center p-6 text-center space-y-2">
          <AlertTriangle className="w-8 h-8 text-[#ef4444] opacity-80" />
          <div className="text-sm font-mono font-bold text-[#fca5a5] uppercase tracking-wider">
            LOCATION UNAVAILABLE
          </div>
          <p className="text-xs font-mono text-[#64748b] max-w-sm leading-relaxed">
            Reason: No verified geographic coordinates were returned by the available intelligence providers.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {/* Leaflet Map Canvas */}
          <div className="relative h-64 bg-[#08090d] border border-[#1e2430] rounded-lg overflow-hidden select-none">
            <div ref={mapContainerRef} className="w-full h-full" />

            {/* Ingress Marker Telemetry Overlay Chip */}
            <div className="absolute bottom-3 left-3 z-[400] bg-[#0f1217]/90 backdrop-blur border border-[#2a3242] px-3 py-1.5 rounded text-[10px] font-mono flex items-center gap-2">
              <Crosshair className="w-3.5 h-3.5 text-[#06b6d4]" />
              <span className="text-[#64748b]">INGRESS TARGET:</span>
              <span className="text-[#f1f5f9] font-bold">{location.ip}</span>
              <span className="text-[#3e485e]">•</span>
              <span className="text-[#67e8f9]">{location.country}{location.countryCode ? ` [${location.countryCode}]` : ''}</span>
            </div>
          </div>

          {/* Compact Intelligence Summary Ledger */}
          <div className="bg-[#0f1217] border border-[#1e2430] p-4 rounded-md space-y-2">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-[#06b6d4] font-semibold uppercase flex items-center gap-1.5">
                <Server className="w-3.5 h-3.5" />
                PROBABLE SOURCE INFRASTRUCTURE
              </span>
              <span className="text-[10px] text-[#64748b]">
                CONFIDENCE: <strong className="text-[#10b981]">{location.confidence.toUpperCase()}</strong>
              </span>
            </div>

            {/* Dense Metadata Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono pt-1">
              <div className="bg-[#12151b] border border-[#1e2430] p-2 rounded">
                <span className="text-[10px] text-[#64748b] block uppercase">ORIGIN IP</span>
                <span className="text-[#f1f5f9] font-bold">{location.ip}</span>
              </div>
              <div className="bg-[#12151b] border border-[#1e2430] p-2 rounded">
                <span className="text-[10px] text-[#64748b] block uppercase">COUNTRY & CITY</span>
                <span className="text-[#f1f5f9] truncate block">
                  {location.city ? `${location.city}, ` : ''}{location.country}
                </span>
              </div>
              <div className="bg-[#12151b] border border-[#1e2430] p-2 rounded">
                <span className="text-[10px] text-[#64748b] block uppercase">AUTONOMOUS SYSTEM</span>
                <span className="text-[#67e8f9] font-bold truncate block">{location.asn || 'Not resolved'}</span>
              </div>
              <div className="bg-[#12151b] border border-[#1e2430] p-2 rounded">
                <span className="text-[10px] text-[#64748b] block uppercase">ORGANIZATION / ISP</span>
                <span className="text-[#94a3b8] truncate block">{location.organization || 'Not resolved'}</span>
              </div>
            </div>

            {/* Conservative Attribution Statement */}
            <p className="text-[11px] font-sans text-[#64748b] italic pt-1 border-t border-[#1e2430]">
              Note: Geolocation identifies origin relay infrastructure preceding perimeter MX gateways. In accordance with forensic standards, infrastructure location does not identify physical threat actor residence or affiliation.
            </p>
          </div>
        </div>
      )}
    </div>
  );
};
