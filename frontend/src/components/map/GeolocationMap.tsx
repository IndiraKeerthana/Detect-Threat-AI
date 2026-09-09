import React, { useEffect, useRef, useMemo } from 'react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { Globe, Server, Crosshair } from 'lucide-react';
import type { EmailAnalysisResponse } from '../../types/investigation';
import { normalizeMapLocation } from '../../services/investigationAdapter';
import { useInvestigationVisual } from '../../context/InvestigationVisualContext';
import { useTheme } from '../../context/ThemeContext';

interface GeolocationMapProps {
  data?: EmailAnalysisResponse | null;
  className?: string;
}

export const GeolocationMap: React.FC<GeolocationMapProps> = ({ data, className = '' }) => {
  const mapContainerRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);
  const markerRef = useRef<L.Marker | null>(null);

  const { mapHighlighted } = useInvestigationVisual();
  const { theme } = useTheme();

  // Normalize map location using investigation adapter
  const location = useMemo(() => (data ? normalizeMapLocation(data) : null), [data]);

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

    // Dynamic Tile Layer matching Light / Dark theme
    const tileUrl =
      theme === 'light'
        ? 'https://{s}.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}{r}.png'
        : 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png';

    L.tileLayer(tileUrl, {
      maxZoom: 19,
      subdomains: 'abcd',
    }).addTo(map);

    // Custom forensic pin icon
    const pinBg = theme === 'light' ? '#0891b2' : '#06b6d4';
    const pinHalo = theme === 'light' ? 'rgba(8, 145, 178, 0.2)' : 'rgba(6, 182, 212, 0.2)';
    const customIcon = L.divIcon({
      className: 'forensic-marker-wrapper',
      html: `
        <div style="position: relative; display: flex; align-items: center; justify-content: center; width: 32px; height: 32px;">
          <div style="position: absolute; width: 28px; height: 28px; border-radius: 9999px; background: ${pinHalo}; border: 1px solid ${pinBg};"></div>
          <div style="width: 14px; height: 14px; border-radius: 9999px; background: ${pinBg}; border: 2px solid #ffffff; box-shadow: 0 0 8px ${pinHalo};"></div>
        </div>
      `,
      iconSize: [32, 32],
      iconAnchor: [16, 16],
    });

    // Create marker
    const marker = L.marker([latitude, longitude], { icon: customIcon }).addTo(map);

    const popupBg = theme === 'light' ? '#ffffff' : '#0f1217';
    const popupText = theme === 'light' ? '#0f172a' : '#f1f5f9';
    const popupBorder = theme === 'light' ? '#cbd5e1' : '#2a3242';

    // Popup content with verified fields
    const popupContent = `
      <div style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: ${popupText}; background: ${popupBg}; border: 1px solid ${popupBorder}; padding: 10px; border-radius: 6px; min-width: 200px;">
        <div style="font-size: 10px; color: ${pinBg}; text-transform: uppercase; font-weight: bold; margin-bottom: 4px;">
          PROBABLE ORIGIN RELAY
        </div>
        <div style="font-size: 13px; font-weight: bold; color: ${popupText}; margin-bottom: 6px;">
          ${location.ip}
        </div>
        <div style="border-top: 1px solid ${popupBorder}; padding-top: 4px; display: flex; flex-direction: column; gap: 2px; color: ${popupText}; font-size: 10px;">
          <div>Location: <strong>${location.city ? location.city + ', ' : ''}${location.country}</strong></div>
          <div>Coordinates: <strong style="color: ${pinBg};">${latitude.toFixed(4)}°, ${longitude.toFixed(4)}°</strong></div>
          <div>ASN: <strong>${location.asn || 'Unknown'}</strong></div>
          <div>Organization: <strong>${location.organization || 'Unknown'}</strong></div>
          <div>Abuse Score: <strong style="color: #ef4444;">${location.abuseScore ? location.abuseScore + '%' : 'N/A'}</strong></div>
        </div>
      </div>
    `;

    marker.bindPopup(popupContent, {
      className: 'forensic-popup',
      closeButton: false,
    });

    markerRef.current = marker;
    mapInstanceRef.current = map;

    return () => {
      map.remove();
      mapInstanceRef.current = null;
    };
  }, [location, theme]);

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
    <div className={`space-y-3 ${className}`}>
      <div className="flex items-center justify-between text-xs font-sans">
        <span className="font-semibold text-[var(--text)] tracking-tight">
          Geolocation map
        </span>
        {location ? (
          <span className="text-xs font-mono text-[var(--text-muted)]">
            Coordinates: <strong className="text-[var(--identifier)]">{location.latitude.toFixed(3)}°, {location.longitude.toFixed(3)}°</strong>
          </span>
        ) : (
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[var(--surface-elevated)] text-[var(--text-dim)] border border-[var(--border-subtle)] font-bold">
            UNAVAILABLE
          </span>
        )}
      </div>

      {/* Map or Case B Clean Empty State */}
      {!location ? (
        <div className="h-56 bg-[var(--surface-subtle)] border border-[var(--border-subtle)] rounded-lg flex flex-col items-center justify-center p-6 text-center space-y-2 select-none">
          <div className="w-10 h-10 rounded-full bg-[var(--surface)] border border-[var(--border-subtle)] flex items-center justify-center text-[var(--text-dim)] mb-1">
            <Globe className="w-5 h-5" />
          </div>
          <div className="text-xs font-bold text-[var(--text)] uppercase tracking-wider font-sans">
            NO VERIFIED GEOLOCATION
          </div>
          <p className="text-xs font-sans text-[var(--text-muted)] max-w-md leading-relaxed">
            No trusted coordinates are available for the identified source infrastructure.
            The map will appear when verified geolocation data is available.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {/* Leaflet Map Canvas */}
          <div className="relative h-64 bg-[var(--surface-subtle)] border border-[var(--border-subtle)] rounded-lg overflow-hidden select-none">
            <div ref={mapContainerRef} className="w-full h-full" />

            {/* Ingress Marker Telemetry Overlay Chip */}
            <div className="absolute bottom-3 left-3 z-[400] bg-[var(--surface)]/95 backdrop-blur border border-[var(--border-subtle)] px-3 py-1.5 rounded text-[10px] font-mono flex items-center gap-2 shadow-sm">
              <Crosshair className="w-3.5 h-3.5 text-[var(--identifier)]" />
              <span className="text-[var(--text-dim)] uppercase">Probable origin:</span>
              <span className="text-[var(--text)] font-bold">{location.ip}</span>
              <span className="text-[var(--border)]">•</span>
              <span className="text-[var(--identifier)] font-semibold">{location.country}{location.countryCode ? ` [${location.countryCode}]` : ''}</span>
            </div>
          </div>

          {/* Compact Telemetry Rationale */}
          <div className="bg-[var(--surface-subtle)] border border-[var(--border-subtle)] p-3.5 rounded-lg space-y-1.5 text-xs font-sans">
            <div className="flex items-center justify-between font-mono text-[11px]">
              <span className="text-[var(--identifier)] font-bold uppercase flex items-center gap-1.5">
                <Server className="w-3.5 h-3.5" />
                Origin Ingress Infrastructure
              </span>
              <span className="text-[var(--text-dim)]">
                Confidence: <strong className="text-[var(--state-pass)]">{location.confidence.toUpperCase()}</strong>
              </span>
            </div>
            <p className="text-[11px] text-[var(--text-muted)] leading-relaxed">
              Geolocation reflects probable origin relay infrastructure mapped from verified IP telemetry. In accordance with forensic standards, infrastructure location does not derive or imply physical threat actor residence or affiliation.
            </p>
          </div>
        </div>
      )}
    </div>
  );
};
