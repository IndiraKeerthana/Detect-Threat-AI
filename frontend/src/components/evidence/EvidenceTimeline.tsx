import React, { useMemo } from 'react';
import {
  Network,
  MapPin,
  ChevronDown,
  ChevronUp,
  Clock,
} from 'lucide-react';
import type { EmailAnalysisResponse } from '../../types/investigation';
import { normalizeTimelineEvents } from '../../services/investigationAdapter';
import type {
  NormalizedTimelineEvent,
  TimelineEventState,
} from '../../services/investigationAdapter';
import { formatISTTimestamp } from '../../utils/dateFormatter';
import { useInvestigationVisual } from '../../context/InvestigationVisualContext';
import { SectionHeader } from '../investigation/SectionHeader';

interface EvidenceTimelineProps {
  data: EmailAnalysisResponse;
}

export const EvidenceTimeline: React.FC<EvidenceTimelineProps> = ({ data }) => {
  const {
    selectedTimelineEventId,
    setSelectedTimelineEventId,
    focusEntity,
    focusMap,
  } = useInvestigationVisual();

  const events = useMemo(() => normalizeTimelineEvents(data), [data]);

  const getStateStyle = (state: TimelineEventState) => {
    switch (state) {
      case 'critical':
        return {
          dotBg: 'bg-[var(--severity-critical)]',
          dotBorder: 'border-[var(--severity-critical)]',
          badgeClass: 'badge-critical',
          accentBar: 'bg-[var(--severity-critical)]',
        };
      case 'warning':
        return {
          dotBg: 'bg-[var(--severity-medium)]',
          dotBorder: 'border-[var(--severity-medium)]',
          badgeClass: 'badge-warning',
          accentBar: 'bg-[var(--severity-medium)]',
        };
      case 'verified':
        return {
          dotBg: 'bg-[var(--state-pass)]',
          dotBorder: 'border-[var(--state-pass)]',
          badgeClass: 'badge-success',
          accentBar: 'bg-[var(--state-pass)]',
        };
      default:
        return {
          dotBg: 'bg-[var(--text-dim)]',
          dotBorder: 'border-[var(--border)]',
          badgeClass: 'badge-neutral',
          accentBar: 'bg-[var(--border)]',
        };
    }
  };

  const handleSelectEvent = (evt: NormalizedTimelineEvent) => {
    if (selectedTimelineEventId === evt.id) {
      setSelectedTimelineEventId(null);
    } else {
      setSelectedTimelineEventId(evt.id);
      if (evt.relatedEntityId) {
        focusEntity(evt.relatedEntityId);
      }
    }
  };

  return (
    <div className="surface-card p-5 border border-[var(--border-subtle)] space-y-4">
      {/* Section Header */}
      <SectionHeader
        index="07"
        title="Forensic evidence timeline"
        subtitle="Ordered reconstruction tracing email transit, authentication verification, tool execution, and triage."
        action={
          <div className="flex items-center space-x-2 text-xs font-mono text-[var(--text-muted)]">
            <span>
              EVENTS: <strong className="text-[var(--text)]">{events.length}</strong>
            </span>
          </div>
        }
      />

      {/* Vertical Timeline Event Stream or Empty Limited State */}
      {events.length === 0 ? (
        <div className="py-10 bg-[var(--surface-subtle)] border border-[var(--border-subtle)] rounded-lg flex flex-col items-center justify-center p-6 text-center space-y-2 select-none">
          <Clock className="w-8 h-8 text-[var(--severity-medium)] opacity-80" />
          <div className="text-xs font-sans font-bold text-[var(--text)] uppercase tracking-wider">
            TIMELINE DATA LIMITED
          </div>
          <p className="text-xs text-[var(--text-muted)] max-w-md font-sans leading-relaxed">
            No verified event timestamps were available in the backend evidence trace to construct a chronological timeline. Speculative timestamps and synthetic intervals are withheld to maintain forensic integrity.
          </p>
        </div>
      ) : (
        <div className="relative pl-7 space-y-3 before:absolute before:left-3 before:top-3 before:bottom-3 before:w-0.5 before:bg-[var(--border-subtle)]">
          {events.map((evt) => {
            const style = getStateStyle(evt.state);
            const isSelected = selectedTimelineEventId === evt.id;
            const displayTimestamp = formatISTTimestamp(evt.timeOffset);

            return (
              <div key={evt.id} className="relative group">
                {/* Event Circle Anchor */}
                <div
                  className={`absolute -left-7 top-3 w-6 h-6 rounded-full bg-[var(--surface)] border-2 ${
                    isSelected ? 'border-[var(--text)] scale-110 shadow-sm' : style.dotBorder
                  } flex items-center justify-center -translate-x-1/2 transition-all cursor-pointer`}
                  onClick={() => handleSelectEvent(evt)}
                >
                  <span
                    className={`w-2 h-2 rounded-full ${style.dotBg} ${
                      evt.state === 'critical' ? 'animate-pulse' : ''
                    }`}
                  />
                </div>

                {/* Event Content Card */}
                <div
                  onClick={() => handleSelectEvent(evt)}
                  className={`p-3.5 rounded-md border transition-all cursor-pointer select-none relative overflow-hidden ${
                    isSelected
                      ? 'bg-[var(--surface-elevated)] border-[var(--ai)]'
                      : 'bg-[var(--surface-subtle)] border-[var(--border-subtle)] hover:border-[var(--border)] hover:bg-[var(--surface)]'
                  }`}
                >
                  {/* Left semantic accent line */}
                  <div className={`absolute left-0 top-0 bottom-0 w-1 ${style.accentBar}`} />

                  <div className="pl-1.5 space-y-1.5 font-sans">
                    {/* Metadata Row */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1.5 text-xs font-mono">
                      <div className="flex items-center space-x-2">
                        <span className="text-[10px] font-bold text-[var(--text-dim)]">
                          <span title={`Original timestamp: ${evt.timeOffset}`}>
                            Step {String(evt.step).padStart(2, '0')} · {displayTimestamp}
                          </span>
                        </span>
                        <span
                          className={`px-1.5 py-0.2 rounded text-[9px] font-bold uppercase border ${style.badgeClass}`}
                        >
                          {evt.categoryLabel}
                        </span>
                      </div>

                      <div className="flex items-center gap-2 self-start sm:self-auto text-[10px] text-[var(--text-dim)]">
                        <span className="truncate max-w-[180px]">SRC: {evt.source}</span>
                        {isSelected ? (
                          <ChevronUp className="w-3.5 h-3.5 text-[var(--text-muted)]" />
                        ) : (
                          <ChevronDown className="w-3.5 h-3.5 text-[var(--text-dim)]" />
                        )}
                      </div>
                    </div>

                    {/* Title */}
                    <div className="text-xs font-semibold text-[var(--text)] tracking-tight font-sans">
                      {evt.title}
                    </div>

                    {/* Description */}
                    <p className="text-[11px] text-[var(--text-muted)] font-sans leading-relaxed">
                      {evt.description}
                    </p>

                    {/* Expanded Detail Tray */}
                    {isSelected && (
                      <div className="pt-2.5 mt-2 border-t border-[var(--border-subtle)] space-y-2 text-xs font-mono animate-in fade-in duration-150">
                        {/* Evidence Tokens */}
                        {evt.evidence.length > 0 && (
                          <div className="space-y-1">
                            <span className="text-[10px] text-[var(--text-dim)] uppercase block font-sans">
                              Raw Evidence Record
                            </span>
                            <div className="flex flex-wrap gap-1.5">
                              {evt.evidence.map((item, i) => (
                                <span
                                  key={i}
                                  className="text-[10px] px-2 py-0.5 rounded bg-[var(--surface)] border border-[var(--border-subtle)] text-[var(--identifier)]"
                                >
                                  {item}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Cross-Visualization Actions */}
                        <div className="flex flex-wrap items-center gap-2 pt-1 font-sans">
                          {evt.relatedEntityId && (
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                focusEntity(evt.relatedEntityId!);
                              }}
                              className="px-2.5 py-1 rounded badge-ai text-[10px] font-mono flex items-center gap-1.5 transition-colors cursor-pointer"
                            >
                              <Network className="w-3 h-3 text-[var(--ai)]" />
                              VIEW IN TOPOLOGY
                            </button>
                          )}

                          {evt.hasLocation && (
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                focusMap();
                              }}
                              className="px-2.5 py-1 rounded badge-infra text-[10px] font-mono flex items-center gap-1.5 transition-colors cursor-pointer"
                            >
                              <MapPin className="w-3 h-3 text-[var(--identifier)]" />
                              VIEW GEOLOCATION MAP
                            </button>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
