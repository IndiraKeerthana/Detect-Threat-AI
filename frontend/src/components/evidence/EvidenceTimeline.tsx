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
          dotBg: 'bg-[#ef4444]',
          dotBorder: 'border-[#5c1d24]',
          badgeClass: 'text-[#fca5a5] bg-[#261114] border-[#5c1d24]',
          accentBar: 'bg-[#ef4444]',
        };
      case 'warning':
        return {
          dotBg: 'bg-[#f59e0b]',
          dotBorder: 'border-[#5c3c12]',
          badgeClass: 'text-[#fcd34d] bg-[#261b0c] border-[#5c3c12]',
          accentBar: 'bg-[#f59e0b]',
        };
      case 'verified':
        return {
          dotBg: 'bg-[#10b981]',
          dotBorder: 'border-[#164e3b]',
          badgeClass: 'text-[#6ee7b7] bg-[#0e241b] border-[#164e3b]',
          accentBar: 'bg-[#10b981]',
        };
      default:
        return {
          dotBg: 'bg-[#64748b]',
          dotBorder: 'border-[#2a3242]',
          badgeClass: 'text-[#94a3b8] bg-[#171b23] border-[#2a3242]',
          accentBar: 'bg-[#2a3242]',
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
    <div className="surface-card p-6 border border-[#1e2430] space-y-4">
      {/* Section Header */}
      <SectionHeader
        index="06B"
        tag="EVIDENCE TIMELINE"
        title="Chronological Forensic Evidence Trace"
        subtitle="Ordered reconstruction tracing email transit, authentication verification, tool execution, and triage"
        action={
          <div className="flex items-center space-x-2 text-xs font-mono">
            <span className="text-[#64748b]">
              EVENTS: <strong className="text-[#f1f5f9]">{events.length}</strong>
            </span>
            {events.length > 0 ? (
              <span className="px-2 py-0.5 rounded bg-[#171b23] text-[#94a3b8] border border-[#2a3242] text-[10px] font-bold">
                CHRONO TRACE
              </span>
            ) : (
              <span className="px-2 py-0.5 rounded bg-[#261b0c] text-[#fcd34d] border border-[#5c3c12] text-[10px] font-bold">
                LIMITED
              </span>
            )}
          </div>
        }
      />

      {/* Vertical Timeline Event Stream or Empty Limited State */}
      {events.length === 0 ? (
        <div className="py-12 bg-[#08090d] border border-[#1e2430] rounded-lg flex flex-col items-center justify-center p-6 text-center space-y-2">
          <Clock className="w-8 h-8 text-[#f59e0b] opacity-80" />
          <div className="text-sm font-mono font-bold text-[#fcd34d] uppercase tracking-wider">
            TIMELINE DATA LIMITED
          </div>
          <p className="text-xs text-[#94a3b8] max-w-md font-sans">
            No verified event timestamps were available in the backend evidence trace to construct a chronological timeline. Speculative timestamps and synthetic intervals are withheld to maintain forensic integrity.
          </p>
        </div>
      ) : (
        <div className="relative pl-7 space-y-3 before:absolute before:left-3 before:top-3 before:bottom-3 before:w-0.5 before:bg-[#1e2430]">
          {events.map((evt) => {
            const style = getStateStyle(evt.state);
            const isSelected = selectedTimelineEventId === evt.id;
            const displayTimestamp = formatISTTimestamp(evt.timeOffset);

            return (
              <div key={evt.id} className="relative group">
                {/* Event Circle Anchor */}
                <div
                  className={`absolute -left-7 top-3 w-6 h-6 rounded-full bg-[#0a0c10] border-2 ${
                    isSelected ? 'border-[#f1f5f9] scale-110 shadow-md' : style.dotBorder
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
                      ? 'bg-[#171b23] border-[#8b5cf6]'
                      : 'bg-[#12151b] border-[#1e2430] hover:border-[#2a3242] hover:bg-[#151921]'
                  }`}
                >
                  {/* Left semantic accent line */}
                  <div className={`absolute left-0 top-0 bottom-0 w-1 ${style.accentBar}`} />

                  <div className="pl-1.5 space-y-1.5">
                    {/* Metadata Row */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1.5 text-xs font-mono">
                      <div className="flex items-center space-x-2">
                        <span className="text-[10px] font-bold text-[#64748b]">
                          <span title={`Original timestamp: ${evt.timeOffset}`}>
                            {String(evt.step).padStart(2, '0')} // {displayTimestamp}
                          </span>
                        </span>
                        <span
                          className={`px-1.5 py-0.2 rounded text-[9px] font-bold uppercase border ${style.badgeClass}`}
                        >
                          {evt.categoryLabel}
                        </span>
                      </div>

                      <div className="flex items-center gap-2 self-start sm:self-auto text-[10px] text-[#64748b]">
                      <span className="truncate max-w-[180px]">SRC: {evt.source}</span>
                      {isSelected ? (
                        <ChevronUp className="w-3.5 h-3.5 text-[#94a3b8]" />
                      ) : (
                        <ChevronDown className="w-3.5 h-3.5 text-[#64748b]" />
                      )}
                    </div>
                  </div>

                  {/* Title */}
                  <div className="text-xs font-mono font-semibold text-[#f1f5f9] tracking-tight">
                    {evt.title}
                  </div>

                  {/* Description */}
                  <p className="text-[11px] text-[#94a3b8] font-sans leading-relaxed">
                    {evt.description}
                  </p>

                  {/* Expanded Detail Tray */}
                  {isSelected && (
                    <div className="pt-2.5 mt-2 border-t border-[#1e2430] space-y-2 text-xs font-mono animate-in fade-in duration-150">
                      {/* Evidence Tokens */}
                      {evt.evidence.length > 0 && (
                        <div className="space-y-1">
                          <span className="text-[10px] text-[#64748b] uppercase block">
                            RAW EVIDENCE RECORD
                          </span>
                          <div className="flex flex-wrap gap-1.5">
                            {evt.evidence.map((item, i) => (
                              <span
                                key={i}
                                className="text-[10px] px-2 py-0.5 rounded bg-[#0a0c10] border border-[#1e2430] text-[#67e8f9]"
                              >
                                {item}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Cross-Visualization Actions */}
                      <div className="flex flex-wrap items-center gap-2 pt-1">
                        {evt.relatedEntityId && (
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              focusEntity(evt.relatedEntityId!);
                            }}
                            className="px-2.5 py-1 rounded bg-[#1e1533] hover:bg-[#2b1e4a] text-[#c4b5fd] border border-[#432474] text-[10px] font-mono flex items-center gap-1.5 transition-colors"
                          >
                            <Network className="w-3 h-3 text-[#8b5cf6]" />
                            VIEW IN GRAPH
                          </button>
                        )}

                        {evt.hasLocation && (
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              focusMap();
                            }}
                            className="px-2.5 py-1 rounded bg-[#0c232c] hover:bg-[#154c5e] text-[#67e8f9] border border-[#154c5e] text-[10px] font-mono flex items-center gap-1.5 transition-colors"
                          >
                            <MapPin className="w-3 h-3 text-[#06b6d4]" />
                            VIEW ON MAP
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
