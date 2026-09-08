import React, { createContext, useContext, useState } from 'react';
import type { ReactNode } from 'react';

interface InvestigationVisualContextType {
  selectedEntityId: string | null;
  setSelectedEntityId: (id: string | null) => void;
  selectedTimelineEventId: string | null;
  setSelectedTimelineEventId: (id: string | null) => void;
  mapHighlighted: boolean;
  setMapHighlighted: (highlight: boolean) => void;
  focusEntity: (entityId: string) => void;
  focusMap: () => void;
}

const InvestigationVisualContext = createContext<InvestigationVisualContextType | undefined>(undefined);

export const InvestigationVisualProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [selectedEntityId, setSelectedEntityId] = useState<string | null>(null);
  const [selectedTimelineEventId, setSelectedTimelineEventId] = useState<string | null>(null);
  const [mapHighlighted, setMapHighlighted] = useState<boolean>(false);

  const focusEntity = (entityId: string) => {
    setSelectedEntityId(entityId);
  };

  const focusMap = () => {
    setMapHighlighted(true);
    setTimeout(() => setMapHighlighted(false), 2500);
  };

  return (
    <InvestigationVisualContext.Provider
      value={{
        selectedEntityId,
        setSelectedEntityId,
        selectedTimelineEventId,
        setSelectedTimelineEventId,
        mapHighlighted,
        setMapHighlighted,
        focusEntity,
        focusMap,
      }}
    >
      {children}
    </InvestigationVisualContext.Provider>
  );
};

export function useInvestigationVisual(): InvestigationVisualContextType {
  const context = useContext(InvestigationVisualContext);
  if (!context) {
    // Return a safe fallback if used outside provider
    return {
      selectedEntityId: null,
      setSelectedEntityId: () => {},
      selectedTimelineEventId: null,
      setSelectedTimelineEventId: () => {},
      mapHighlighted: false,
      setMapHighlighted: () => {},
      focusEntity: () => {},
      focusMap: () => {},
    };
  }
  return context;
}
