import React from 'react';
import { InvestigationHeader } from '../components/investigation/InvestigationHeader';
import { ThreatAssessmentCard } from '../components/threat/ThreatAssessmentCard';
import { AIInvestigationCard } from '../components/investigation/AIInvestigationCard';
import { KeyFindingsList } from '../components/threat/KeyFindingsList';
import { AuthenticationSection } from '../components/evidence/AuthenticationSection';
import { InfrastructureIntel } from '../components/intelligence/InfrastructureIntel';
import { AttackGraph } from '../components/graph/AttackGraph';
import { GeolocationMap } from '../components/map/GeolocationMap';
import { EvidenceTimeline } from '../components/evidence/EvidenceTimeline';
import type { EmailAnalysisResponse } from '../types/investigation';
import type { CaseRecord, CaseStatus } from '../services/caseStore';
import { InvestigationVisualProvider } from '../context/InvestigationVisualContext';

interface InvestigationProps {
  data: EmailAnalysisResponse;
  caseRecord?: CaseRecord;
  onNavigateHome: () => void;
  onViewReport?: () => void;
  onStatusChange?: (newStatus: CaseStatus) => void;
}

export const Investigation: React.FC<InvestigationProps> = ({
  data,
  caseRecord,
  onNavigateHome,
  onViewReport,
  onStatusChange,
}) => {
  return (
    <InvestigationVisualProvider>
      <div className="space-y-8 max-w-7xl mx-auto py-2">
        {/* 1. Case Header with Status Control & View Report Trigger */}
        <InvestigationHeader
          data={data}
          caseRecord={caseRecord}
          caseId={caseRecord?.id || 'CASE-UNASSIGNED'}
          onStatusChange={onStatusChange}
          onViewReport={onViewReport}
          onNavigateBack={onNavigateHome}
        />

        {/* 2. Threat Assessment Hero */}
        <ThreatAssessmentCard
          assessment={data.risk_assessment}
          correlationCount={data.threat_intelligence?.relationships?.length || 0}
        />

        {/* 3. Autonomous AI Investigation Record */}
        <AIInvestigationCard aiData={data.ai_investigation} />

        {/* 4. Evidence Matrix: Key Findings + Authentication */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
          {/* Left Column: Key Forensic Findings Ledger */}
          <KeyFindingsList
            indicators={data.security_analysis?.indicators}
            aiFindings={data.ai_investigation?.key_findings}
          />

          {/* Right Column: RFC 8601 Authentication Verification Matrix */}
          <AuthenticationSection auth={data.security_analysis?.authentication_results} />
        </div>

        {/* 5. Infrastructure Intelligence Telemetry */}
        <InfrastructureIntel
          relay={data.relay_analysis}
          intelligence={data.threat_intelligence}
          urls={data.security_analysis?.url_analysis}
        />

        {/* 6. Forensic Visualizations & Topology Grid */}
        <div className="space-y-6">
          {/* Interactive Forensic Attack / Infrastructure Graph */}
          <AttackGraph data={data} />

          {/* Geolocation & Delivery Chronology 2-Column Sub-grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
            <GeolocationMap data={data} />
            <EvidenceTimeline data={data} />
          </div>
        </div>
      </div>
    </InvestigationVisualProvider>
  );
};
