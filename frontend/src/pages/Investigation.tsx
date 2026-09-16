import React from 'react';
import { InvestigationHeader } from '../components/investigation/InvestigationHeader';
import { ThreatAssessmentCard } from '../components/threat/ThreatAssessmentCard';
import { KeyFindingsList } from '../components/threat/KeyFindingsList';
import { AIInvestigationCard } from '../components/investigation/AIInvestigationCard';
import { AttackGraph } from '../components/graph/AttackGraph';
import { InfrastructureIntel } from '../components/intelligence/InfrastructureIntel';
import { RecommendationsCard } from '../components/investigation/RecommendationsCard';
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
  const recommendedActions =
    data.ai_investigation?.recommended_actions ||
    data.recommended_actions?.map((a) => a.action) ||
    [];

  return (
    <InvestigationVisualProvider>
      <div className="space-y-6 max-w-7xl mx-auto py-2 font-sans">
        {/* Top Header Bar & Case Metadata */}
        <InvestigationHeader
          data={data}
          caseRecord={caseRecord}
          caseId={caseRecord?.id || 'CASE-UNASSIGNED'}
          onStatusChange={onStatusChange}
          onViewReport={onViewReport}
          onNavigateBack={onNavigateHome}
        />

        {/* SECTION 1: Overall Risk Score & Classification */}
        <ThreatAssessmentCard
          data={data}
          assessment={data.risk_assessment}
          correlationCount={data.threat_intelligence?.relationships?.length || 0}
        />

        {/* SECTION 2: Why This Email Was Flagged */}
        <KeyFindingsList
          indicators={data.security_analysis?.indicators}
        />

        {/* SECTION 3: AI Safety Assessment */}
        <AIInvestigationCard
          aiData={data.ai_investigation}
          aiStatus={data.ai_status}
          aiError={data.ai_error}
        />

        {/* SECTION 4: Attack & Infrastructure Path */}
        <AttackGraph data={data} />

        {/* SECTION 5: Sender Location & Online Safety Check */}
        <InfrastructureIntel
          data={data}
          relay={data.relay_analysis}
          intelligence={data.threat_intelligence}
          urls={data.security_analysis?.url_analysis}
          auth={data.security_analysis?.authentication_results}
        />

        {/* SECTION 6: Recommendations */}
        <RecommendationsCard
          data={data}
          recommendedActions={recommendedActions}
          riskScore={data.risk_assessment?.score ?? 0}
        />
      </div>
    </InvestigationVisualProvider>
  );
};
