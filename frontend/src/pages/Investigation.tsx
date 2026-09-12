import React from 'react';
import { InvestigationHeader } from '../components/investigation/InvestigationHeader';
import { ThreatAssessmentCard } from '../components/threat/ThreatAssessmentCard';
import { AIInvestigationCard } from '../components/investigation/AIInvestigationCard';
import { KeyFindingsList } from '../components/threat/KeyFindingsList';
import { InfrastructureIntel } from '../components/intelligence/InfrastructureIntel';
import { AttackGraph } from '../components/graph/AttackGraph';
import type { EmailAnalysisResponse } from '../types/investigation';
import type { CaseRecord, CaseStatus } from '../services/caseStore';
import { InvestigationVisualProvider } from '../context/InvestigationVisualContext';
import { SectionHeader } from '../components/investigation/SectionHeader';

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
  const recommendedActions = data.ai_investigation?.recommended_actions || [
    'Isolate recipient mailbox and revoke active session tokens immediately.',
    'Block origin IP address and sender domain on perimeter firewall & secure email gateway.',
    'Submit extracted payload URLs to automated URL detonation and threat intelligence feeds.',
    'Initiate tenant-wide email sweep for identical Message-ID or subject hash artifacts.',
  ];

  return (
    <InvestigationVisualProvider>
      <div className="space-y-6 max-w-7xl mx-auto py-2">
        {/* Case Header with Workflow Controls */}
        <InvestigationHeader
          data={data}
          caseRecord={caseRecord}
          caseId={caseRecord?.id || 'CASE-UNASSIGNED'}
          onStatusChange={onStatusChange}
          onViewReport={onViewReport}
          onNavigateBack={onNavigateHome}
        />

        {/* 01 Threat Posture Hero */}
        <ThreatAssessmentCard
          data={data}
          assessment={data.risk_assessment}
          correlationCount={data.threat_intelligence?.relationships?.length || 0}
        />

        {/* 02 Key Forensic Findings Ledger */}
        <KeyFindingsList
          indicators={data.security_analysis?.indicators}
        />

        {/* 03 AI Forensic Assessment */}
        <AIInvestigationCard
          aiData={data.ai_investigation}
          aiStatus={data.ai_status}
          aiError={data.ai_error}
        />

        {/* 04 Observable Topology (Protected Attack Graph) */}
        <AttackGraph data={data} />

        {/* 05 Infrastructure Intelligence */}
        <InfrastructureIntel
          data={data}
          relay={data.relay_analysis}
          intelligence={data.threat_intelligence}
          urls={data.security_analysis?.url_analysis}
        />

        {/* 06 Recommended Incident Response Actions */}
        <div className="surface-card p-5 border border-[var(--border-subtle)] space-y-4">
          <SectionHeader
            index="06"
            title="Recommended response actions"
            subtitle="Prioritized containment and mitigation steps derived from forensic assessment."
            action={
              <span className="text-xs font-mono text-[var(--text-dim)]">
                ACTIONS: <strong className="text-[var(--text)]">{recommendedActions.length}</strong>
              </span>
            }
          />

          <div className="border border-[var(--border-subtle)] rounded bg-[var(--surface-subtle)] divide-y divide-[var(--border-subtle)]">
            {recommendedActions.map((action, idx) => (
              <div key={idx} className="p-3.5 flex items-start gap-3 text-xs font-sans">
                <div className="w-5 h-5 rounded bg-[var(--surface)] border border-[var(--border-subtle)] flex items-center justify-center text-[var(--identifier)] font-mono text-[10px] font-bold shrink-0 mt-0.5">
                  {idx + 1}
                </div>
                <p className="text-[var(--text-muted)] leading-relaxed flex-1">
                  {action}
                </p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </InvestigationVisualProvider>
  );
};
