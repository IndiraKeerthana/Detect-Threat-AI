import React from 'react';
import { InvestigationHeader } from '../components/investigation/InvestigationHeader';
import { ThreatAssessmentCard } from '../components/threat/ThreatAssessmentCard';
import { AIInvestigationCard } from '../components/investigation/AIInvestigationCard';
import { KeyFindingsList } from '../components/threat/KeyFindingsList';
import { AuthenticationSection } from '../components/evidence/AuthenticationSection';
import { InfrastructureIntel } from '../components/intelligence/InfrastructureIntel';
import { AttackGraphPlaceholder } from '../components/graph/AttackGraphPlaceholder';
import { GeolocationPlaceholder } from '../components/map/GeolocationPlaceholder';
import { EvidenceTimelinePlaceholder } from '../components/evidence/EvidenceTimelinePlaceholder';
import type { EmailAnalysisResponse } from '../types/investigation';
import { ArrowLeft } from 'lucide-react';

interface InvestigationProps {
  data: EmailAnalysisResponse;
  onNavigateHome: () => void;
}

export const Investigation: React.FC<InvestigationProps> = ({
  data,
  onNavigateHome,
}) => {
  return (
    <div className="space-y-6">
      {/* Top Bar with Case Header */}
      <div className="flex items-center justify-between">
        <button
          onClick={onNavigateHome}
          className="inline-flex items-center gap-1.5 text-xs font-mono text-[#94a3b8] hover:text-[#f1f5f9] transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          BACK TO UPLOAD WORKSPACE
        </button>

        <span className="text-xs font-mono text-[#64748b]">
          CASE REF: <span className="text-[#f1f5f9]">CASE-2026-0891</span>
        </span>
      </div>

      {/* Main Email & Case Header */}
      <InvestigationHeader data={data} />

      {/* Primary 2-Column Workstation Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column (8 cols): Primary Forensic Findings & AI */}
        <div className="lg:col-span-8 space-y-6">
          {/* Autonomous AI Agent Card */}
          <AIInvestigationCard aiData={data.ai_investigation} />

          {/* Key Security Findings */}
          <KeyFindingsList
            indicators={data.security_analysis?.indicators}
            aiFindings={data.ai_investigation?.key_findings}
          />

          {/* RFC 8601 Authentication Matrix */}
          <AuthenticationSection auth={data.security_analysis?.authentication_results} />

          {/* Attack Graph Topology Placeholder */}
          <AttackGraphPlaceholder graph={data.evidence_graph} />
        </div>

        {/* Right Column (4 cols): Scoring, Infrastructure, Relays, Map */}
        <div className="lg:col-span-4 space-y-6">
          {/* Deterministic Scoring Card */}
          <ThreatAssessmentCard assessment={data.risk_assessment} />

          {/* Infrastructure & Threat Telemetry */}
          <InfrastructureIntel
            relay={data.relay_analysis}
            intelligence={data.threat_intelligence}
            urls={data.security_analysis?.url_analysis}
          />

          {/* Geolocation Origin Telemetry */}
          <GeolocationPlaceholder
            ips={data.relay_analysis?.extracted_ips}
            primaryIp={data.relay_analysis?.probable_source_infrastructure?.address}
          />

          {/* Chronological Relay Timeline */}
          <EvidenceTimelinePlaceholder hops={data.relay_analysis?.relay_hops} />
        </div>
      </div>
    </div>
  );
};
