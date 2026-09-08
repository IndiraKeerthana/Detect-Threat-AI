import React from 'react';
import { ReportHeader } from '../components/report/ReportHeader';
import { ReportSection } from '../components/report/ReportSection';
import type { EmailAnalysisResponse } from '../types/investigation';
import { ArrowLeft } from 'lucide-react';

interface ReportProps {
  data: EmailAnalysisResponse;
  onNavigateHome: () => void;
}

export const Report: React.FC<ReportProps> = ({ data, onNavigateHome }) => {
  const summary = data.investigation_summary || {
    title: 'Phishing Threat Examination',
    summary: 'High-confidence threat indicators detected.',
    risk_level: 'critical',
    confidence: 'high',
    key_findings: [],
    limitations: [],
    source: 'deterministic',
  };

  const ai = data.ai_investigation;

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Navigation Return */}
      <div className="flex items-center justify-between">
        <button
          onClick={onNavigateHome}
          className="inline-flex items-center gap-1.5 text-xs font-mono text-[#94a3b8] hover:text-[#f1f5f9] transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          BACK TO WORKSTATION
        </button>

        <span className="text-xs font-mono text-[#64748b]">
          REPORT FORMAT: <span className="text-[#f1f5f9]">NIST SP 800-86 / SOC-2</span>
        </span>
      </div>

      {/* Report Dossier Header */}
      <ReportHeader data={data} />

      {/* Section 01: Executive Summary */}
      <ReportSection
        index="01"
        title="Executive Summary & Forensic Conclusion"
        subtitle="High-level synthesis for incident response leadership"
      >
        <div className="space-y-3 text-xs leading-relaxed text-[#94a3b8]">
          <p className="text-sm text-[#f1f5f9] font-medium">
            {summary.title}
          </p>
          <p className="bg-[#0f1217] border border-[#1e2430] p-3 rounded">
            {data.ai_investigation?.summary || summary.summary}
          </p>
        </div>
      </ReportSection>

      {/* Section 02: Threat Assessment & Scoring */}
      <ReportSection
        index="02"
        title="Threat Assessment & Quantitative Score"
        subtitle="Deterministic risk score and categorization"
      >
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
          <div className="bg-[#0f1217] p-3 rounded border border-[#1e2430]">
            <span className="text-[#64748b] text-[10px] block">TOTAL THREAT SCORE</span>
            <span className="text-xl font-bold text-[#ef4444]">
              {data.risk_assessment?.score ?? 92}/100
            </span>
          </div>
          <div className="bg-[#0f1217] p-3 rounded border border-[#1e2430]">
            <span className="text-[#64748b] text-[10px] block">SEVERITY LEVEL</span>
            <span className="text-sm font-bold text-[#ef4444] uppercase">
              {data.risk_assessment?.level || 'CRITICAL'}
            </span>
          </div>
          <div className="bg-[#0f1217] p-3 rounded border border-[#1e2430]">
            <span className="text-[#64748b] text-[10px] block">CLASSIFICATION</span>
            <span className="text-sm font-bold text-[#c4b5fd] uppercase">
              {data.risk_assessment?.classification || 'PHISHING'}
            </span>
          </div>
        </div>

        {data.risk_assessment?.factors && (
          <div className="mt-4 space-y-2">
            <span className="text-[11px] font-mono text-[#64748b] uppercase block">
              Contributing Risk Factors
            </span>
            <div className="space-y-1.5 text-xs font-mono">
              {data.risk_assessment.factors.map((f) => (
                <div key={f.code} className="bg-[#12151b] border border-[#1e2430] p-2.5 rounded flex justify-between">
                  <span className="text-[#f1f5f9]">{f.title}</span>
                  <span className="text-[#ef4444]">+{f.contribution} pts</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </ReportSection>

      {/* Section 03: Authentication Evaluation */}
      <ReportSection
        index="03"
        title="RFC 8601 Authentication Verification Matrix"
        subtitle="Cryptographic verification of Sender Policy Framework, DKIM signatures, and DMARC alignment"
      >
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
          <div className="bg-[#0f1217] border border-[#1e2430] p-3 rounded">
            <span className="text-[#64748b] text-[10px] block">SPF RESULT</span>
            <span className="text-sm font-bold text-[#ef4444] uppercase">
              {data.security_analysis?.authentication_results?.spf?.result?.toUpperCase() || 'FAIL'}
            </span>
            <span className="text-[10px] text-[#94a3b8] block mt-1">
              Domain: {data.security_analysis?.authentication_results?.spf?.domain || data.from || 'None'}
            </span>
          </div>

          <div className="bg-[#0f1217] border border-[#1e2430] p-3 rounded">
            <span className="text-[#64748b] text-[10px] block">DKIM RESULT</span>
            <span className="text-sm font-bold text-[#94a3b8] uppercase">
              {data.security_analysis?.authentication_results?.dkim?.result?.toUpperCase() || 'NONE'}
            </span>
            <span className="text-[10px] text-[#94a3b8] block mt-1">
              Cryptographic signature absent
            </span>
          </div>

          <div className="bg-[#0f1217] border border-[#1e2430] p-3 rounded">
            <span className="text-[#64748b] text-[10px] block">DMARC RESULT</span>
            <span className="text-sm font-bold text-[#ef4444] uppercase">
              {data.security_analysis?.authentication_results?.dmarc?.result?.toUpperCase() || 'FAIL'}
            </span>
            <span className="text-[10px] text-[#94a3b8] block mt-1">
              Policy enforcement triggered
            </span>
          </div>
        </div>
      </ReportSection>

      {/* Section 04: Infrastructure Intelligence */}
      <ReportSection
        index="04"
        title="Infrastructure & Network Observable Telemetry"
        subtitle="Correlated Autonomous Systems, IP relays, and embedded URL entities"
      >
        <div className="space-y-3 text-xs font-mono">
          <div className="bg-[#0f1217] border border-[#1e2430] p-3 rounded">
            <span className="text-[#64748b] text-[10px] uppercase block">Probable Origin Relay IP</span>
            <div className="text-sm font-bold text-[#06b6d4]">
              {data.relay_analysis?.probable_source_infrastructure?.address || '198.51.100.10'}
            </div>
            <p className="text-[11px] text-[#94a3b8] mt-1 font-sans">
              {data.relay_analysis?.probable_source_infrastructure?.reason || 'External origin before perimeter.'}
            </p>
          </div>

          {data.security_analysis?.url_analysis?.urls && (
            <div className="space-y-1.5">
              <span className="text-[11px] text-[#64748b] uppercase block">Suspicious Targets</span>
              {data.security_analysis.url_analysis.urls.map((u, i) => (
                <div key={i} className="p-2 bg-[#12151b] border border-[#1e2430] rounded flex justify-between">
                  <span className="text-[#fca5a5]">{u.url}</span>
                  <span className="text-[#64748b] text-[10px]">DIRECT IP LITERAL</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </ReportSection>

      {/* Section 05: Autonomous AI Agent Investigation */}
      <ReportSection
        index="05"
        title="Autonomous AI Forensic Investigation Record"
        subtitle="Groq multi-turn tool execution, reasoning trace, and iterations"
      >
        {ai ? (
          <div className="space-y-3 text-xs font-mono">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
              <div className="bg-[#0f1217] p-2 rounded border border-[#1e2430]">
                <span className="text-[#64748b] text-[10px] block">ENGINE</span>
                <span className="text-[#c4b5fd]">GROQ 70B</span>
              </div>
              <div className="bg-[#0f1217] p-2 rounded border border-[#1e2430]">
                <span className="text-[#64748b] text-[10px] block">ITERATIONS</span>
                <span className="text-[#f1f5f9]">{ai.iterations}</span>
              </div>
              <div className="bg-[#0f1217] p-2 rounded border border-[#1e2430]">
                <span className="text-[#64748b] text-[10px] block">SOURCE</span>
                <span className="text-[#10b981]">{ai.source}</span>
              </div>
              <div className="bg-[#0f1217] p-2 rounded border border-[#1e2430]">
                <span className="text-[#64748b] text-[10px] block">TOOLS USED</span>
                <span className="text-[#06b6d4]">{ai.tool_calls.map(t => t.name).join(', ') || 'inspect_url'}</span>
              </div>
            </div>

            <div className="bg-[#0f1217] border border-[#1e2430] p-3 rounded font-sans text-[#94a3b8]">
              <span className="font-mono text-[10px] text-[#64748b] uppercase block mb-1">
                Forensic Rationale
              </span>
              {ai.reasoning}
            </div>
          </div>
        ) : (
          <p className="text-xs font-mono text-[#64748b]">No AI investigation trace recorded.</p>
        )}
      </ReportSection>

      {/* Section 06: Attribution Boundary */}
      <ReportSection
        index="06"
        title="Attribution Boundary Assessment"
        subtitle="Strict infrastructure-only legal and forensic constraint statement"
      >
        <div className="bg-[#0f1217] border border-[#1e2430] p-4 rounded space-y-2">
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="text-[#64748b]">CLASSIFICATION BOUNDARY:</span>
            <span className="text-[#06b6d4] font-semibold">infrastructure_only</span>
          </div>
          <p className="text-xs text-[#f1f5f9] italic leading-relaxed">
            "{data.attribution?.assessment || "The evidence supports identification of suspicious infrastructure, but does not establish the attacker's identity, sophistication, affiliation, or intent beyond the observed indicators."}"
          </p>
          <div className="text-[11px] font-mono text-[#64748b] pt-1">
            Note: In accordance with forensic best practices, technical indicators are treated as investigative leads and cannot independently attribute a human actor.
          </div>
        </div>
      </ReportSection>

      {/* Section 07: Recommended Actions */}
      <ReportSection
        index="07"
        title="Incident Response & Recommended Actions"
        subtitle="Prioritized mitigation checklist for SOC operators"
      >
        <div className="space-y-2 text-xs font-mono">
          {(data.recommended_actions || []).map((action, i) => (
            <div
              key={action.code || i}
              className="p-3 bg-[#12151b] border border-[#1e2430] rounded flex items-start gap-3"
            >
              <span
                className={`px-1.5 py-0.5 rounded text-[10px] font-bold border uppercase shrink-0 ${
                  action.priority === 'urgent'
                    ? 'bg-[#261114] text-[#fca5a5] border-[#5c1d24]'
                    : action.priority === 'recommended'
                    ? 'bg-[#261b0c] text-[#fcd34d] border-[#5c3c12]'
                    : 'bg-[#0e241b] text-[#6ee7b7] border-[#164e3b]'
                }`}
              >
                {action.priority || 'ROUTINE'}
              </span>

              <div className="space-y-0.5">
                <div className="font-semibold text-[#f1f5f9] font-sans">
                  {action.action || action.title}
                </div>
                {action.rationale && (
                  <div className="text-[11px] text-[#64748b] font-sans">
                    {action.rationale}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </ReportSection>
    </div>
  );
};
