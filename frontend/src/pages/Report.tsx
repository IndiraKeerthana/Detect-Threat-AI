import React from 'react';
import { ReportHeader } from '../components/report/ReportHeader';
import { ReportSection } from '../components/report/ReportSection';
import type { EmailAnalysisResponse } from '../types/investigation';
import type { CaseRecord } from '../services/caseStore';
import { ArrowLeft, Fingerprint } from 'lucide-react';

interface ReportProps {
  data: EmailAnalysisResponse;
  caseRecord?: CaseRecord;
  onNavigateHome: () => void;
}

export const Report: React.FC<ReportProps> = ({ data, caseRecord, onNavigateHome }) => {
  const activeId = caseRecord?.id || 'CASE-UNASSIGNED';
  const summary = data.investigation_summary;

  const ai = data.ai_investigation;
  const score = caseRecord?.riskScore ?? (data.risk_assessment?.score ?? 0);
  const severity = caseRecord?.severity || data.risk_assessment?.level || 'unknown';
  const classification = caseRecord?.classification || data.risk_assessment?.classification || 'unclassified';

  return (
    <div className="space-y-6 max-w-5xl mx-auto py-2">
      {/* Navigation Return & Dossier Standards Bar */}
      <div className="flex items-center justify-between pb-2 border-b border-[#1e2430]">
        <button
          onClick={onNavigateHome}
          className="inline-flex items-center gap-1.5 text-xs font-mono text-[#94a3b8] hover:text-[#f1f5f9] transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>BACK TO INVESTIGATION</span>
        </button>

        <span className="text-xs font-mono text-[#64748b]">
          REPORT SPECIFICATION: <span className="text-[#f1f5f9]">NIST SP 800-86 / SOC-2</span>
        </span>
      </div>

      {/* Official Report Header Dossier */}
      <ReportHeader data={data} caseRecord={caseRecord} />

      {/* SECTION 01: Case Summary */}
      <ReportSection
        index="01"
        title="Case Summary & Intake Reference"
        subtitle="Forensic case identifiers, scope, parties, and custody metadata"
      >
        <div className="space-y-3 font-mono text-xs">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="bg-[#0f1217] border border-[#1e2430] p-3 rounded space-y-1.5">
              <div className="flex justify-between">
                <span className="text-[#64748b] text-[10px] uppercase">CASE IDENTIFIER</span>
                <span className="text-[#06b6d4] font-bold">{activeId}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#64748b] text-[10px] uppercase">WORKFLOW STATUS</span>
                <span className="text-[#fcd34d] font-semibold uppercase">{caseRecord?.status || 'OPEN'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#64748b] text-[10px] uppercase">CREATION TIMESTAMP</span>
                <span className="text-[#f1f5f9]">{caseRecord?.createdAt || 'Unrecorded'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#64748b] text-[10px] uppercase">LAST MODIFIED</span>
                <span className="text-[#f1f5f9]">{caseRecord?.updatedAt || 'Unrecorded'}</span>
              </div>
            </div>

            <div className="bg-[#0f1217] border border-[#1e2430] p-3 rounded space-y-1.5">
              <div className="flex justify-between">
                <span className="text-[#64748b] text-[10px] uppercase">ORIGIN SENDER</span>
                <span className="text-[#f1f5f9] truncate ml-2 font-medium" title={data.from || ''}>
                  {data.from || 'Unspecified'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#64748b] text-[10px] uppercase">TARGET RECIPIENT</span>
                <span className="text-[#f1f5f9] truncate ml-2" title={data.to || ''}>
                  {data.to || 'Unspecified'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#64748b] text-[10px] uppercase">REPLY-TO ALIGNMENT</span>
                <span className="text-[#fca5a5] truncate ml-2" title={data.reply_to || 'Aligned'}>
                  {data.reply_to || 'Aligned'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#64748b] text-[10px] uppercase">PROBABLE RELAY IP</span>
                <span className="text-[#06b6d4]">
                  {caseRecord?.sourceIp || data.relay_analysis?.probable_source_infrastructure?.address || 'Unavailable'}
                </span>
              </div>
            </div>
          </div>

          {/* RFC 5322 Message-ID Technical Bar */}
          <div className="bg-[#0a0c10] border border-[#1e2430] p-2.5 rounded flex items-center justify-between gap-2">
            <div className="flex items-center space-x-2 truncate">
              <Fingerprint className="w-3.5 h-3.5 text-[#8b5cf6] shrink-0" />
              <span className="text-[10px] uppercase text-[#64748b]">RFC 5322 MESSAGE-ID:</span>
              <span className="text-[#06b6d4] truncate select-all">{data.message_id || 'None'}</span>
            </div>
            <span className="text-[10px] text-[#64748b] shrink-0">AUTHENTICATED ARTIFACT</span>
          </div>

          {caseRecord?.analystNotes && (
            <div className="bg-[#12151b] border border-[#1e2430] p-3 rounded">
              <span className="text-[10px] text-[#64748b] uppercase block mb-1">Analyst Intake Dispatch</span>
              <p className="text-xs text-[#94a3b8] font-sans">{caseRecord.analystNotes}</p>
            </div>
          )}
        </div>
      </ReportSection>

      {/* SECTION 02: Threat Assessment */}
      <ReportSection
        index="02"
        title="Threat Assessment & Quantitative Scoring"
        subtitle="Deterministic multi-factor risk assessment and categorization"
      >
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
          <div className="bg-[#0f1217] p-3 rounded border border-[#1e2430]">
            <span className="text-[#64748b] text-[10px] block">TOTAL THREAT SCORE</span>
            <span className="text-xl font-bold text-[#ef4444]">
              {score}/100
            </span>
          </div>
          <div className="bg-[#0f1217] p-3 rounded border border-[#1e2430]">
            <span className="text-[#64748b] text-[10px] block">SEVERITY LEVEL</span>
            <span className="text-sm font-bold text-[#ef4444] uppercase">
              {severity}
            </span>
          </div>
          <div className="bg-[#0f1217] p-3 rounded border border-[#1e2430]">
            <span className="text-[#64748b] text-[10px] block">CLASSIFICATION</span>
            <span className="text-sm font-bold text-[#c4b5fd] uppercase">
              {classification}
            </span>
          </div>
        </div>

        {data.risk_assessment?.factors && data.risk_assessment.factors.length > 0 && (
          <div className="mt-4 space-y-2">
            <span className="text-[11px] font-mono text-[#64748b] uppercase block">
              Contributing Risk Factors
            </span>
            <div className="space-y-1.5 text-xs font-mono">
              {data.risk_assessment.factors.map((f) => (
                <div key={f.code} className="bg-[#12151b] border border-[#1e2430] p-2.5 rounded flex justify-between">
                  <span className="text-[#f1f5f9]">{f.title}</span>
                  <span className="text-[#ef4444] font-bold">+{f.contribution} pts</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </ReportSection>

      {/* SECTION 03: Executive Findings */}
      <ReportSection
        index="03"
        title="Executive Findings & Forensic Conclusion"
        subtitle="High-level synthesis for incident response leadership and CISO briefing"
      >
        <div className="space-y-3 text-xs leading-relaxed text-[#94a3b8]">
          <p className="text-sm text-[#f1f5f9] font-medium font-sans">
            {summary?.title || 'Forensic Assessment Summary'}
          </p>
          <div className="bg-[#0f1217] border border-[#1e2430] p-3.5 rounded font-sans leading-relaxed text-[#f1f5f9]/90">
            {data.ai_investigation?.summary || summary?.summary || (
              'No executive narrative available for the analyzed artifact.'
            )}
          </div>
        </div>
      </ReportSection>

      {/* SECTION 04: Authentication Analysis */}
      <ReportSection
        index="04"
        title="Authentication Analysis (RFC 8601)"
        subtitle="Cryptographic verification of Sender Policy Framework, DKIM signatures, and DMARC alignment"
      >
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
          <div className="bg-[#0f1217] border border-[#1e2430] p-3 rounded">
            <span className="text-[#64748b] text-[10px] block uppercase">SPF VERIFICATION</span>
            <span className="text-sm font-bold text-[#ef4444] uppercase">
              {data.security_analysis?.authentication_results?.spf?.result?.toUpperCase() || 'NOT EVALUATED'}
            </span>
            <span className="text-[10px] text-[#94a3b8] block mt-1">
              Domain: {data.security_analysis?.authentication_results?.spf?.domain || data.from || 'None'}
            </span>
          </div>

          <div className="bg-[#0f1217] border border-[#1e2430] p-3 rounded">
            <span className="text-[#64748b] text-[10px] block uppercase">DKIM SIGNATURE</span>
            <span className="text-sm font-bold text-[#94a3b8] uppercase">
              {data.security_analysis?.authentication_results?.dkim?.result?.toUpperCase() || 'NOT EVALUATED'}
            </span>
            <span className="text-[10px] text-[#94a3b8] block mt-1">
              {data.security_analysis?.authentication_results?.dkim?.result ? 'Evaluated' : 'Cryptographic signature absent'}
            </span>
          </div>

          <div className="bg-[#0f1217] border border-[#1e2430] p-3 rounded">
            <span className="text-[#64748b] text-[10px] block uppercase">DMARC POLICY</span>
            <span className="text-sm font-bold text-[#ef4444] uppercase">
              {data.security_analysis?.authentication_results?.dmarc?.result?.toUpperCase() || 'NOT EVALUATED'}
            </span>
            <span className="text-[10px] text-[#94a3b8] block mt-1">
              {data.security_analysis?.authentication_results?.dmarc?.result ? 'Evaluated policy' : 'Policy not evaluated'}
            </span>
          </div>
        </div>
      </ReportSection>

      {/* SECTION 05: Infrastructure Intelligence */}
      <ReportSection
        index="05"
        title="Infrastructure Intelligence & Routing"
        subtitle="Correlated Autonomous Systems, IP relays, and embedded URL entities"
      >
        <div className="space-y-3 text-xs font-mono">
          <div className="bg-[#0f1217] border border-[#1e2430] p-3 rounded">
            <span className="text-[#64748b] text-[10px] uppercase block">Probable Origin Relay IP</span>
            <div className="text-sm font-bold text-[#06b6d4]">
              {caseRecord?.sourceIp || data.relay_analysis?.probable_source_infrastructure?.address || 'Unavailable'}
            </div>
            <p className="text-[11px] text-[#94a3b8] mt-1 font-sans">
              {data.relay_analysis?.probable_source_infrastructure?.reason ||
                'No relay rationale recorded.'}
            </p>
          </div>

          {data.security_analysis?.url_analysis?.urls && (
            <div className="space-y-1.5">
              <span className="text-[11px] text-[#64748b] uppercase block">Suspicious Embedded URLs</span>
              {data.security_analysis.url_analysis.urls.map((u, i) => (
                <div key={i} className="p-2 bg-[#12151b] border border-[#1e2430] rounded flex justify-between">
                  <span className="text-[#fca5a5]">{u.url}</span>
                  <span className="text-[#64748b] text-[10px]">
                    {/^(\d{1,3}\.){3}\d{1,3}$/.test(u.domain) ? 'DIRECT IP LITERAL' : (u.is_https ? 'HTTPS DOMAIN' : 'HTTP DOMAIN')}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </ReportSection>

      {/* SECTION 06: Evidence & Correlations */}
      <ReportSection
        index="06"
        title="Evidence & Correlations"
        subtitle="Forensic indicators, cross-observable linkages, and threat relationships"
      >
        <div className="space-y-2 text-xs font-mono">
          {(data.security_analysis?.indicators || []).map((ind, i) => (
            <div key={ind.code || i} className="bg-[#12151b] border border-[#1e2430] p-3 rounded space-y-1">
              <div className="flex items-center justify-between">
                <span className="font-bold text-[#f1f5f9]">{ind.title}</span>
                <span className="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase border bg-[#261114] text-[#fca5a5] border-[#5c1d24]">
                  {ind.severity}
                </span>
              </div>
              <p className="text-[11px] text-[#94a3b8] font-sans">{ind.explanation}</p>
              {ind.evidence && ind.evidence.length > 0 && (
                <div className="flex flex-wrap gap-1.5 pt-1">
                  {ind.evidence.map((ev, evIdx) => (
                    <span key={evIdx} className="px-1.5 py-0.5 rounded bg-[#0a0c10] border border-[#1e2430] text-[#06b6d4] text-[10px]">
                      {ev}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      </ReportSection>

      {/* SECTION 07: AI Investigation Summary */}
      <ReportSection
        index="07"
        title="AI Investigation Summary"
        subtitle={ai?.source === 'ai_agent' ? "Groq multi-turn autonomous tool execution, reasoning trace, and iterations" : "Rule-based forensic correlation, risk synthesis, and deterministic evaluation"}
      >
        {ai ? (
          <div className="space-y-3 text-xs font-mono">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
              <div className="bg-[#0f1217] p-2 rounded border border-[#1e2430]">
                <span className="text-[#64748b] text-[10px] block">PROVIDER</span>
                <span className={ai.source === 'ai_agent' ? "text-[#c4b5fd]" : "text-[#fcd34d]"}>
                  {(ai.provider || (ai.source === 'ai_agent' ? 'AI AGENT' : 'DETERMINISTIC FALLBACK')).toUpperCase()}
                </span>
              </div>
              <div className="bg-[#0f1217] p-2 rounded border border-[#1e2430]">
                <span className="text-[#64748b] text-[10px] block">MODEL</span>
                <span className="text-[#f1f5f9] truncate block" title={ai.model || 'N/A'}>
                  {ai.model || 'N/A'}
                </span>
              </div>
              <div className="bg-[#0f1217] p-2 rounded border border-[#1e2430]">
                <span className="text-[#64748b] text-[10px] block">SOURCE</span>
                <span className={ai.source === 'ai_agent' ? "text-[#10b981]" : "text-[#fcd34d]"}>
                  {ai.source.toUpperCase()}
                </span>
              </div>
              <div className="bg-[#0f1217] p-2 rounded border border-[#1e2430]">
                <span className="text-[#64748b] text-[10px] block">ITERATIONS</span>
                <span className="text-[#f1f5f9]">{ai.iterations}</span>
              </div>
            </div>

            <div className="bg-[#0f1217] border border-[#1e2430] p-3 rounded font-sans text-[#94a3b8]">
              <span className="font-mono text-[10px] text-[#64748b] uppercase block mb-1">
                Autonomous Forensic Rationale
              </span>
              {ai.reasoning}
            </div>
          </div>
        ) : (
          <p className="text-xs font-mono text-[#64748b]">No autonomous AI investigation trace recorded.</p>
        )}
      </ReportSection>

      {/* SECTION 08: Recommended Actions */}
      <ReportSection
        index="08"
        title="Recommended Actions"
        subtitle="Prioritized incident response mitigation checklist for SOC operators"
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

      {/* SECTION 09: Attribution Limitations */}
      <ReportSection
        index="09"
        title="Attribution Limitations"
        subtitle="Strict infrastructure-only legal and forensic constraint statement"
      >
        <div className="bg-[#0f1217] border border-[#1e2430] p-4 rounded space-y-2">
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="text-[#64748b]">CLASSIFICATION BOUNDARY:</span>
            <span className="text-[#06b6d4] font-semibold">infrastructure_only</span>
          </div>
          <p className="text-xs text-[#f1f5f9] italic leading-relaxed font-serif">
            "{data.attribution?.assessment || "The evidence supports identification of suspicious infrastructure, but does not establish the attacker's identity, sophistication, affiliation, or intent beyond the observed indicators."}"
          </p>
          <div className="text-[11px] font-mono text-[#64748b] pt-1">
            Note: In accordance with forensic best practices, technical indicators are treated as investigative leads and cannot independently attribute a human actor.
          </div>
        </div>
      </ReportSection>
    </div>
  );
};
