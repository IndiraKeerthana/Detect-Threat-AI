import React from 'react';
import { SectionHeader } from './SectionHeader';
import type { EmailAnalysisResponse } from '../../types/investigation';

interface RecommendationsCardProps {
  data?: EmailAnalysisResponse;
  recommendedActions?: string[];
  riskScore?: number;
}

interface ActionRecommendation {
  id: string;
  priorityWeight: number;
  title: string;
  description: string;
}

const RECIPIENT_ADVICE_PATTERNS = [
  /do not click/i,
  /do not download/i,
  /do not reply/i,
  /report (this )?email/i,
  /delete (this )?email/i,
  /avoid clicking/i,
  /move to junk/i,
];

export const RecommendationsCard: React.FC<RecommendationsCardProps> = ({
  data,
  recommendedActions = [],
  riskScore: passedRiskScore,
}) => {
  const riskScore = data?.risk_assessment?.score ?? passedRiskScore ?? 0;
  const classification = data?.risk_assessment?.classification ?? 'suspicious';
  const isHighRisk = riskScore >= 70 || classification === 'phishing' || classification === 'malware';
  const isMediumRisk = riskScore >= 40 && riskScore < 70;

  // Analysis observations from data
  const urls = data?.security_analysis?.url_analysis?.urls || [];
  const hasUrls = urls.length > 0 || (data?.security_analysis?.indicators?.some((i) => i.category === 'url') ?? false);

  const auth = data?.security_analysis?.authentication_results;
  const hasAuthFailures =
    auth?.spf?.result === 'fail' ||
    auth?.spf?.result === 'softfail' ||
    auth?.dkim?.result === 'fail' ||
    auth?.dkim?.result === 'none' ||
    auth?.dmarc?.result === 'fail' ||
    (data?.security_analysis?.indicators?.some((i) => i.category === 'authentication' && i.severity !== 'info') ?? false);

  const sourceIp = data?.relay_analysis?.probable_source_infrastructure?.address;
  const hasSuspiciousIp = Boolean(sourceIp) || (data?.relay_analysis?.extracted_ips?.some((ip) => ip.is_public_source_candidate) ?? false);

  const attachments = data?.attachments || [];
  const hasAttachments = attachments.length > 0 || (data?.security_analysis?.indicators?.some((i) => i.category === 'attachment') ?? false);

  const isBec =
    classification === 'bec' ||
    (data?.security_analysis?.content_signals?.signals?.some((s) => s.category === 'bec') ?? false) ||
    (data?.security_analysis?.indicators?.some(
      (i) => i.code.includes('BEC') || i.code.includes('FINANCIAL') || (i.category === 'content' && i.explanation.toLowerCase().includes('wire'))
    ) ?? false);

  const fromAddress = data?.from || data?.parsed_email?.from_address;

  // Filter raw backend / AI recommended actions to exclude recipient advice
  const filteredRawActions = recommendedActions.filter(
    (action) => !RECIPIENT_ADVICE_PATTERNS.some((pattern) => pattern.test(action))
  );

  // Helper to check if any filtered raw action provides specific context
  const getSpecificLead = (keywords: string[]): string | null => {
    for (const action of filteredRawActions) {
      if (keywords.some((kw) => action.toLowerCase().includes(kw))) {
        return action;
      }
    }
    return null;
  };

  // Build candidate recommendations dynamically
  const candidateRecommendations: ActionRecommendation[] = [];

  // 1. Immediate Containment / Block
  if (isHighRisk) {
    const lead = getSpecificLead(['block', 'sinkhole', 'blacklist']);
    candidateRecommendations.push({
      id: 'block-indicators',
      priorityWeight: 1,
      title: 'Block Confirmed Malicious Indicators',
      description: lead
        ? `Consider blocking confirmed malicious URLs, domains, or IP addresses across relevant security controls. Lead: ${lead}`
        : 'Consider blocking confirmed malicious URLs, domains, or IP addresses across relevant security controls.',
    });
  }

  // 2. Investigate Suspicious Links
  if (hasUrls) {
    const lead = getSpecificLead(['url', 'link', 'proxy', 'harvesting']);
    let desc =
      urls.length > 0
        ? `Review the ${urls.length} identified URL${urls.length > 1 ? 's' : ''} and determine whether they should be blocked.`
        : 'Review and analyze the identified URLs. Consider blocking confirmed malicious URLs.';
    if (lead && !desc.includes(lead)) {
      desc += ` Lead: ${lead}`;
    }
    candidateRecommendations.push({
      id: 'investigate-links',
      priorityWeight: 2,
      title: 'Investigate Suspicious Links',
      description: desc,
    });
  }

  // 3. Review Email Authentication
  if (hasAuthFailures) {
    const lead = getSpecificLead(['spf', 'dkim', 'dmarc', 'auth']);
    candidateRecommendations.push({
      id: 'review-auth',
      priorityWeight: 2,
      title: 'Review Email Authentication',
      description: lead
        ? `Investigate the authentication failures and verify whether the sender infrastructure is authorized. Lead: ${lead}`
        : 'Investigate the authentication failures and verify whether the sender infrastructure is authorized.',
    });
  }

  // 4. Check for Related Financial Requests
  if (isBec) {
    const lead = getSpecificLead(['invoice', 'payment', 'wire', 'financial']);
    candidateRecommendations.push({
      id: 'check-financial',
      priorityWeight: 2,
      title: 'Check for Related Financial Requests',
      description: lead
        ? `Search for similar payment, invoice, banking-change, or financial requests. Lead: ${lead}`
        : 'Search for similar payment, invoice, banking-change, or financial requests.',
    });
  }

  // 5. Analyze the Attachment
  if (hasAttachments) {
    const lead = getSpecificLead(['attachment', 'file', 'malware', 'payload']);
    candidateRecommendations.push({
      id: 'analyze-attachment',
      priorityWeight: 2,
      title: 'Analyze the Attachment',
      description:
        attachments.length > 0
          ? `Perform appropriate malware/file analysis on attachment (${attachments[0].filename || 'file'}) and check whether it was delivered to other users.`
          : lead
          ? `Perform appropriate malware/file analysis and check whether the attachment was delivered to other users. Lead: ${lead}`
          : 'Perform appropriate malware/file analysis and check whether the attachment was delivered to other users.',
    });
  }

  // 6. Investigate Source IP
  if (hasSuspiciousIp) {
    const lead = getSpecificLead(['ip', 'relay', 'origin']);
    candidateRecommendations.push({
      id: 'investigate-ip',
      priorityWeight: 3,
      title: 'Investigate Source IP',
      description: sourceIp
        ? `Review activity associated with IP ${sourceIp} and check for related incidents.`
        : lead
        ? `Review activity associated with the identified IP addresses and check for related incidents. Lead: ${lead}`
        : 'Review activity associated with the identified IP addresses and check for related incidents.',
    });
  }

  // 7. Investigate the Sender
  if (fromAddress) {
    candidateRecommendations.push({
      id: 'investigate-sender',
      priorityWeight: 3,
      title: 'Investigate the Sender',
      description: `Verify the sender identity (${fromAddress}), sending domain, and authentication results.`,
    });
  }

  // 8. Search for Related Emails (Scope/Campaign Hunting)
  const purgeLead = getSpecificLead(['purge', 'message-id', 'search', 'mailbox']);
  candidateRecommendations.push({
    id: 'search-related',
    priorityWeight: 4,
    title: 'Search for Related Emails',
    description: purgeLead
      ? `Search the organization's mail environment for matching senders, subjects, URLs, domains, IPs, or similar messages. Lead: ${purgeLead}`
      : "Search the organization's mail environment for matching senders, subjects, URLs, domains, IPs, or similar messages.",
  });

  // 9. Preserve Evidence
  candidateRecommendations.push({
    id: 'preserve-evidence',
    priorityWeight: 5,
    title: 'Preserve Evidence',
    description: 'Retain the original email, headers, URLs, attachments, timestamps, and relevant investigation evidence.',
  });

  // 10. Review Related Security Activity
  const telemetryLead = getSpecificLead(['session', 'sso', 'logs', 'telemetry', 'recipient']);
  candidateRecommendations.push({
    id: 'review-activity',
    priorityWeight: 6,
    title: 'Review Related Security Activity',
    description: telemetryLead
      ? `Check authentication logs, endpoint telemetry, proxy/DNS logs, SIEM events, and other relevant security data. Lead: ${telemetryLead}`
      : 'Check authentication logs, endpoint telemetry, proxy/DNS logs, SIEM events, and other relevant security data.',
  });

  // 11. Escalate the Incident
  if (isHighRisk || isMediumRisk) {
    candidateRecommendations.push({
      id: 'escalate-incident',
      priorityWeight: 7,
      title: 'Escalate the Incident',
      description: 'Escalate when evidence suggests credential theft, financial fraud, malware delivery, account compromise, or an active campaign.',
    });
  }

  // 12. Continue Investigation (Insufficient evidence / low risk case)
  if (riskScore < 30 && !isHighRisk && !hasAuthFailures && !hasUrls && !hasAttachments) {
    candidateRecommendations.unshift({
      id: 'continue-investigation',
      priorityWeight: 0,
      title: 'Continue Investigation',
      description: 'Additional evidence is required before taking containment action.',
    });
  }

  // Deduplicate items and select top 4–6 prioritized actions
  const uniqueRecommendationsMap = new Map<string, ActionRecommendation>();
  for (const rec of candidateRecommendations) {
    if (!uniqueRecommendationsMap.has(rec.id)) {
      uniqueRecommendationsMap.set(rec.id, rec);
    }
  }

  const selectedRecommendations = Array.from(uniqueRecommendationsMap.values())
    .sort((a, b) => a.priorityWeight - b.priorityWeight)
    .slice(0, 5);

  return (
    <div className="surface-card p-6 border border-[var(--border-subtle)] rounded-2xl space-y-6 font-sans">
      {/* Section Header */}
      <SectionHeader
        index={6}
        title="Recommendations"
        subtitle="Recommended next steps for investigating and responding to this email."
      />

      {/* Simple Clean Vertical List of Recommendations */}
      <div className="divide-y divide-[var(--border-subtle)]/60 pt-1">
        {selectedRecommendations.map((item) => (
          <div key={item.id} className="py-4 first:pt-1 last:pb-1 space-y-1">
            <div className="flex items-center gap-2.5">
              <span className="text-sky-400 font-mono text-sm font-semibold select-none shrink-0">→</span>
              <h4 className="font-semibold text-base text-[var(--text)] tracking-tight">
                {item.title}
              </h4>
            </div>
            <p className="text-xs text-[var(--text-muted)] leading-relaxed pl-6 font-normal max-w-4xl">
              {item.description}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
};
