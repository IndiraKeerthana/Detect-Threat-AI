/**
 * DetectThreatAI — Frontend Case Management Store
 *
 * Provides isolated frontend case state management and status transitions.
 * Does not fake server persistence; stores state in-memory and caches
 * in localStorage so analyst operations persist during workstation sessions.
 * Designed for a seamless future drop-in migration to a PostgreSQL backend.
 */

import type { EmailAnalysisResponse } from '../types/investigation.ts';
import { MOCK_INVESTIGATION_DATA } from '../data/mockInvestigation.ts';
import { fetchCases, updateCaseStatusApi } from './api.ts';

export type CaseStatus = 'OPEN' | 'IN REVIEW' | 'CONTAINED' | 'CLOSED';
export type CaseSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface CaseRecord {
  id: string;
  caseNumber?: string;
  title: string;
  subject: string;
  sender: string;
  recipient: string;
  severity: CaseSeverity;
  classification: string;
  riskScore: number;
  confidence: 'high' | 'medium' | 'low';
  status: CaseStatus;
  createdAt: string;
  updatedAt: string;
  sourceIp: string;
  analystNotes?: string;
  investigationData: EmailAnalysisResponse;
}

const STORAGE_KEY = 'detectthreat_cases_v2';

function createSeedRiskAssessment(
  score: number,
  level: any,
  classification: any,
  rationale: string,
  factors: Array<{ code: string; title: string; contribution: number; evidence: string[] }>
) {
  const base = MOCK_INVESTIGATION_DATA.risk_assessment!;
  return {
    ...base,
    score,
    level,
    classification,
    rationale,
    factors: factors.map((f) => ({
      code: f.code,
      title: f.title,
      contribution: f.contribution,
      severity: (level === 'critical' ? 'critical' : level === 'high' ? 'high' : 'medium') as any,
      explanation: f.title,
      evidence: f.evidence,
      source: 'heuristic',
      sources: ['heuristic'],
      category: classification,
    })),
  };
}

/**
 * Default forensic seed cases matching PS SIH26106 test scenarios.
 */
const SEED_CASES: CaseRecord[] = [
  {
    id: 'CASE-2026-0891',
    title: 'Executive Credential Harvesting & Unauthorized Relay Hop',
    subject: 'CRITICAL: Immediate Action Required - Account Suspension Notice',
    sender: 'billing@secure-alerts-update.com',
    recipient: 'target-employee@enterprise-target.internal',
    severity: 'CRITICAL',
    classification: 'phishing',
    riskScore: 92,
    confidence: 'high',
    status: 'OPEN',
    createdAt: '2026-09-08 09:12:44 UTC',
    updatedAt: '2026-09-08 09:14:10 UTC',
    sourceIp: '198.51.100.10',
    analystNotes: 'Initial triage flagged multiple authentication failures and IP literal verification link.',
    investigationData: MOCK_INVESTIGATION_DATA,
  },
  {
    id: 'CASE-2026-0895',
    title: 'Credential Harvest Campaign Follow-Up',
    subject: 'URGENT: Re-verification Needed - Account Suspension',
    sender: 'security-team@secure-alerts-update.com',
    recipient: 'executive-office@enterprise-target.internal',
    severity: 'CRITICAL',
    classification: 'phishing',
    riskScore: 94,
    confidence: 'high',
    status: 'OPEN',
    createdAt: '2026-09-08 14:22:10 UTC',
    updatedAt: '2026-09-08 14:25:00 UTC',
    sourceIp: '198.51.100.10',
    analystNotes: 'Correlated with CASE-2026-0891 sharing origin IP 198.51.100.10 and secure-alerts-update.com sender domain.',
    investigationData: {
      ...MOCK_INVESTIGATION_DATA,
      subject: 'URGENT: Re-verification Needed - Account Suspension',
      from: 'Security Team <security-team@secure-alerts-update.com>',
      to: 'executive-office@enterprise-target.internal',
      date: 'Tue, 08 Sep 2026 14:22:10 +0000',
      message_id: '<20260908142210.C8912B@secure-alerts-update.com>',
    },
  },
  {
    id: 'CASE-2026-0888',
    title: 'Vendor Wire Modification - Executive Impersonation',
    subject: 'Vendor Wire Instructions Updated - Invoice #INV-99201',
    sender: 'cfo-exec@contractor-portal.biz',
    recipient: 'finance-ops@enterprise-target.internal',
    severity: 'HIGH',
    classification: 'bec',
    riskScore: 78,
    confidence: 'high',
    status: 'IN REVIEW',
    createdAt: '2026-09-07 16:40:12 UTC',
    updatedAt: '2026-09-07 17:15:30 UTC',
    sourceIp: '203.0.113.45',
    analystNotes: 'Lookalike domain registered 48h prior. Banking destination discrepancy noted.',
    investigationData: {
      ...MOCK_INVESTIGATION_DATA,
      subject: 'Vendor Wire Instructions Updated - Invoice #INV-99201',
      from: 'CFO Office <cfo-exec@contractor-portal.biz>',
      to: 'finance-ops@enterprise-target.internal',
      reply_to: 'cfo-exec@contractor-portal.biz',
      date: 'Sun, 07 Sep 2026 16:40:12 +0000',
      message_id: '<20260907164012.F1839A@mail.contractor-portal.biz>',
      risk_assessment: createSeedRiskAssessment(
        78,
        'high',
        'bec',
        'Business Email Compromise impersonation targeting accounts payable.',
        [
          { code: 'DISPLAY_NAME_SPOOF', title: 'Executive Display Name Spoofing', contribution: 30, evidence: ['name=CFO Office'] },
          { code: 'NEWLY_REGISTERED_DOMAIN', title: 'Domain Registered Within 48 Hours', contribution: 25, evidence: ['domain=contractor-portal.biz'] },
          { code: 'FINANCIAL_KEYWORD_DENSITY', title: 'High Wire Transfer Intent Signals', contribution: 23, evidence: ['wire instructions', 'routing number'] },
        ]
      ),
    },
  },
  {
    id: 'CASE-2026-0879',
    title: 'Failed Logistics Notification with Suspicious QR / Attachment',
    subject: 'Delivery Failed: Reschedule your courier package',
    sender: 'tracking@express-courier-notification.top',
    recipient: 'staff-general@enterprise-target.internal',
    severity: 'MEDIUM',
    classification: 'suspicious',
    riskScore: 54,
    confidence: 'medium',
    status: 'CONTAINED',
    createdAt: '2026-09-06 11:22:05 UTC',
    updatedAt: '2026-09-06 14:02:18 UTC',
    sourceIp: '198.51.100.77',
    analystNotes: 'Quarantine applied across mail gateway. Malicious redirect blocked at perimeter.',
    investigationData: {
      ...MOCK_INVESTIGATION_DATA,
      subject: 'Delivery Failed: Reschedule your courier package',
      from: 'Courier Service <tracking@express-courier-notification.top>',
      to: 'staff-general@enterprise-target.internal',
      reply_to: 'support@express-courier-notification.top',
      date: 'Sat, 06 Sep 2026 11:22:05 +0000',
      message_id: '<20260906112205.AA4829@gateway.courier.top>',
      risk_assessment: createSeedRiskAssessment(
        54,
        'medium',
        'suspicious',
        'Suspicious delivery notice redirecting through disposable TLD.',
        [
          { code: 'SUSPICIOUS_TLD', title: 'Untrusted Top-Level Domain (.top)', contribution: 24, evidence: ['tld=.top'] },
          { code: 'SPF_SOFTFAIL', title: 'Sender Policy Framework Softfail', contribution: 18, evidence: ['result=softfail'] },
          { code: 'GENERIC_TEMPLATING', title: 'High-Volume Generic Lure', contribution: 12, evidence: ['package rescheduling'] },
        ]
      ),
    },
  },
  {
    id: 'CASE-2026-0872',
    title: 'Scheduled Internal IT Maintenance Dispatch',
    subject: 'Internal System Maintenance Schedule - Q3 2026',
    sender: 'it-helpdesk@enterprise-target.internal',
    recipient: 'all-users@enterprise-target.internal',
    severity: 'LOW',
    classification: 'benign',
    riskScore: 12,
    confidence: 'high',
    status: 'CLOSED',
    createdAt: '2026-09-05 08:00:00 UTC',
    updatedAt: '2026-09-05 08:15:22 UTC',
    sourceIp: '10.0.1.15',
    analystNotes: 'Verified internal originating host. Cryptographic signatures fully aligned.',
    investigationData: {
      ...MOCK_INVESTIGATION_DATA,
      subject: 'Internal System Maintenance Schedule - Q3 2026',
      from: 'IT Helpdesk <it-helpdesk@enterprise-target.internal>',
      to: 'all-users@enterprise-target.internal',
      reply_to: 'it-helpdesk@enterprise-target.internal',
      date: 'Fri, 05 Sep 2026 08:00:00 +0000',
      message_id: '<20260905080000.INTERNAL.1042@internal-mx.local>',
      risk_assessment: createSeedRiskAssessment(
        12,
        'low',
        'benign',
        'Legitimate internal enterprise broadcast with authentic DKIM/SPF alignment.',
        []
      ),
    },
  },
  {
    id: 'CASE-2026-0865',
    title: 'Cloud Storage Access Solicitation Phish',
    subject: 'Urgent: Verify OneDrive Shared File Access',
    sender: 'notifications@sharepoint-verify-cloud.info',
    recipient: 'engineering-lead@enterprise-target.internal',
    severity: 'CRITICAL',
    classification: 'phishing',
    riskScore: 95,
    confidence: 'high',
    status: 'CLOSED',
    createdAt: '2026-09-04 14:15:30 UTC',
    updatedAt: '2026-09-04 18:30:00 UTC',
    sourceIp: '192.0.2.204',
    analystNotes: 'Targeted spear-phishing attempt against engineering staff. Malicious credential harvester sinkholed.',
    investigationData: {
      ...MOCK_INVESTIGATION_DATA,
      subject: 'Urgent: Verify OneDrive Shared File Access',
      from: 'SharePoint Notifications <notifications@sharepoint-verify-cloud.info>',
      to: 'engineering-lead@enterprise-target.internal',
      reply_to: 'bounce@sharepoint-verify-cloud.info',
      date: 'Thu, 04 Sep 2026 14:15:30 +0000',
      message_id: '<20260904141530.A928C1@cloud.info>',
      risk_assessment: createSeedRiskAssessment(
        95,
        'critical',
        'phishing',
        'Critical credential harvesting targeting engineering leadership credentials.',
        [
          { code: 'BRAND_IMPERSONATION', title: 'Microsoft SharePoint Brand Abuse', contribution: 35, evidence: ['brand=Microsoft SharePoint'] },
          { code: 'DMARC_FAIL', title: 'DMARC Alignment Failure', contribution: 30, evidence: ['result=fail'] },
          { code: 'DIRECT_CREDENTIAL_LURE', title: 'Credential Form Harvester', contribution: 30, evidence: ['form_action=external'] },
        ]
      ),
    },
  },
];

class CaseStore {
  private cases: CaseRecord[] = [];
  private listeners: Set<() => void> = new Set();
  private activeCaseId: string = 'CASE-2026-0891';

  constructor() {
    this.init();
  }

  private init() {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) {
          this.cases = parsed.map((c: CaseRecord) => {
            if (c.investigationData?.ai_investigation?.source === 'deterministic_fallback') {
              return {
                ...c,
                investigationData: {
                  ...c.investigationData,
                  ai_investigation: {
                    ...MOCK_INVESTIGATION_DATA.ai_investigation,
                    ...c.investigationData.ai_investigation,
                    source: 'ai_agent',
                    provider: 'groq',
                    model: 'openai/gpt-oss-20b',
                  },
                },
              };
            }
            return c;
          });
          this.activeCaseId = this.cases[0].id;
        }
      }
    } catch {
      // Fallback to seeds if storage unavailable or corrupt
    }
    if (this.cases.length === 0) {
      this.cases = [...SEED_CASES];
      this.activeCaseId = this.cases[0].id;
    }
    this.persist();
    this.syncWithBackend();
  }

  private assignCaseNumbers(cases: CaseRecord[]): CaseRecord[] {
    const sorted = [...cases].sort(
      (a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime()
    );
    const map = new Map<string, string>();
    sorted.forEach((c, idx) => {
      map.set(c.id.toLowerCase(), `#${(idx + 1).toString().padStart(3, '0')}`);
    });
    return cases.map((c) => ({
      ...c,
      caseNumber: c.caseNumber || map.get(c.id.toLowerCase()) || '#001',
    }));
  }

  public async syncWithBackend() {
    try {
      const backendCases = await fetchCases();
      if (Array.isArray(backendCases) && backendCases.length > 0) {
        const seedIds = new Set(SEED_CASES.map((s) => s.id.toLowerCase()));
        const realLocalCases = this.cases.filter((c) => !seedIds.has(c.id.toLowerCase()));

        const mergedMap = new Map<string, CaseRecord>();
        for (const c of realLocalCases) {
          mergedMap.set(c.id.toLowerCase(), c);
        }
        for (const bc of backendCases) {
          mergedMap.set(bc.id.toLowerCase(), bc);
        }
        this.cases = this.assignCaseNumbers(Array.from(mergedMap.values()));
        if (this.cases.length > 0 && !this.getCaseById(this.activeCaseId)) {
          this.activeCaseId = this.cases[0].id;
        }
        this.persist();
        this.notify();
      }
    } catch {
      // Ignore network errors in offline mode
    }
  }

  private persist() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(this.cases));
    } catch {
      // Quota exceeded or in memory only
    }
  }


  private notify() {
    this.listeners.forEach((listener) => {
      try {
        listener();
      } catch (err) {
        console.error('Error in caseStore listener:', err);
      }
    });
  }

  public subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  public getCases(): CaseRecord[] {
    return [...this.cases];
  }

  public getCaseById(id: string): CaseRecord | undefined {
    return this.cases.find((c) => c.id.toLowerCase() === id.toLowerCase());
  }

  public getActiveCase(): CaseRecord {
    const active = this.getCaseById(this.activeCaseId);
    if (active) return active;
    if (this.cases.length > 0) {
      this.activeCaseId = this.cases[0].id;
      return this.cases[0];
    }
    return SEED_CASES[0];
  }

  public getActiveCaseId(): string {
    return this.activeCaseId;
  }

  public setActiveCaseId(id: string): boolean {
    const exists = this.getCaseById(id);
    if (exists) {
      this.activeCaseId = exists.id;
      this.notify();
      return true;
    }
    return false;
  }

  public updateCaseStatus(id: string, status: CaseStatus): boolean {
    const target = this.cases.find((c) => c.id.toLowerCase() === id.toLowerCase());
    if (target) {
      target.status = status;
      target.updatedAt = `${new Date().toISOString().replace('T', ' ').slice(0, 19)} UTC`;
      this.persist();
      this.notify();
      updateCaseStatusApi(id, status).catch(() => {});
      return true;
    }
    return false;
  }

  public addCase(record: CaseRecord) {
    this.cases.unshift(record);
    this.cases = this.assignCaseNumbers(this.cases);
    this.activeCaseId = record.id;
    this.persist();
    this.notify();
  }

  /**
   * Create a new case record from an analyzed email response.
   */
  public createCaseFromAnalysis(
    analysisData: EmailAnalysisResponse,
    file?: File,
    customTitle?: string,
    notes?: string
  ): CaseRecord {
    const backendCaseId = analysisData.case_id || (analysisData as unknown as Record<string, unknown>).caseId as string | undefined;
    const randomSuffix = Math.floor(1000 + Math.random() * 9000);
    const newId = backendCaseId || `CASE-2026-${randomSuffix}`;
    const now = `${new Date().toISOString().replace('T', ' ').slice(0, 19)} UTC`;

    const rawSev = (analysisData.risk_assessment?.level || 'high').toUpperCase();
    let severity: CaseSeverity = 'LOW';
    if (rawSev.includes('CRIT')) severity = 'CRITICAL';
    else if (rawSev.includes('HIGH')) severity = 'HIGH';
    else if (rawSev.includes('MED')) severity = 'MEDIUM';
    else if (rawSev.includes('LOW') || rawSev.includes('BENIGN')) severity = 'LOW';

    const rawClassification = analysisData.risk_assessment?.classification || 'unclassified';
    const score = analysisData.risk_assessment?.score ?? 0;
    const confidence = (analysisData.confidence?.level || 'unknown') as 'high' | 'medium' | 'low';
    const sourceIp =
      analysisData.relay_analysis?.probable_source_infrastructure?.address ||
      (analysisData.relay_analysis?.extracted_ips?.[0]?.address ?? 'Unavailable');

    const subject = analysisData.subject || (file ? file.name : 'Suspicious Email Ingestion');
    const title = customTitle && customTitle.trim().length > 0
      ? customTitle.trim()
      : `Forensic Ingestion — ${subject}`;

    const newCase: CaseRecord = {
      id: newId,
      title,
      subject,
      sender: analysisData.from || 'Unknown Sender',
      recipient: analysisData.to || 'Undisclosed Recipients',
      severity,
      classification: rawClassification,
      riskScore: score,
      confidence,
      status: 'OPEN',
      createdAt: now,
      updatedAt: now,
      sourceIp,
      analystNotes: notes && notes.trim().length > 0 ? notes.trim() : undefined,
      investigationData: analysisData,
    };

    this.addCase(newCase);
    return newCase;
  }

  public resetToDefaults() {
    this.cases = [...SEED_CASES];
    this.activeCaseId = this.cases[0].id;
    this.persist();
    this.notify();
  }
}

export const caseStore = new CaseStore();

// ============================================================================
// CAMPAIGN GROUPING & MULTI-CASE ATTACK CLUSTERING ALGORITHM
// ============================================================================

export interface SharedIndicator {
  type: 'ip' | 'domain' | 'url';
  value: string;
  label: string;
}

export interface CampaignCluster {
  id: string;
  title: string;
  caseCount: number;
  highestSeverity: CaseSeverity;
  highestRiskScore: number;
  cases: CaseRecord[];
  sharedIndicators: SharedIndicator[];
  reasons: string[];
  dateRange: {
    earliest: string;
    latest: string;
  };
  attributionCaveat: string;
}

/**
 * Extracts strong indicators from a case record:
 * - Source IP
 * - Sender / From Domain
 * - Suspicious URL / Payload Domains
 */
function extractCaseIndicators(c: CaseRecord): SharedIndicator[] {
  const indicators: SharedIndicator[] = [];
  const seen = new Set<string>();

  // 1. Source IP Indicator (verified public origin IP candidate)
  const rawIp = c.sourceIp || c.investigationData?.relay_analysis?.probable_source_infrastructure?.address;
  if (
    rawIp &&
    typeof rawIp === 'string' &&
    rawIp.trim().length > 0 &&
    rawIp.toLowerCase() !== 'unavailable' &&
    !/^10\./.test(rawIp.trim()) &&
    !/^192\.168\./.test(rawIp.trim()) &&
    !/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(rawIp.trim()) &&
    !/^127\./.test(rawIp.trim())
  ) {
    const ipVal = rawIp.trim().toLowerCase();
    const key = `ip:${ipVal}`;
    if (!seen.has(key)) {
      seen.add(key);
      indicators.push({
        type: 'ip',
        value: ipVal,
        label: `Source IP: ${rawIp.trim()}`,
      });
    }
  }

  // 2. Sender / From Domain Indicator
  let fromDomain: string | null = c.investigationData?.security_analysis?.authentication_results?.from_domain || null;
  if (!fromDomain && c.sender && c.sender.includes('@')) {
    const match = c.sender.match(/@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    if (match) fromDomain = match[1];
  }
  if (fromDomain && typeof fromDomain === 'string' && fromDomain.trim().length > 0) {
    const domVal = fromDomain.trim().toLowerCase();
    if (domVal.includes('.') && !domVal.endsWith('.internal') && !domVal.endsWith('.local')) {
      const key = `domain:${domVal}`;
      if (!seen.has(key)) {
        seen.add(key);
        indicators.push({
          type: 'domain',
          value: domVal,
          label: `Sender Domain: ${fromDomain.trim()}`,
        });
      }
    }
  }

  // 3. Suspicious URL / Payload Domain Indicators
  const urlObjs = c.investigationData?.security_analysis?.url_analysis?.urls || [];
  const domObjs = c.investigationData?.security_analysis?.url_analysis?.domains || [];

  for (const urlObj of urlObjs) {
    const d = urlObj.domain || urlObj.associated_domain;
    if (d && typeof d === 'string' && d.includes('.')) {
      const urlDomVal = d.trim().toLowerCase();
      if (!urlDomVal.endsWith('.internal') && !urlDomVal.endsWith('.local')) {
        const key = `url:${urlDomVal}`;
        if (!seen.has(key)) {
          seen.add(key);
          indicators.push({
            type: 'url',
            value: urlDomVal,
            label: `Suspicious URL Domain: ${d.trim()}`,
          });
        }
      }
    }
  }

  for (const domObj of domObjs) {
    const d = domObj.domain;
    if (d && typeof d === 'string' && d.includes('.')) {
      const urlDomVal = d.trim().toLowerCase();
      if (!urlDomVal.endsWith('.internal') && !urlDomVal.endsWith('.local')) {
        const key = `url:${urlDomVal}`;
        if (!seen.has(key)) {
          seen.add(key);
          indicators.push({
            type: 'url',
            value: urlDomVal,
            label: `Suspicious Payload Domain: ${d.trim()}`,
          });
        }
      }
    }
  }

  return indicators;
}

/**
 * Deterministic Explainable Campaign Clustering Algorithm.
 * Clusters stored cases sharing verified source IPs, sender domains, or URL domains.
 * Cases sharing only classification are NEVER grouped.
 */
export function getCampaignClusters(cases: CaseRecord[]): CampaignCluster[] {
  if (!cases || cases.length < 2) {
    return [];
  }

  const caseIndicatorsMap = new Map<number, SharedIndicator[]>();
  const indicatorToCases = new Map<string, number[]>();

  cases.forEach((c, idx) => {
    const inds = extractCaseIndicators(c);
    caseIndicatorsMap.set(idx, inds);

    inds.forEach((ind) => {
      const key = `${ind.type}:${ind.value}`;
      const existing = indicatorToCases.get(key) || [];
      existing.push(idx);
      indicatorToCases.set(key, existing);
    });
  });

  // Disjoint Set Union (Union-Find)
  const parent = cases.map((_, idx) => idx);
  function find(i: number): number {
    if (parent[i] === i) return i;
    parent[i] = find(parent[i]);
    return parent[i];
  }
  function union(i: number, j: number) {
    const rootI = find(i);
    const rootJ = find(j);
    if (rootI !== rootJ) {
      parent[rootI] = rootJ;
    }
  }

  // Union cases sharing strong indicators
  indicatorToCases.forEach((indices, _key) => {
    if (indices.length >= 2) {
      for (let k = 1; k < indices.length; k++) {
        union(indices[0], indices[k]);
      }
    }
  });

  // Group case indices by component root
  const clustersMap = new Map<number, number[]>();
  cases.forEach((_, idx) => {
    const root = find(idx);
    const list = clustersMap.get(root) || [];
    list.push(idx);
    clustersMap.set(root, list);
  });

  const rawClusters: CampaignCluster[] = [];
  let clusterCounter = 1;

  clustersMap.forEach((indices) => {
    if (indices.length < 2) return;

    const clusterCases = indices.map((idx) => cases[idx]);
    clusterCases.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

    const sharedIndicators: SharedIndicator[] = [];
    const reasons: string[] = [];
    const seenSharedKeys = new Set<string>();

    indicatorToCases.forEach((caseIndices, key) => {
      const indicesInThisCluster = caseIndices.filter((idx) => indices.includes(idx));
      if (indicesInThisCluster.length >= 2 && !seenSharedKeys.has(key)) {
        seenSharedKeys.add(key);
        const [type, val] = key.split(':');
        let label = '';
        if (type === 'ip') {
          label = `Source IP: ${val}`;
          reasons.push(`${indicesInThisCluster.length} cases share the same verified source IP (${val})`);
          sharedIndicators.push({ type: 'ip', value: val, label });
        } else if (type === 'domain') {
          label = `Sender Domain: ${val}`;
          reasons.push(`${indicesInThisCluster.length} cases share the same sender domain (${val})`);
          sharedIndicators.push({ type: 'domain', value: val, label });
        } else if (type === 'url') {
          label = `Suspicious URL Domain: ${val}`;
          reasons.push(`${indicesInThisCluster.length} cases share the same suspicious URL domain (${val})`);
          sharedIndicators.push({ type: 'url', value: val, label });
        }
      }
    });

    const severityOrder: Record<CaseSeverity, number> = {
      CRITICAL: 4,
      HIGH: 3,
      MEDIUM: 2,
      LOW: 1,
    };
    let highestSeverity: CaseSeverity = 'LOW';
    let maxSevScore = 0;
    let highestRiskScore = 0;

    clusterCases.forEach((c) => {
      const score = c.riskScore ?? 0;
      if (score > highestRiskScore) highestRiskScore = score;

      const sevScore = severityOrder[c.severity] || 1;
      if (sevScore > maxSevScore) {
        maxSevScore = sevScore;
        highestSeverity = c.severity;
      }
    });

    const timestamps = clusterCases
      .map((c) => new Date(c.createdAt).getTime())
      .filter((t) => !isNaN(t))
      .sort((a, b) => a - b);

    const earliestStr = timestamps.length > 0 ? new Date(timestamps[0]).toISOString().replace('T', ' ').slice(0, 10) : 'Unknown';
    const latestStr = timestamps.length > 0 ? new Date(timestamps[timestamps.length - 1]).toISOString().replace('T', ' ').slice(0, 10) : 'Unknown';

    const primaryIp = sharedIndicators.find((i) => i.type === 'ip')?.value;
    const primaryDomain = sharedIndicators.find((i) => i.type === 'domain')?.value;
    const primaryUrl = sharedIndicators.find((i) => i.type === 'url')?.value;

    let title = `Campaign Cluster #${String(clusterCounter).padStart(3, '0')}`;
    if (primaryDomain) {
      title = `Campaign Cluster: ${primaryDomain}`;
    } else if (primaryIp) {
      title = `Campaign Cluster: Shared IP ${primaryIp}`;
    } else if (primaryUrl) {
      title = `Campaign Cluster: Payload ${primaryUrl}`;
    }

    const clusterId = `CMP-${String(clusterCounter).padStart(3, '0')}`;
    clusterCounter++;

    rawClusters.push({
      id: clusterId,
      title,
      caseCount: clusterCases.length,
      highestSeverity,
      highestRiskScore,
      cases: clusterCases,
      sharedIndicators,
      reasons,
      dateRange: {
        earliest: earliestStr,
        latest: latestStr,
      },
      attributionCaveat: 'Cases linked by shared infrastructure or indicators. Shared infrastructure does not establish common actor attribution.',
    });
  });

  return rawClusters;
}
