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

export type CaseStatus = 'OPEN' | 'IN REVIEW' | 'CONTAINED' | 'CLOSED';
export type CaseSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface CaseRecord {
  id: string;
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
          this.cases = parsed;
          this.activeCaseId = this.cases[0].id;
          return;
        }
      }
    } catch {
      // Fallback to seeds if storage unavailable or corrupt
    }
    this.cases = [...SEED_CASES];
    this.activeCaseId = this.cases[0].id;
    this.persist();
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
      return true;
    }
    return false;
  }

  public addCase(record: CaseRecord) {
    this.cases.unshift(record);
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
    const randomSuffix = Math.floor(1000 + Math.random() * 9000);
    const newId = `CASE-2026-${randomSuffix}`;
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
