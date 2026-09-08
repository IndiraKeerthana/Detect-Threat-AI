/**
 * Strict TypeScript types for DetectThreatAI forensic intelligence models.
 * Generated directly from backend Pydantic schemas (Steps 1–7).
 */

export type Confidence = 'high' | 'medium' | 'low' | 'unknown';
export type RiskLevel = 'benign' | 'low' | 'medium' | 'high' | 'critical';
export type ThreatClassification = 'benign' | 'phishing' | 'bec' | 'mixed' | 'suspicious' | 'malware' | 'spoofing' | 'spam';
export type AuthStatus = 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'temperror' | 'permerror' | 'skipped' | 'unknown';
export type IndicatorSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type GraphNodeType =
  | 'email'
  | 'identity'
  | 'ip'
  | 'domain'
  | 'url'
  | 'country'
  | 'region'
  | 'city'
  | 'asn'
  | 'location'
  | 'provider'
  | 'indicator'
  | 'provider_observation';

// --- Email Parser & Relays (Steps 1 & 2) ---

export interface AttachmentMetadata {
  filename: string | null;
  content_type: string;
  size: number;
}

export interface ExtractedIP {
  address: string;
  version: number;
  classification: string;
  is_public_source_candidate: boolean;
  hop_number: number;
}

export interface RelayHop {
  hop_number: number;
  original_header: string;
  hostnames: string[];
  extracted_ips: ExtractedIP[];
}

export interface CandidateSourceIP {
  address: string | null;
  confidence: string;
  reason: string;
}

export interface RelayAnalysisMetadata {
  received_header_count: number;
  input_header_order: string;
  reconstructed_order: string;
  source_selection_scope: string;
}

export interface RelayAnalysis {
  relay_hops: RelayHop[];
  extracted_ips: ExtractedIP[];
  probable_source_infrastructure: CandidateSourceIP;
  metadata: RelayAnalysisMetadata;
}

// --- Security Analysis (Steps 3 & 4) ---

export interface AuthenticationMethodResult {
  method: string;
  result: AuthStatus;
  domain?: string | null;
  selector?: string | null;
  identity?: string | null;
  reason?: string | null;
  properties?: Record<string, string>;
  raw: string;
}

export interface AuthenticationResultsAnalysis {
  headers: string[];
  authserv_ids: string[];
  results: AuthenticationMethodResult[];
  spf?: AuthenticationMethodResult | null;
  dkim?: AuthenticationMethodResult | null;
  dmarc?: AuthenticationMethodResult | null;
  from_domain?: string | null;
  return_path_domain?: string | null;
  reply_to_domain?: string | null;
  alignment_notes: string[];
}

export interface ExtractedURL {
  url: string;
  normalized_url: string;
  domain: string;
  scheme: string;
  port?: number | null;
  path: string;
  has_query: boolean;
  is_https: boolean;
  associated_domain: string;
  source: 'body_text' | 'body_html' | 'header';
}

export interface ExtractedDomain {
  domain: string;
  source: 'from' | 'reply_to' | 'return_path' | 'received' | 'url' | 'dkim' | 'dmarc' | 'body_text' | 'body_html' | 'header';
}

export interface URLDomainAnalysis {
  urls: ExtractedURL[];
  domains: ExtractedDomain[];
}

export interface ContentSignal {
  code: string;
  category: 'phishing' | 'bec' | 'social_engineering';
  severity: IndicatorSeverity;
  explanation: string;
  evidence: string[];
}

export interface ContentSignals {
  signals: ContentSignal[];
  normalized_text_length: number;
}

export interface SecurityIndicator {
  code: string;
  category: 'authentication' | 'url' | 'content' | 'identity' | 'attachment';
  severity: IndicatorSeverity;
  title: string;
  explanation: string;
  evidence: string[];
}

export interface SecurityAnalysis {
  summary: string;
  indicators: SecurityIndicator[];
  authentication_results: AuthenticationResultsAnalysis;
  url_analysis: URLDomainAnalysis;
  domains: ExtractedDomain[];
  content_signals: ContentSignals;
}

// --- Threat Intelligence (Step 5) ---

export interface ThreatEntity {
  type: 'ip' | 'domain' | 'url';
  value: string;
  sources: string[];
}

export interface ThreatObservation {
  provider: string;
  entity_type: 'ip' | 'domain' | 'url';
  entity: string;
  kind: string;
  status: 'success' | 'not_found' | 'error';
  data: Record<string, unknown>;
  evidence: string[];
  retrieved_at?: string | null;
  confidence: 'high' | 'medium' | 'low' | 'none';
}

export interface ProviderStatus {
  provider: string;
  configured: boolean;
  status: 'available' | 'degraded' | 'skipped' | 'error';
  checked: number;
  message?: string | null;
}

export interface ThreatRelationship {
  source_type: string;
  source: string;
  target_type: string;
  target: string;
  relationship: string;
  providers: string[];
}

export interface ThreatIntelligence {
  entities: ThreatEntity[];
  observations: ThreatObservation[];
  relationships: ThreatRelationship[];
  provider_status: ProviderStatus[];
}

// --- Deterministic Investigation (Step 6) ---

export interface Correlation {
  code: string;
  relationship: string;
  explanation: string;
  evidence: string[];
  entities: string[];
  confidence: Confidence;
  sources: string[];
}

export interface EvidenceGraphNode {
  id: string;
  type: GraphNodeType;
  value: string;
  sources: string[];
  properties: Record<string, unknown>;
}

export interface EvidenceGraphEdge {
  source: string;
  target: string;
  relationship: string;
  providers: string[];
  evidence: string[];
  confidence: Confidence;
  properties: Record<string, unknown>;
}

export interface EvidenceGraph {
  nodes: EvidenceGraphNode[];
  edges: EvidenceGraphEdge[];
  correlations: Correlation[];
}

export interface RiskFactor {
  code: string;
  title: string;
  contribution: number;
  severity: IndicatorSeverity;
  explanation: string;
  evidence: string[];
  source: string;
  sources: string[];
  category: string;
}

export interface ConfidenceFactor {
  category: 'authentication' | 'content' | 'url' | 'infrastructure' | 'reputation' | 'registration/DNS' | 'correlation';
  level: Confidence;
  explanation: string;
  evidence_count: number;
  evidence: string[];
  sources: string[];
}

export interface ConfidenceAssessment {
  level: Confidence;
  explanation: string;
  evidence_count: number;
  limitations: string[];
  factors: ConfidenceFactor[];
}

export interface RiskAssessment {
  score: number;
  level: RiskLevel;
  classification: ThreatClassification;
  threat_types: string[];
  factors: RiskFactor[];
  rationale: string;
  confidence: ConfidenceAssessment;
}

export interface AttributionAssessment {
  status: 'not_attributed' | 'infrastructure_only' | 'limited_attribution';
  assessment: string;
  confidence: Confidence;
  supporting_evidence: string[];
  limitations: string[];
}

export interface RecommendedAction {
  code: string;
  priority: 'routine' | 'recommended' | 'urgent';
  action: string;
  rationale: string;
  evidence: string[];
  title?: string;
  reason?: string;
  source?: string;
}

export interface InvestigationSummary {
  title: string;
  summary: string;
  risk_level: RiskLevel;
  confidence: Confidence;
  key_findings: string[];
  limitations: string[];
  source: 'deterministic' | 'fallback';
}

export interface InvestigationAnalysis {
  risk_assessment: RiskAssessment;
  attribution: AttributionAssessment;
  evidence_graph: EvidenceGraph;
  correlations: Correlation[];
  recommended_actions: RecommendedAction[];
  investigation_summary: InvestigationSummary;
}

// --- Step 7: Groq Autonomous AI Forensic Agent ---

export interface AIAttribution {
  status: 'not_attributed' | 'infrastructure_only' | 'limited_attribution';
  assessment: string;
  confidence: Confidence;
  supporting_evidence: string[];
  limitations: string[];
}

export interface AIFinding {
  title: string;
  severity: IndicatorSeverity;
  explanation: string;
  evidence: string[];
}

export interface AIToolCall {
  name: string;
  arguments: Record<string, unknown>;
  result_summary: string;
  target?: string | null;
  iteration?: number | null;
  status: string;
}

export interface AIInvestigationResult {
  summary: string;
  risk_level: RiskLevel;
  classification: ThreatClassification;
  confidence: Confidence;
  reasoning: string;
  key_findings: AIFinding[];
  recommended_actions: string[];
  attribution: AIAttribution;
  evidence: string[];
  tool_calls: AIToolCall[];
  iterations: number;
  source: 'ai_agent' | 'deterministic_fallback';
}

// --- Full API Response Contract ---

export interface EmailAnalysisResponse {
  from: string | null;
  to: string | null;
  cc: string | null;
  bcc: string | null;
  subject: string | null;
  date: string | null;
  message_id: string | null;
  reply_to: string | null;
  return_path: string | null;
  mime_version: string | null;
  content_type: string | null;
  received: string[];
  body_text: string | null;
  body_html: string | null;
  attachments: AttachmentMetadata[];
  relay_analysis?: RelayAnalysis | null;
  security_analysis?: SecurityAnalysis | null;
  threat_intelligence?: ThreatIntelligence | null;
  correlations: Correlation[];
  evidence_graph?: EvidenceGraph | null;
  risk_assessment?: RiskAssessment | null;
  confidence?: ConfidenceAssessment | null;
  attribution?: AttributionAssessment | null;
  attribution_limitations: string[];
  recommended_actions: RecommendedAction[];
  investigation_summary?: InvestigationSummary | null;
  investigation?: InvestigationAnalysis | null;
  ai_investigation?: AIInvestigationResult | null;
}

// --- Case Management (UI Foundation) ---

export interface CaseItem {
  id: string;
  subject: string;
  sender: string;
  recipient: string;
  severity: RiskLevel;
  classification: ThreatClassification;
  created: string;
  status: 'active' | 'in_review' | 'remediated' | 'closed';
  indicatorsCount: number;
  sourceIp: string;
  aiAttributionStatus: string;
}
