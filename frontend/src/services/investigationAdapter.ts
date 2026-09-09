/**
 * Forensic Data Adapter for DetectThreatAI
 * Normalizes backend investigation schemas and mock data into clean,
 * typed structures for the Graph, Map, and Evidence Timeline.
 */

import type {
  EmailAnalysisResponse,
  Confidence,
  IndicatorSeverity,
  RelayHop,
} from '../types/investigation';

// --- 1. Graph Data Models ---

export type ForensicNodeType =
  | 'email'
  | 'domain'
  | 'url'
  | 'ip'
  | 'asn'
  | 'location'
  | 'identity'
  | 'dns'
  | 'provider'
  | 'relay';

export type NodeStatusState = 'neutral' | 'suspicious' | 'malicious' | 'unavailable';

export interface NormalizedGraphNode {
  id: string;
  type: ForensicNodeType;
  label: string;
  primaryValue: string;
  secondaryMeta?: string;
  severity: IndicatorSeverity;
  status: NodeStatusState;
  whyItMatters?: string;
  rankColumn: number;
  source: string;
  confidence: Confidence;
  properties: Record<string, unknown>;
  evidence?: string[];
}

export interface NormalizedGraphEdge {
  id: string;
  source: string;
  target: string;
  relationship: string;
  label: string;
  isObserved: boolean;
  confidence: Confidence;
  evidence: string[];
}

export interface NormalizedGraphData {
  nodes: NormalizedGraphNode[];
  edges: NormalizedGraphEdge[];
  correlationsCount: number;
}

export interface InvestigationPathStage {
  id: string;
  category: 'EMAIL' | 'SENDER' | 'RELAY' | 'SOURCE_IP' | 'NETWORK' | 'GEOLOCATION';
  label: string;
  value: string;
  status: 'available' | 'unavailable' | 'suspicious' | 'malicious';
  detail?: string;
}

// --- 2. Map Data Models ---

export interface NormalizedMapLocation {
  ip: string;
  latitude: number;
  longitude: number;
  country: string;
  countryCode?: string;
  region?: string;
  city?: string;
  asn?: string;
  organization?: string;
  confidence: Confidence;
  source: string;
  abuseScore?: number;
}

// --- 3. Timeline Data Models ---

export type TimelineEventCategory =
  | 'INGESTION'
  | 'RELAY_HOP'
  | 'AUTHENTICATION'
  | 'URL_DISCOVERY'
  | 'INTELLIGENCE'
  | 'AI_TOOL_EXECUTION'
  | 'CORRELATION'
  | 'ASSESSMENT';

export type TimelineEventState = 'critical' | 'warning' | 'verified' | 'informational';

export interface NormalizedTimelineEvent {
  id: string;
  step: number;
  timeOffset: string;
  category: TimelineEventCategory;
  categoryLabel: string;
  title: string;
  description: string;
  source: string;
  state: TimelineEventState;
  evidence: string[];
  relatedEntityId?: string;
  hasLocation?: boolean;
}

// ============================================================================
// ADAPTER FUNCTIONS
// ============================================================================

/**
 * Normalizes graph nodes and edges from EmailAnalysisResponse
 * Enforces strict 3-layer topology:
 * 1. Primary Observed Email Path (Solid edges: EMAIL -> SENDER -> RELAY -> SOURCE IP)
 * 2. Correlated Email Relationships (Solid edges: EMAIL -> REPLY-TO, EMAIL -> URL PAYLOAD)
 * 3. External Intelligence Enrichment (Dashed edges: SOURCE IP -> ASN, SOURCE IP -> GEOLOCATION)
 * Node budget: 5-8 nodes max.
 * Provenance: IPs like 8.8.8.8 from external threat intel/DNS lookups are NEVER promoted to observed SOURCE IP or SMTP RELAY.
 */
export function normalizeGraphData(data: EmailAnalysisResponse): NormalizedGraphData {
  const nodesMap = new Map<string, NormalizedGraphNode>();
  const edgesMap = new Map<string, NormalizedGraphEdge>();
  const obsList = data.threat_intelligence?.observations || [];

  // Layer A: Primary Observed Email Path

  // Stage 0: Root Email Node
  const rootEmailId = 'email:root';
  const emailSubject = data.subject || 'Email Subject';
  const emailFrom = data.from || undefined;
  nodesMap.set(rootEmailId, {
    id: rootEmailId,
    type: 'email',
    label: data.message_id ? data.message_id.replace(/[<>]/g, '') : 'Root Email Artifact',
    primaryValue: emailSubject,
    secondaryMeta: emailFrom,
    severity: 'info',
    status: 'neutral',
    whyItMatters: 'Primary investigation root artifact received for forensic evaluation.',
    rankColumn: 0,
    source: 'RFC 5322 Headers',
    confidence: 'high',
    properties: {
      from: data.from,
      to: data.to,
      date: data.date,
      message_id: data.message_id,
      role: 'email_root',
    },
  });

  // Stage 1: Sender Node (Authenticated From Header Domain or Identity)
  const probableRelayAddress = data.relay_analysis?.probable_source_infrastructure?.address;
  const isRelayObserved = Boolean(probableRelayAddress && probableRelayAddress.trim().length > 0);

  const fromDomain = data.security_analysis?.authentication_results?.from_domain;
  const authResults = data.security_analysis?.authentication_results;
  const isAuthFail = authResults?.spf?.result === 'fail' || authResults?.dmarc?.result === 'fail';

  let senderNodeId: string | null = null;
  if (fromDomain) {
    senderNodeId = `domain:${fromDomain.toLowerCase()}`;
    const domainProperties: Record<string, unknown> = { domain: fromDomain, role: 'sender' };
    const domainEvidence: string[] = ['RFC 5322 From header domain'];

    if (authResults?.spf?.result) {
      domainProperties.spf = authResults.spf.result;
      domainEvidence.push(`SPF ${authResults.spf.result}`);
    }
    if (authResults?.dkim?.result) {
      domainProperties.dkim = authResults.dkim.result;
      domainEvidence.push(`DKIM ${authResults.dkim.result}`);
    }
    if (authResults?.dmarc?.result) {
      domainProperties.dmarc = authResults.dmarc.result;
      domainEvidence.push(`DMARC ${authResults.dmarc.result}`);
    }

    const domainObs = data.threat_intelligence?.observations?.find(
      (o) => o.entity_type === 'domain' && o.entity.toLowerCase() === fromDomain.toLowerCase()
    );
    if (domainObs?.data) {
      const dData = domainObs.data as Record<string, unknown>;
      if (typeof dData.age_days === 'number') domainProperties.age_days = dData.age_days;
      if (typeof dData.registrar === 'string') domainProperties.registrar = dData.registrar;
      if (typeof dData.created_date === 'string') domainProperties.created_date = dData.created_date;
    }
    if (domainObs?.evidence && Array.isArray(domainObs.evidence)) {
      domainEvidence.push(...domainObs.evidence);
    }

    nodesMap.set(senderNodeId, {
      id: senderNodeId,
      type: 'domain',
      label: fromDomain,
      primaryValue: fromDomain,
      secondaryMeta: domainProperties.age_days !== undefined
        ? `From Header (Age: ${domainProperties.age_days}d)`
        : 'Authenticated From Domain',
      severity: isAuthFail ? 'high' : 'info',
      status: isAuthFail ? 'suspicious' : 'neutral',
      whyItMatters: isAuthFail
        ? 'Email sender domain failed SPF/DMARC authentication checks.'
        : 'Authenticated envelope and header sender domain.',
      rankColumn: 1,
      source: 'RFC 5322 From',
      confidence: 'high',
      properties: domainProperties,
      evidence: domainEvidence,
    });

    edgesMap.set(`${rootEmailId}->${senderNodeId}:sent_from`, {
      id: `${rootEmailId}->${senderNodeId}:sent_from`,
      source: rootEmailId,
      target: senderNodeId,
      relationship: 'sent_from',
      label: 'SENT FROM',
      isObserved: true,
      confidence: 'high',
      evidence: ['RFC 5322 From header match'],
    });
  } else if (isRelayObserved) {
    // Only render sender placeholder in horizontal topology when real infrastructure IS observed
    senderNodeId = 'domain:sender_unavailable';
    nodesMap.set(senderNodeId, {
      id: senderNodeId,
      type: 'domain',
      label: 'SENDER\n[Unavailable]',
      primaryValue: 'Sender Unavailable',
      secondaryMeta: 'Not observed in headers',
      severity: 'info',
      status: 'unavailable',
      whyItMatters: 'No authenticated sender domain observed in headers.',
      rankColumn: 1,
      source: 'Header Analysis',
      confidence: 'high',
      properties: { role: 'sender' },
      evidence: ['No RFC 5322 From header domain observed'],
    });

    edgesMap.set(`${rootEmailId}->${senderNodeId}:sent_from_na`, {
      id: `${rootEmailId}->${senderNodeId}:sent_from_na`,
      source: rootEmailId,
      target: senderNodeId,
      relationship: 'sent_from',
      label: 'SENT FROM (N/A)',
      isObserved: false,
      confidence: 'high',
      evidence: ['Unobserved sender domain stage'],
    });
  }

  // Stage 2: Ingress Relay & Infrastructure Processing
  if (isRelayObserved && probableRelayAddress) {
    // --- REAL OBSERVED INFRASTRUCTURE TOPOLOGY (FULL 6-STAGE TOPOLOGY) ---

    // SMTP Relay Node (Rank 2)
    const relayNodeId = `relay:${probableRelayAddress.toLowerCase()}`;
    const matchingObs = data.threat_intelligence?.observations?.find(
      (o) => o.entity_type === 'ip' && o.entity.toLowerCase() === probableRelayAddress.toLowerCase()
    );
    const obsData = (matchingObs?.data || {}) as Record<string, unknown>;
    const ipProperties: Record<string, unknown> = { address: probableRelayAddress, role: 'relay' };
    if (data.relay_analysis?.probable_source_infrastructure?.reason) {
      ipProperties.selection_reason = data.relay_analysis.probable_source_infrastructure.reason;
    }
    if (typeof obsData.abuse_confidence_score === 'number') {
      ipProperties.abuse_score = obsData.abuse_confidence_score;
    } else if (typeof obsData.abuse_score === 'number') {
      ipProperties.abuse_score = obsData.abuse_score;
    }

    const ipEvidence: string[] = [];
    if (data.relay_analysis?.probable_source_infrastructure?.reason) {
      ipEvidence.push(data.relay_analysis.probable_source_infrastructure.reason);
    }
    if (matchingObs?.evidence && Array.isArray(matchingObs.evidence)) {
      ipEvidence.push(...matchingObs.evidence);
    }

    const abuseScoreNum = typeof ipProperties.abuse_score === 'number' ? ipProperties.abuse_score : 0;
    const isAbuseHigh = abuseScoreNum > 50;

    nodesMap.set(relayNodeId, {
      id: relayNodeId,
      type: 'relay',
      label: probableRelayAddress,
      primaryValue: probableRelayAddress,
      secondaryMeta: 'Perimeter Ingress Relay',
      severity: isAbuseHigh ? 'critical' : 'info',
      status: isAbuseHigh ? 'malicious' : 'neutral',
      whyItMatters: 'Strongest verified public ingress infrastructure candidate extracted from Received header chain.',
      rankColumn: 2,
      source: matchingObs?.provider ? `Received Ingress / ${matchingObs.provider}` : 'Received Header Ingress',
      confidence: 'high',
      properties: ipProperties,
      evidence: ipEvidence.length > 0 ? ipEvidence : ['Perimeter ingress relay hop'],
    });

    const edgeSource = senderNodeId || rootEmailId;
    edgesMap.set(`${edgeSource}->${relayNodeId}:delivered_via`, {
      id: `${edgeSource}->${relayNodeId}:delivered_via`,
      source: edgeSource,
      target: relayNodeId,
      relationship: 'delivered_via',
      label: 'DELIVERED VIA',
      isObserved: true,
      confidence: 'high',
      evidence: ['Received header ingress route'],
    });

    // Source IP Node (Rank 3)
    const sourceIpNodeId = `ip:${probableRelayAddress.toLowerCase()}`;
    const ipProps: Record<string, unknown> = { address: probableRelayAddress, role: 'source_ip' };
    if (typeof obsData.abuse_confidence_score === 'number') {
      ipProps.abuse_score = obsData.abuse_confidence_score;
    }
    if (typeof obsData.reverse_dns === 'string') ipProps.reverse_dns = obsData.reverse_dns;

    nodesMap.set(sourceIpNodeId, {
      id: sourceIpNodeId,
      type: 'ip',
      label: probableRelayAddress,
      primaryValue: probableRelayAddress,
      secondaryMeta: 'Source IP Endpoint',
      severity: isAbuseHigh ? 'critical' : 'info',
      status: isAbuseHigh ? 'malicious' : 'neutral',
      whyItMatters: 'Verified public origin IP address associated with email ingress infrastructure.',
      rankColumn: 3,
      source: 'Relay Analysis',
      confidence: 'high',
      properties: ipProps,
      evidence: matchingObs?.evidence || ['Extracted from ingress relay hop'],
    });

    edgesMap.set(`${relayNodeId}->${sourceIpNodeId}:origin_ip`, {
      id: `${relayNodeId}->${sourceIpNodeId}:origin_ip`,
      source: relayNodeId,
      target: sourceIpNodeId,
      relationship: 'origin_ip',
      label: 'SOURCE IP',
      isObserved: true,
      confidence: 'high',
      evidence: ['Relay origin endpoint'],
    });

    // Layer C: External Intelligence Enrichment (Dashed Edges)

    // Consolidated SINGLE NETWORK / ASN Node
    let asnVal: string | undefined;
    let ispVal: string | undefined;
    let cidrVal: string | undefined;
    let asnProvider: string | undefined;
    const asnEvidence: string[] = [];

    for (const obs of obsList) {
      if (obs.status === 'success' && obs.data && (obs.entity.toLowerCase() === probableRelayAddress.toLowerCase() || obs.entity_type === 'ip')) {
        const d = obs.data as Record<string, unknown>;
        const rawAsn = d.asn || d.as_number;
        if (rawAsn) {
          asnVal = String(rawAsn).trim();
          ispVal = (typeof d.isp === 'string' ? d.isp : (typeof d.organization === 'string' ? d.organization : undefined));
          cidrVal = typeof d.cidr === 'string' ? d.cidr : undefined;
          asnProvider = obs.provider || 'BGP Telemetry';
          if (obs.evidence && Array.isArray(obs.evidence)) {
            asnEvidence.push(...obs.evidence);
          }
          break;
        }
      }
    }

    if (asnVal) {
      const asnNodeId = `asn:${asnVal.toLowerCase()}`;
      const asnLabel = ispVal ? `${asnVal} (${ispVal})` : asnVal;
      nodesMap.set(asnNodeId, {
        id: asnNodeId,
        type: 'asn',
        label: asnLabel,
        primaryValue: asnVal,
        secondaryMeta: ispVal || 'BGP Autonomous System',
        severity: 'info',
        status: 'neutral',
        whyItMatters: 'BGP Autonomous System routing authority announcing network IP prefixes.',
        rankColumn: 4,
        source: asnProvider || 'BGP Routing Telemetry',
        confidence: 'high',
        properties: { asn: asnVal, isp: ispVal, cidr: cidrVal, role: 'network' },
        evidence: asnEvidence.length > 0 ? asnEvidence : [`BGP announced by ${asnVal}`],
      });

      edgesMap.set(`${sourceIpNodeId}->${asnNodeId}:announced_by`, {
        id: `${sourceIpNodeId}->${asnNodeId}:announced_by`,
        source: sourceIpNodeId,
        target: asnNodeId,
        relationship: 'announced_by',
        label: 'ANNOUNCED BY',
        isObserved: false, // DASHED EDGE FOR OSINT ENRICHMENT
        confidence: 'high',
        evidence: [`BGP routing announcement via ${asnVal}`],
      });
    }

    // Consolidated SINGLE GEOLOCATION Node
    let cityVal: string | undefined;
    let countryVal: string | undefined;
    let codeVal: string | undefined;
    let latVal: number | undefined;
    let lonVal: number | undefined;
    let geoProvider: string | undefined;
    const geoEvidence: string[] = [];

    for (const obs of obsList) {
      if (obs.status === 'success' && obs.data && (obs.entity.toLowerCase() === probableRelayAddress.toLowerCase() || obs.entity_type === 'ip')) {
        const d = obs.data as Record<string, unknown>;
        const c = typeof d.country === 'string' ? d.country : undefined;
        const cc = typeof d.country_code === 'string' ? d.country_code : undefined;
        const ct = typeof d.city === 'string' ? d.city : undefined;
        const lat = typeof d.latitude === 'number' ? d.latitude : undefined;
        const lon = typeof d.longitude === 'number' ? d.longitude : undefined;

        if (c || cc || ct || (lat !== undefined && lon !== undefined)) {
          countryVal = c;
          codeVal = cc;
          cityVal = ct;
          latVal = lat;
          lonVal = lon;
          geoProvider = obs.provider || 'IP Geolocation';
          if (obs.evidence && Array.isArray(obs.evidence)) {
            geoEvidence.push(...obs.evidence);
          }
          break;
        }
      }
    }

    if (countryVal || codeVal || cityVal || (latVal !== undefined && lonVal !== undefined)) {
      const geoKey = (codeVal || countryVal || cityVal || 'location').toLowerCase().replace(/\s+/g, '_');
      const geoNodeId = `location:${geoKey}`;
      const locString = [cityVal, countryVal || codeVal].filter(Boolean).join(', ');

      nodesMap.set(geoNodeId, {
        id: geoNodeId,
        type: 'location',
        label: locString || 'Geolocation',
        primaryValue: locString || 'Geolocation',
        secondaryMeta: (latVal !== undefined && lonVal !== undefined) ? `GPS: ${latVal}, ${lonVal}` : 'Infrastructure Location',
        severity: 'info',
        status: 'neutral',
        whyItMatters: 'Verified IP geolocation telemetry associated with origin infrastructure. Infrastructure location, not attacker physical location.',
        rankColumn: 5,
        source: geoProvider || 'IP Geolocation Telemetry',
        confidence: 'high',
        properties: { country: countryVal, country_code: codeVal, city: cityVal, latitude: latVal, longitude: lonVal, role: 'geolocation' },
        evidence: geoEvidence.length > 0 ? geoEvidence : [`IP geolocation observed: ${locString}`],
      });

      const parentForGeo = (asnVal ? `asn:${asnVal.toLowerCase()}` : sourceIpNodeId);
      edgesMap.set(`${parentForGeo}->${geoNodeId}:located_in`, {
        id: `${parentForGeo}->${geoNodeId}:located_in`,
        source: parentForGeo,
        target: geoNodeId,
        relationship: 'located_in',
        label: 'LOCATED IN',
        isObserved: false, // DASHED EDGE FOR OSINT ENRICHMENT
        confidence: 'high',
        evidence: [`Geolocation telemetry observed via ${geoProvider || 'telemetry'}`],
      });
    }
  } else {
    // --- NO VERIFIED ORIGIN INFRASTRUCTURE (COMPACT EXPLANATORY STATE NODE) ---
    const unavailStateId = 'infrastructure:unavailable';
    const rankCol = senderNodeId ? 2 : 1;
    nodesMap.set(unavailStateId, {
      id: unavailStateId,
      type: 'relay',
      label: 'NO VERIFIED ORIGIN INFRASTRUCTURE',
      primaryValue: 'No Public Source Candidate',
      secondaryMeta: 'Relay Infrastructure Unavailable',
      severity: 'info',
      status: 'unavailable',
      whyItMatters: 'No usable public IP was observed in the Received header relay chain.',
      rankColumn: rankCol,
      source: 'Relay Header Analysis',
      confidence: 'high',
      properties: {
        role: 'no_verified_infrastructure',
        reason: data.relay_analysis?.probable_source_infrastructure?.reason || 'No public external relay hop observed in headers.',
      },
      evidence: ['No usable public source IP candidate extracted from Received headers'],
    });

    const parentNodeId = senderNodeId || rootEmailId;
    edgesMap.set(`${parentNodeId}->${unavailStateId}:unavail_status`, {
      id: `${parentNodeId}->${unavailStateId}:unavail_status`,
      source: parentNodeId,
      target: unavailStateId,
      relationship: 'infrastructure_status',
      label: 'STATUS',
      isObserved: false,
      confidence: 'high',
      evidence: ['Header relay analysis completed — no public source candidate'],
    });
  }

  // Layer B: Correlated Email Relationships (Solid Edges)

  // Secondary Branch 1: Diverted Reply-To Domain Node
  const replyToDomain = data.security_analysis?.authentication_results?.reply_to_domain;
  if (replyToDomain && replyToDomain !== fromDomain) {
    const replyToId = `domain:replyto_${replyToDomain.toLowerCase()}`;
    nodesMap.set(replyToId, {
      id: replyToId,
      type: 'domain',
      label: replyToDomain,
      primaryValue: replyToDomain,
      secondaryMeta: 'Diverted Reply-To Channel',
      severity: 'medium',
      status: 'suspicious',
      whyItMatters: 'Reply-To domain differs from From domain, creating a potential response diversion vector.',
      rankColumn: 1,
      source: 'Reply-To Header',
      confidence: 'high',
      properties: { domain: replyToDomain, mismatch: true, role: 'reply_to' },
      evidence: ['Differs from RFC 5322 From domain'],
    });

    edgesMap.set(`${rootEmailId}->${replyToId}:redirects_to`, {
      id: `${rootEmailId}->${replyToId}:redirects_to`,
      source: rootEmailId,
      target: replyToId,
      relationship: 'redirects_to',
      label: 'REDIRECTS REPLIES TO',
      isObserved: true,
      confidence: 'high',
      evidence: ['Reply-To header redirection'],
    });
  }

  // Secondary Branch 2: Extracted URL Payload Node (Cap at 1 key URL for node budget)
  const extractedUrls = data.security_analysis?.url_analysis?.urls || [];
  if (extractedUrls.length > 0) {
    const targetUrlObj = extractedUrls[0];
    const urlId = `url:${targetUrlObj.url.toLowerCase()}`;
    const urlEvidence: string[] = ['Extracted message body URL'];

    if (targetUrlObj.domain && /^(\d{1,3}\.){3}\d{1,3}$/.test(targetUrlObj.domain)) {
      urlEvidence.push('Bare IP address in URL');
    }
    if (!targetUrlObj.is_https) {
      urlEvidence.push('Unencrypted HTTP transport');
    }

    const urlObs = obsList.find(
      (o) => o.entity_type === 'url' && o.entity.toLowerCase() === targetUrlObj.url.toLowerCase()
    );
    if (urlObs?.evidence && Array.isArray(urlObs.evidence)) {
      urlEvidence.push(...urlObs.evidence);
    }

    const isMalicious = (urlObs?.data?.malicious_votes as number) > 0 || urlEvidence.some((e) => e.includes('Bare IP'));

    nodesMap.set(urlId, {
      id: urlId,
      type: 'url',
      label: targetUrlObj.url,
      primaryValue: targetUrlObj.url,
      secondaryMeta: targetUrlObj.domain || 'URL Payload',
      severity: isMalicious ? 'critical' : 'info',
      status: isMalicious ? 'malicious' : 'suspicious',
      whyItMatters: 'Extracted message body hyperlink targeting external web infrastructure.',
      rankColumn: 2,
      source: targetUrlObj.source ? `Message Body (${targetUrlObj.source})` : 'Message Body HTML',
      confidence: 'high',
      properties: {
        url: targetUrlObj.url,
        is_https: targetUrlObj.is_https,
        domain: targetUrlObj.domain,
        scheme: targetUrlObj.scheme,
        path: targetUrlObj.path,
        role: 'url_payload',
        ...(urlObs?.data || {}),
      },
      evidence: urlEvidence,
    });

    edgesMap.set(`${rootEmailId}->${urlId}:contains_link`, {
      id: `${rootEmailId}->${urlId}:contains_link`,
      source: rootEmailId,
      target: urlId,
      relationship: 'contains_link',
      label: 'CONTAINS LINK',
      isObserved: true,
      confidence: 'high',
      evidence: ['Extracted message hyperlink payload'],
    });
  }

  const validEdges = Array.from(edgesMap.values()).filter(
    (edge) => nodesMap.has(edge.source) && nodesMap.has(edge.target) && edge.source !== edge.target
  );

  return {
    nodes: Array.from(nodesMap.values()),
    edges: validEdges,
    correlationsCount: data.correlations?.length || 0,
  };
}

/**
 * Normalizes investigation stage path for top breadcrumb navigation.
 * Strict Provenance: Only displays relay & IP if observed in email relay analysis.
 */
export function normalizeInvestigationPath(data: EmailAnalysisResponse): InvestigationPathStage[] {
  const path: InvestigationPathStage[] = [];

  // 1. Email Root
  path.push({
    id: 'path-email',
    category: 'EMAIL',
    label: 'EMAIL',
    value: data.subject ? (data.subject.length > 25 ? data.subject.slice(0, 22) + '...' : data.subject) : 'Email Artifact',
    status: 'available',
    detail: data.from || 'RFC 5322 Message',
  });

  // 2. Sender / Identity
  const fromDomain = data.security_analysis?.authentication_results?.from_domain;
  const isAuthFail = data.security_analysis?.authentication_results?.spf?.result === 'fail' || data.security_analysis?.authentication_results?.dmarc?.result === 'fail';
  if (fromDomain) {
    path.push({
      id: 'path-sender',
      category: 'SENDER',
      label: 'SENDER',
      value: fromDomain,
      status: isAuthFail ? 'suspicious' : 'available',
      detail: isAuthFail ? 'Auth Failure' : 'Authenticated',
    });
  } else {
    path.push({
      id: 'path-sender',
      category: 'SENDER',
      label: 'SENDER',
      value: 'Unavailable',
      status: 'unavailable',
    });
  }

  // 3. SMTP Relay
  const relayAddress = data.relay_analysis?.probable_source_infrastructure?.address;
  if (relayAddress) {
    path.push({
      id: 'path-relay',
      category: 'RELAY',
      label: 'RELAY',
      value: relayAddress,
      status: 'available',
      detail: 'Received Hop',
    });
  } else {
    path.push({
      id: 'path-relay',
      category: 'RELAY',
      label: 'RELAY',
      value: 'Unavailable',
      status: 'unavailable',
    });
  }

  // 4. Source IP
  if (relayAddress) {
    const matchingObs = data.threat_intelligence?.observations?.find(
      (o) => o.entity_type === 'ip' && o.entity.toLowerCase() === relayAddress.toLowerCase()
    );
    const score = ((matchingObs?.data as Record<string, unknown>)?.abuse_confidence_score as number) || 0;
    path.push({
      id: 'path-ip',
      category: 'SOURCE_IP',
      label: 'SOURCE IP',
      value: relayAddress,
      status: score > 50 ? 'malicious' : 'available',
      detail: score > 0 ? `Abuse ${score}%` : 'Public IP',
    });
  } else {
    path.push({
      id: 'path-ip',
      category: 'SOURCE_IP',
      label: 'SOURCE IP',
      value: 'Unavailable',
      status: 'unavailable',
    });
  }

  // 5. Network / ASN (Only if associated with observed relayAddress)
  let asnVal: string | undefined;
  if (relayAddress && data.threat_intelligence?.observations) {
    for (const o of data.threat_intelligence.observations) {
      if (o.status === 'success' && o.data && (o.entity.toLowerCase() === relayAddress.toLowerCase() || o.entity_type === 'ip')) {
        const asn = (o.data as Record<string, unknown>).asn || (o.data as Record<string, unknown>).as_number;
        if (asn) {
          asnVal = String(asn);
          break;
        }
      }
    }
  }
  if (asnVal) {
    path.push({
      id: 'path-network',
      category: 'NETWORK',
      label: 'NETWORK',
      value: asnVal,
      status: 'available',
      detail: 'BGP Route',
    });
  } else {
    path.push({
      id: 'path-network',
      category: 'NETWORK',
      label: 'NETWORK',
      value: 'Unavailable',
      status: 'unavailable',
    });
  }

  // 6. Geolocation (Only if associated with observed relayAddress)
  let geoVal: string | undefined;
  if (relayAddress && data.threat_intelligence?.observations) {
    for (const o of data.threat_intelligence.observations) {
      if (o.status === 'success' && o.data && (o.entity.toLowerCase() === relayAddress.toLowerCase() || o.entity_type === 'ip')) {
        const d = o.data as Record<string, unknown>;
        const country = typeof d.country === 'string' ? d.country : undefined;
        const code = typeof d.country_code === 'string' ? d.country_code : undefined;
        const city = typeof d.city === 'string' ? d.city : undefined;
        if (country || code || city) {
          geoVal = [city, country].filter(Boolean).join(', ') || code;
          break;
        }
      }
    }
  }
  if (geoVal) {
    path.push({
      id: 'path-location',
      category: 'GEOLOCATION',
      label: 'GEOLOCATION',
      value: geoVal,
      status: 'available',
      detail: 'Verified GPS',
    });
  } else {
    path.push({
      id: 'path-location',
      category: 'GEOLOCATION',
      label: 'GEOLOCATION',
      value: 'Unavailable',
      status: 'unavailable',
    });
  }

  return path;
}

/**
 * Dynamically synthesizes evidence-backed rationale points for "Why This Matters".
 * Strictly distinguishes observed email evidence from external enrichment.
 */
export function generateWhyThisMatters(data: EmailAnalysisResponse): string[] {
  const points: string[] = [];

  const relayAddress = data.relay_analysis?.probable_source_infrastructure?.address;
  if (relayAddress) {
    points.push(`The Received header identifies ${relayAddress} as the strongest observed public infrastructure candidate in the relay chain.`);
  } else {
    points.push(`No public source IP was observed in the Received header relay chain (ingress infrastructure unavailable).`);
  }

  const fromDomain = data.security_analysis?.authentication_results?.from_domain;
  const replyToDomain = data.security_analysis?.authentication_results?.reply_to_domain;
  if (replyToDomain && fromDomain && replyToDomain !== fromDomain) {
    points.push(`The Reply-To domain (${replyToDomain}) differs from the envelope sender (${fromDomain}), introducing a potential response diversion vector.`);
  } else if (fromDomain) {
    points.push(`Primary sender domain identified as ${fromDomain}.`);
  }

  const extractedUrls = data.security_analysis?.url_analysis?.urls || [];
  if (extractedUrls.length > 0) {
    const unencrypted = extractedUrls.filter(u => !u.is_https);
    if (unencrypted.length > 0) {
      points.push(`Message body contains ${unencrypted.length} unencrypted HTTP hyperlink payload(s).`);
    } else {
      points.push(`Message body contains ${extractedUrls.length} extracted hyperlink target(s).`);
    }
  }

  if (relayAddress && data.threat_intelligence?.observations) {
    const verifiedGeo = data.threat_intelligence.observations.find(
      (o) => o.status === 'success' && o.data && (o.entity.toLowerCase() === relayAddress.toLowerCase() || o.entity_type === 'ip') && isValidCoordinate((o.data as Record<string, unknown>).latitude, (o.data as Record<string, unknown>).longitude)
    );
    if (verifiedGeo) {
      const d = verifiedGeo.data as Record<string, unknown>;
      const locStr = [d.city, d.country].filter(Boolean).join(', ') || d.country_code || 'coordinates';
      points.push(`External threat intelligence telemetry links the origin ingress IP (${relayAddress}) to verified geographic location (${locStr}). Threat intelligence identifies this address as known infrastructure. This does not establish attacker ownership or physical origin.`);
    }
  }

  points.push(`Attribution Model: Infrastructure origin only. Geolocation and BGP routing reflect hosting infrastructure, not verified physical threat actor identity.`);

  return points;
}

/**
 * Helper to determine if an IP address is private, loopback, link-local,
 * multicast, unspecified, documentation (TEST-NET), or reserved.
 */
export function isPrivateOrReservedIP(ip: string): boolean {
  if (!ip || typeof ip !== 'string') return true;
  const trimmed = ip.trim();

  // IPv6 check
  if (trimmed.includes(':')) {
    const lower = trimmed.toLowerCase();
    if (lower === '::' || lower === '::1') return true;
    if (lower.startsWith('fe80:')) return true; // Link-local
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // Unique local
    if (lower.startsWith('2001:db8:')) return true; // Documentation
    if (lower.startsWith('ff')) return true; // Multicast
    return false;
  }

  // IPv4 check
  const parts = trimmed.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
    return true; // Malformed / non-IP
  }

  const [a, b, c] = parts;

  // 0.0.0.0/8 (Current network)
  if (a === 0) return true;
  // 10.0.0.0/8 (RFC 1918 Private)
  if (a === 10) return true;
  // 100.64.0.0/10 (Shared Address Space / CGNAT)
  if (a === 100 && b >= 64 && b <= 127) return true;
  // 127.0.0.0/8 (Loopback)
  if (a === 127) return true;
  // 169.254.0.0/16 (Link-local)
  if (a === 169 && b === 254) return true;
  // 172.16.0.0/12 (RFC 1918 Private)
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.0.0.0/24 (IETF Protocol Assignments)
  if (a === 192 && b === 0 && c === 0) return true;
  // 192.0.2.0/24 (TEST-NET-1 Documentation)
  if (a === 192 && b === 0 && c === 2) return true;
  // 192.168.0.0/16 (RFC 1918 Private)
  if (a === 192 && b === 168) return true;
  // 198.18.0.0/15 (Benchmarking)
  if (a === 198 && (b === 18 || b === 19)) return true;
  // 198.51.100.0/24 (TEST-NET-2 Documentation)
  if (a === 198 && b === 51 && c === 100) return true;
  // 203.0.113.0/24 (TEST-NET-3 Documentation)
  if (a === 203 && b === 0 && c === 113) return true;
  // 224.0.0.0/4 (Multicast: 224-239)
  if (a >= 224 && a <= 239) return true;
  // 240.0.0.0/4 (Reserved for future use: 240-255)
  if (a >= 240) return true;

  return false;
}

/**
 * Validates that latitude and longitude are finite numbers within valid geographic ranges.
 */
export function isValidCoordinate(latitude: unknown, longitude: unknown): boolean {
  if (typeof latitude !== 'number' || typeof longitude !== 'number') return false;
  if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) return false;
  if (latitude < -90 || latitude > 90) return false;
  if (longitude < -180 || longitude > 180) return false;
  return true;
}

/**
 * Normalizes verified geolocation for the map visualization.
 * Returns null if no valid coordinates are available or if evidence is missing.
 * Strict Forensic Rule: NEVER manufactures fallback IP, coordinates, or location names.
 */
export function normalizeMapLocation(data: EmailAnalysisResponse): NormalizedMapLocation | null {
  // 1. Identify target IP address
  let targetIP = data.relay_analysis?.probable_source_infrastructure?.address || null;

  // If no probable source address from relay_analysis, check if a verified geolocation
  // observation explicitly identifies an IP with valid coordinates
  if (!targetIP) {
    const geoObs = data.threat_intelligence?.observations?.find(
      (obs) =>
        obs.status === 'success' &&
        obs.entity_type === 'ip' &&
        obs.entity &&
        isValidCoordinate(obs.data?.latitude, obs.data?.longitude)
    );
    if (geoObs) {
      targetIP = geoObs.entity;
    }
  }

  // If missing/null: DO NOT substitute 198.51.100.10. Return null.
  if (!targetIP) {
    return null;
  }

  // 2. Search for verified coordinates and geolocation telemetry in observations
  let lat: number | null = null;
  let lon: number | null = null;
  let country: string | undefined = undefined;
  let countryCode: string | undefined = undefined;
  let region: string | undefined = undefined;
  let city: string | undefined = undefined;
  let asn: string | undefined = undefined;
  let organization: string | undefined = undefined;
  let abuseScore: number | undefined = undefined;
  let confidence: Confidence = 'high';
  let source = 'Verified Geolocation Telemetry';
  let isExplicitlyVerifiedGeo = false;

  const obsList = data.threat_intelligence?.observations || [];
  for (const obs of obsList) {
    if (
      obs.status === 'success' &&
      obs.entity_type === 'ip' &&
      obs.entity.toLowerCase() === targetIP.toLowerCase() &&
      obs.data
    ) {
      const d = obs.data as Record<string, unknown>;
      if (isValidCoordinate(d.latitude, d.longitude)) {
        lat = d.latitude as number;
        lon = d.longitude as number;
        if (obs.kind === 'geolocation' || d.geo_verified === true || d.eligible === true) {
          isExplicitlyVerifiedGeo = true;
        }
        if (obs.provider) {
          source = `${obs.provider} Geolocation Telemetry`;
        }
        if (obs.confidence && obs.confidence !== 'none') {
          confidence = obs.confidence;
        }
      }
      if (typeof d.country === 'string' && d.country) country = d.country;
      if (typeof d.country_code === 'string' && d.country_code) countryCode = d.country_code;
      if (typeof d.city === 'string' && d.city) city = d.city;
      if (typeof d.region === 'string' && d.region) region = d.region;
      if (typeof d.asn === 'string' && d.asn) asn = d.asn;
      if (typeof d.isp === 'string' && d.isp) organization = d.isp;
      else if (typeof d.organization === 'string' && d.organization) organization = d.organization;
      if (typeof d.abuse_confidence_score === 'number') abuseScore = d.abuse_confidence_score;
      else if (typeof d.abuse_score === 'number') abuseScore = d.abuse_score;
    }
  }

  // 3. If coordinates not found in observations, inspect evidence graph nodes
  if (lat === null || lon === null) {
    const graphNodes = data.evidence_graph?.nodes || [];
    for (const node of graphNodes) {
      if (
        (node.type === 'location' || node.type === 'ip') &&
        (node.id.toLowerCase() === `ip:${targetIP.toLowerCase()}` ||
          node.value.toLowerCase() === targetIP.toLowerCase() ||
          node.type === 'location')
      ) {
        if (isValidCoordinate(node.properties?.latitude, node.properties?.longitude)) {
          lat = node.properties.latitude as number;
          lon = node.properties.longitude as number;
          isExplicitlyVerifiedGeo = true;
          if (typeof node.properties?.country === 'string') country = node.properties.country;
          if (typeof node.properties?.country_code === 'string') countryCode = node.properties.country_code;
          if (typeof node.properties?.city === 'string') city = node.properties.city;
          if (typeof node.properties?.region === 'string') region = node.properties.region;
          if (node.sources && node.sources.length > 0) source = node.sources.join(', ');
          break;
        }
      }
    }
  }

  // 4. Strict Coordinate Validation: Reject missing, NaN, Infinity, or out-of-range coordinates
  if (lat === null || lon === null || !isValidCoordinate(lat, lon)) {
    return null;
  }

  // 5. Private / Reserved / Documentation IP check:
  // Do not display physical geolocation for private/reserved/documentation IPs unless explicitly verified
  if (isPrivateOrReservedIP(targetIP) && !isExplicitlyVerifiedGeo) {
    return null;
  }

  return {
    ip: targetIP,
    latitude: lat,
    longitude: lon,
    country: country || (countryCode ? countryCode : 'Unknown Location'),
    countryCode,
    region,
    city,
    asn,
    organization,
    confidence,
    source,
    abuseScore,
  };
}

/**
 * Strict validation and parsing of authentic backend forensic timestamps.
 * Rejects null, undefined, synthetic offsets ("T+..."), malformed strings, and non-dates.
 * Returns the exact unchanged timestamp string and its numeric epoch ms for sorting, or null.
 */
export function parseValidTimestamp(raw: unknown): { raw: string; ms: number } | null {
  if (raw === null || raw === undefined) return null;
  if (typeof raw !== 'string' && typeof raw !== 'number') return null;

  if (typeof raw === 'string') {
    const trimmed = raw.trim();
    if (!trimmed) return null;

    // Reject synthetic relative offsets like T+00:00, T+00:15, T+0s, etc.
    if (/^T[+-]/i.test(trimmed)) return null;

    // Reject non-date literal placeholders
    const lower = trimmed.toLowerCase();
    if (
      lower === 'not-a-date' ||
      lower === 'null' ||
      lower === 'undefined' ||
      lower === 'invalid date' ||
      lower === 'none'
    ) {
      return null;
    }

    const parsedMs = Date.parse(trimmed);
    if (Number.isNaN(parsedMs) || !Number.isFinite(parsedMs)) {
      return null;
    }

    // Epoch sanity check: reject dates before 1970 or past year 2100 (4102444800000 ms)
    if (parsedMs < 0 || parsedMs > 4102444800000) {
      return null;
    }

    return { raw: trimmed, ms: parsedMs };
  }

  if (typeof raw === 'number') {
    if (Number.isNaN(raw) || !Number.isFinite(raw)) return null;
    let ms = raw;
    // Seconds unix epoch
    if (raw > 0 && raw < 10000000000) {
      ms = raw * 1000;
    }
    if (ms < 0 || ms > 4102444800000) return null;
    return { raw: new Date(ms).toISOString(), ms };
  }

  return null;
}

/**
 * Extracts a verified timestamp from a RelayHop, prioritizing explicit timestamp properties
 * or parsing the standard RFC 5322 date-time following the last ';' in original_header.
 */
export function extractHopTimestamp(
  hop: RelayHop,
  receivedHeaders?: string[]
): { raw: string; ms: number } | null {
  if (!hop) return null;

  // 1. Check direct timestamp properties if present on the hop
  const anyHop = hop as unknown as Record<string, unknown>;
  if (anyHop.timestamp) {
    const parsed = parseValidTimestamp(anyHop.timestamp);
    if (parsed) return parsed;
  }
  if (anyHop.datetime) {
    const parsed = parseValidTimestamp(anyHop.datetime);
    if (parsed) return parsed;
  }
  if (anyHop.date) {
    const parsed = parseValidTimestamp(anyHop.date);
    if (parsed) return parsed;
  }

  // 2. Parse from original Received header after the last ';' delimiter
  if (typeof hop.original_header === 'string') {
    const lastSemicolon = hop.original_header.lastIndexOf(';');
    if (lastSemicolon !== -1) {
      const candidate = hop.original_header.slice(lastSemicolon + 1).trim();
      const parsed = parseValidTimestamp(candidate);
      if (parsed) return parsed;
    }
  }

  // 3. Fallback: match against raw Received headers array by hop IP or hostname
  if (Array.isArray(receivedHeaders) && receivedHeaders.length > 0) {
    const hopIp = hop.extracted_ips?.[0]?.address;
    const hopHost = hop.hostnames?.[0];
    const match = receivedHeaders.find((h) => {
      if (typeof h !== 'string' || !h.includes(';')) return false;
      if (hopIp && h.includes(hopIp)) return true;
      if (hopHost && h.includes(hopHost)) return true;
      return false;
    });

    if (match) {
      const lastSemicolon = match.lastIndexOf(';');
      if (lastSemicolon !== -1) {
        const candidate = match.slice(lastSemicolon + 1).trim();
        const parsed = parseValidTimestamp(candidate);
        if (parsed) return parsed;
      }
    }
  }

  return null;
}

interface RawTimelineCandidate {
  id: string;
  timestampMs: number;
  timeOffset: string;
  category: TimelineEventCategory;
  categoryLabel: string;
  title: string;
  description: string;
  source: string;
  state: TimelineEventState;
  evidence: string[];
  relatedEntityId?: string;
  hasLocation?: boolean;
}

/**
 * Normalizes authentic chronological forensic events for the evidence timeline.
 * Strict Forensic Rule: Timeline events may ONLY originate from trustworthy backend data.
 * Missing timestamps remain missing; no synthetic offsets or filler events are created.
 */
export function normalizeTimelineEvents(data: EmailAnalysisResponse): NormalizedTimelineEvent[] {
  if (!data) return [];

  const rawEvents: RawTimelineCandidate[] = [];

  // 1. Initial Ingestion / Email Date Header
  const emailDate = parseValidTimestamp(data.date ?? (data as unknown as Record<string, unknown>)?.timestamp);
  if (emailDate) {
    rawEvents.push({
      id: 'evt-ingest',
      timestampMs: emailDate.ms,
      timeOffset: emailDate.raw,
      category: 'INGESTION',
      categoryLabel: 'EMAIL DATE RECORDED',
      title: 'MIME RFC 5322 Artifact Registered',
      description: `Message registered with Subject: "${data.subject || 'None'}". Message-ID recorded.`,
      source: 'Email Date Header',
      state: 'informational',
      evidence: [
        `date=${emailDate.raw}`,
        ...(data.from ? [`from=${data.from}`] : []),
        ...(data.to ? [`to=${data.to}`] : []),
        ...(data.message_id ? [`message_id=${data.message_id}`] : []),
      ],
      relatedEntityId: 'email:root',
    });
  }

  // 2. Relay Hops (Only hops with verified timestamps)
  const hops = data.relay_analysis?.relay_hops || [];
  for (const hop of hops) {
    const hopTime = extractHopTimestamp(hop, data.received);
    if (!hopTime) continue;

    const isProbable = data.relay_analysis?.probable_source_infrastructure?.address
      ? hop.extracted_ips.some(
          (ip) => ip.address === data.relay_analysis?.probable_source_infrastructure?.address
        )
      : false;

    const hopIp = hop.extracted_ips?.[0]?.address;

    rawEvents.push({
      id: `evt-hop-${hop.hop_number}`,
      timestampMs: hopTime.ms,
      timeOffset: hopTime.raw,
      category: 'RELAY_HOP',
      categoryLabel: isProbable ? 'CRITICAL RELAY INGRESS' : 'RELAY TRANSIT HOP',
      title: `Hop #${hop.hop_number}: ${hop.hostnames.length > 0 ? hop.hostnames.join(' → ') : (hopIp || 'Direct peer')}`,
      description: isProbable && hopIp
        ? `External relay hop (${hopIp}) identified before internal MX perimeter.`
        : `ESMTP transfer recorded between intermediate mail transfer agents.`,
      source: 'Received Header Timestamp',
      state: isProbable ? 'critical' : 'informational',
      evidence: [
        `received_time=${hopTime.raw}`,
        ...hop.extracted_ips.map((ip) => `ip=${ip.address}`),
      ],
      relatedEntityId: hopIp ? `ip:${hopIp}` : undefined,
      hasLocation: isProbable && !isPrivateOrReservedIP(hopIp || ''),
    });
  }

  // 3. RFC 8601 Authentication (Only if explicitly timestamped)
  const auth = data.security_analysis?.authentication_results;
  if (auth) {
    const anyAuth = auth as unknown as Record<string, unknown>;
    const authTime = parseValidTimestamp(anyAuth.timestamp ?? anyAuth.evaluated_at ?? anyAuth.date);
    if (authTime) {
      const isAuthFail = auth.spf?.result === 'fail' || auth.dmarc?.result === 'fail';
      rawEvents.push({
        id: 'evt-auth',
        timestampMs: authTime.ms,
        timeOffset: authTime.raw,
        category: 'AUTHENTICATION',
        categoryLabel: 'RFC 8601 EVALUATION',
        title: `SPF: ${auth.spf?.result?.toUpperCase() || 'FAIL'} • DKIM: ${auth.dkim?.result?.toUpperCase() || 'NONE'} • DMARC: ${auth.dmarc?.result?.toUpperCase() || 'FAIL'}`,
        description: 'Strict cryptographic authentication evaluation against sender From header.',
        source: auth.authserv_ids?.[0] ? `Authserv ID: ${auth.authserv_ids[0]}` : 'Authentication Results',
        state: isAuthFail ? 'critical' : 'verified',
        evidence: [
          `evaluated_at=${authTime.raw}`,
          `spf=${auth.spf?.result || 'none'}`,
          `dkim=${auth.dkim?.result || 'none'}`,
          `dmarc=${auth.dmarc?.result || 'none'}`,
        ],
        relatedEntityId: auth.from_domain ? `domain:${auth.from_domain}` : undefined,
      });
    }
  }

  // 4. URL Discovery (Only if explicitly timestamped)
  const urls = data.security_analysis?.url_analysis?.urls || [];
  for (const u of urls) {
    const anyUrl = u as unknown as Record<string, unknown>;
    const urlTime = parseValidTimestamp(anyUrl.timestamp ?? anyUrl.extracted_at);
    if (urlTime) {
      rawEvents.push({
        id: `evt-url-${u.domain || u.url}`,
        timestampMs: urlTime.ms,
        timeOffset: urlTime.raw,
        category: 'URL_DISCOVERY',
        categoryLabel: 'PAYLOAD EXTRACTED',
        title: `Suspicious URL Target: ${u.url}`,
        description: 'Extracted direct bare IP or URL payload from message body.',
        source: 'Message Body Analysis',
        state: 'critical',
        evidence: [`extracted_at=${urlTime.raw}`, `url=${u.url}`, `scheme=${u.scheme}`],
        relatedEntityId: `url:${u.url}`,
      });
    }
  }

  // 5. Threat Intelligence Feeds (Only observations with verified retrieved_at/timestamp)
  const obsList = data.threat_intelligence?.observations || [];
  for (const obs of obsList) {
    const anyObs = obs as unknown as Record<string, unknown>;
    const anyData = obs.data as unknown as Record<string, unknown> | undefined;
    const obsTime = parseValidTimestamp(obs.retrieved_at ?? anyData?.retrieved_at ?? anyObs.timestamp);
    if (obsTime) {
      const isBad = ((obs.data?.abuse_confidence_score as number) ?? 0) > 50 || obs.kind === 'malware_url';
      rawEvents.push({
        id: `evt-intel-${obs.provider}-${obs.entity}`,
        timestampMs: obsTime.ms,
        timeOffset: obsTime.raw,
        category: 'INTELLIGENCE',
        categoryLabel: 'TELEMETRY FEED',
        title: `${obs.provider} // ${obs.kind.toUpperCase()} (${obs.entity})`,
        description: obs.evidence && obs.evidence.length > 0 ? obs.evidence.join(' • ') : 'Threat intelligence observation recorded.',
        source: obs.provider || 'Threat Intelligence',
        state: isBad ? 'warning' : 'informational',
        evidence: [
          `retrieved_at=${obsTime.raw}`,
          ...(obs.evidence || []),
        ],
        relatedEntityId: obs.entity_type === 'ip' ? `ip:${obs.entity}` : `url:${obs.entity}`,
        hasLocation: obs.entity_type === 'ip' && !isPrivateOrReservedIP(obs.entity),
      });
    }
  }

  // 6. Autonomous AI Agent Tool Executions (Only if actual execution timestamps exist)
  const aiTools = data.ai_investigation?.tool_calls || [];
  for (const tool of aiTools) {
    const anyTool = tool as unknown as Record<string, unknown>;
    const toolTime = parseValidTimestamp(anyTool.timestamp ?? anyTool.executed_at ?? anyTool.time);
    if (toolTime) {
      rawEvents.push({
        id: `evt-tool-${tool.name}-${toolTime.ms}`,
        timestampMs: toolTime.ms,
        timeOffset: toolTime.raw,
        category: 'AI_TOOL_EXECUTION',
        categoryLabel: 'AUTONOMOUS TOOL LOOP',
        title: `Agent Tool Call: ${tool.name}()`,
        description: tool.result_summary || `Tool execution recorded for observable target.`,
        source: tool.iteration ? `Groq AI Agent (Iteration ${tool.iteration})` : 'Groq Autonomous AI Forensic Agent',
        state: 'warning',
        evidence: [
          `executed_at=${toolTime.raw}`,
          `tool=${tool.name}`,
          ...(tool.target ? [`target=${tool.target}`] : []),
          `status=${tool.status}`,
        ],
        relatedEntityId: tool.target ? (tool.target.startsWith('http') ? `url:${tool.target}` : `domain:${tool.target}`) : undefined,
      });
    }
  }

  // 7. Cross-Signal Correlation (Only if explicitly timestamped)
  const correlations = data.correlations || [];
  for (const c of correlations) {
    const anyC = c as unknown as Record<string, unknown>;
    const corrTime = parseValidTimestamp(anyC.timestamp ?? anyC.correlated_at);
    if (corrTime) {
      rawEvents.push({
        id: `evt-corr-${c.code}`,
        timestampMs: corrTime.ms,
        timeOffset: corrTime.raw,
        category: 'CORRELATION',
        categoryLabel: 'CROSS-SIGNAL CORRELATION',
        title: c.relationship.replace(/_/g, ' ').toUpperCase(),
        description: c.explanation,
        source: 'Deterministic Correlation Engine',
        state: 'critical',
        evidence: [`timestamp=${corrTime.raw}`, ...c.evidence],
        relatedEntityId: c.entities[0] ? (c.entities[0].includes('.') ? `ip:${c.entities[0]}` : `domain:${c.entities[0]}`) : undefined,
      });
    }
  }

  // 8. Final Threat Assessment (Only if explicitly timestamped)
  const risk = data.risk_assessment;
  if (risk) {
    const anyRisk = risk as unknown as Record<string, unknown>;
    const riskTime = parseValidTimestamp(anyRisk.timestamp ?? anyRisk.calculated_at ?? anyRisk.assessed_at);
    if (riskTime) {
      rawEvents.push({
        id: 'evt-assessment',
        timestampMs: riskTime.ms,
        timeOffset: riskTime.raw,
        category: 'ASSESSMENT',
        categoryLabel: 'INCIDENT TRIAGE COMPLETE',
        title: `Risk Score: ${risk.score}/100 • Classification: ${risk.classification.toUpperCase()}`,
        description: risk.rationale,
        source: 'Forensic Scoring & Triage Engine',
        state: risk.score > 75 ? 'critical' : 'warning',
        evidence: [`assessed_at=${riskTime.raw}`, ...risk.factors.map((f) => `${f.code} (+${f.contribution} pts)`)],
      });
    }
  }

  // Preserve chronology: Sort ascending by authentic timestamp epoch ms
  rawEvents.sort((a, b) => a.timestampMs - b.timestampMs);

  // Map to NormalizedTimelineEvent with 1-based sequential steps and exact unchanged timestamps
  return rawEvents.map((event, index) => ({
    id: event.id,
    step: index + 1,
    timeOffset: event.timeOffset,
    category: event.category,
    categoryLabel: event.categoryLabel,
    title: event.title,
    description: event.description,
    source: event.source,
    state: event.state,
    evidence: event.evidence,
    relatedEntityId: event.relatedEntityId,
    hasLocation: event.hasLocation,
  }));
}
