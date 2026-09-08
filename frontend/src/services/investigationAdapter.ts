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
  | 'provider';

export interface NormalizedGraphNode {
  id: string;
  type: ForensicNodeType;
  label: string;
  primaryValue: string;
  secondaryMeta?: string;
  severity: IndicatorSeverity;
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
  confidence: Confidence;
  evidence: string[];
}

export interface NormalizedGraphData {
  nodes: NormalizedGraphNode[];
  edges: NormalizedGraphEdge[];
  correlationsCount: number;
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
 */
export function normalizeGraphData(data: EmailAnalysisResponse): NormalizedGraphData {
  const nodesMap = new Map<string, NormalizedGraphNode>();
  const edgesMap = new Map<string, NormalizedGraphEdge>();

  // 1. Process from evidence_graph if present
  if (data.evidence_graph && data.evidence_graph.nodes && data.evidence_graph.nodes.length > 0) {
    for (const n of data.evidence_graph.nodes) {
      let nodeType: ForensicNodeType = 'domain';
      if (n.type === 'email') nodeType = 'email';
      else if (n.type === 'ip') nodeType = 'ip';
      else if (n.type === 'url') nodeType = 'url';
      else if (n.type === 'asn') nodeType = 'asn';
      else if (n.type === 'location' || n.type === 'country' || n.type === 'city') nodeType = 'location';
      else if (n.type === 'identity') nodeType = 'identity';
      else if (n.type === 'provider') nodeType = 'provider';

      let severity: IndicatorSeverity = 'info';
      if (nodeType === 'url') severity = 'critical';
      else if (nodeType === 'ip' && (n.properties?.abuse_score as number) > 50) severity = 'critical';
      else if (nodeType === 'domain' && n.properties?.mismatch) severity = 'medium';
      else if (nodeType === 'domain' && (n.properties?.age_days as number) <= 7) severity = 'high';

      nodesMap.set(n.id, {
        id: n.id,
        type: nodeType,
        label: n.value,
        primaryValue: n.value,
        secondaryMeta: n.properties?.probable_source
          ? 'Probable Origin Relay'
          : n.properties?.target_type
          ? String(n.properties.target_type)
          : undefined,
        severity,
        source: n.sources.join(', ') || 'Evidence Graph',
        confidence: 'high',
        properties: n.properties || {},
      });
    }

    for (const e of data.evidence_graph.edges) {
      const edgeId = `${e.source}->${e.target}:${e.relationship}`;
      edgesMap.set(edgeId, {
        id: edgeId,
        source: e.source,
        target: e.target,
        relationship: e.relationship,
        label: e.relationship.replace(/_/g, ' ').toUpperCase(),
        confidence: e.confidence || 'high',
        evidence: e.evidence || [],
      });
    }
  }

  // 2. Ensure Essential Forensic Hub Nodes Exist
  // Root Email Node
  let rootEmailId = 'email:root';
  for (const [id, node] of nodesMap.entries()) {
    if (node.type === 'email') {
      rootEmailId = id;
      break;
    }
  }
  if (!nodesMap.has(rootEmailId)) {
    nodesMap.set(rootEmailId, {
      id: rootEmailId,
      type: 'email',
      label: data.message_id ? data.message_id.replace(/[<>]/g, '') : 'Root Email Artifact',
      primaryValue: data.subject || 'Email Subject',
      secondaryMeta: data.from || undefined,
      severity: 'info',
      source: 'RFC 5322 Headers',
      confidence: 'high',
      properties: {
        from: data.from,
        to: data.to,
        date: data.date,
        message_id: data.message_id,
      },
    });
  } else {
    const existingEmail = nodesMap.get(rootEmailId)!;
    if (existingEmail.primaryValue === 'message' && data.subject) {
      existingEmail.primaryValue = data.subject;
      existingEmail.label = data.subject;
    }
    if (!existingEmail.secondaryMeta && data.from) {
      existingEmail.secondaryMeta = data.from;
    }
  }

  // Probable Relay IP Node
  const relayAddress = data.relay_analysis?.probable_source_infrastructure?.address;
  if (relayAddress) {
    const directIpId = `ip:${relayAddress.toLowerCase()}`;
    let targetIpId: string | undefined;
    for (const [id, node] of nodesMap.entries()) {
      if (node.type === 'ip' && (id.toLowerCase() === directIpId || node.primaryValue === relayAddress)) {
        targetIpId = id;
        break;
      }
    }

    if (!targetIpId) {
      targetIpId = directIpId;
      const matchingObs = data.threat_intelligence?.observations?.find(
        (o) => o.entity_type === 'ip' && o.entity.toLowerCase() === relayAddress.toLowerCase()
      );
      const obsData = (matchingObs?.data || {}) as Record<string, unknown>;
      const ipProperties: Record<string, unknown> = {
        address: relayAddress,
      };
      if (data.relay_analysis?.probable_source_infrastructure?.reason) {
        ipProperties.selection_reason = data.relay_analysis.probable_source_infrastructure.reason;
      }
      if (typeof obsData.abuse_confidence_score === 'number') {
        ipProperties.abuse_score = obsData.abuse_confidence_score;
      } else if (typeof obsData.abuse_score === 'number') {
        ipProperties.abuse_score = obsData.abuse_score;
      }
      if (typeof obsData.country === 'string') {
        ipProperties.country = obsData.country;
      }
      if (typeof obsData.asn === 'string') {
        ipProperties.asn = obsData.asn;
      }
      if (typeof obsData.reverse_dns === 'string') {
        ipProperties.reverse_dns = obsData.reverse_dns;
      }

      const ipEvidence: string[] = [];
      if (data.relay_analysis?.probable_source_infrastructure?.reason) {
        ipEvidence.push(data.relay_analysis.probable_source_infrastructure.reason);
      }
      if (matchingObs?.evidence && Array.isArray(matchingObs.evidence)) {
        ipEvidence.push(...matchingObs.evidence);
      }

      const abuseScoreNum = typeof ipProperties.abuse_score === 'number' ? ipProperties.abuse_score : 0;

      nodesMap.set(targetIpId, {
        id: targetIpId,
        type: 'ip',
        label: relayAddress,
        primaryValue: relayAddress,
        secondaryMeta: 'Origin Ingress Relay',
        severity: abuseScoreNum > 50 ? 'critical' : 'info',
        source: matchingObs?.provider ? `Received Ingress / ${matchingObs.provider}` : 'Received Header Ingress',
        confidence: 'high',
        properties: ipProperties,
        evidence: ipEvidence.length > 0 ? ipEvidence : ['Perimeter ingress relay hop'],
      });
    }

    // Edge: Root Email -> Relay IP
    const relayEdgeId = `${rootEmailId}->${targetIpId}:delivered_via`;
    if (!edgesMap.has(relayEdgeId)) {
      edgesMap.set(relayEdgeId, {
        id: relayEdgeId,
        source: rootEmailId,
        target: targetIpId,
        relationship: 'delivered_via',
        label: 'DELIVERED VIA',
        confidence: 'high',
        evidence: ['Received header ingress route'],
      });
    }
  }

  // Sender Domain Node
  const fromDomain = data.security_analysis?.authentication_results?.from_domain;
  if (fromDomain) {
    const directDomainId = `domain:${fromDomain.toLowerCase()}`;
    let targetDomainId: string | undefined;
    for (const [id, node] of nodesMap.entries()) {
      if (node.type === 'domain' && (id.toLowerCase() === directDomainId || node.primaryValue.toLowerCase() === fromDomain.toLowerCase())) {
        targetDomainId = id;
        break;
      }
    }

    if (!targetDomainId) {
      targetDomainId = directDomainId;
      const auth = data.security_analysis?.authentication_results;
      const domainProperties: Record<string, unknown> = {
        domain: fromDomain,
      };
      const domainEvidence: string[] = [];
      if (auth?.spf?.result) {
        domainProperties.spf = auth.spf.result;
        domainEvidence.push(`SPF ${auth.spf.result}`);
      }
      if (auth?.dkim?.result) {
        domainProperties.dkim = auth.dkim.result;
        domainEvidence.push(`DKIM ${auth.dkim.result}`);
      }
      if (auth?.dmarc?.result) {
        domainProperties.dmarc = auth.dmarc.result;
        domainEvidence.push(`DMARC ${auth.dmarc.result}`);
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

      const isAuthFail = auth?.spf?.result === 'fail' || auth?.dmarc?.result === 'fail';

      nodesMap.set(targetDomainId, {
        id: targetDomainId,
        type: 'domain',
        label: fromDomain,
        primaryValue: fromDomain,
        secondaryMeta: domainProperties.age_days !== undefined
          ? `From Header Domain (Age: ${domainProperties.age_days}d)`
          : 'From Header Domain',
        severity: isAuthFail ? 'high' : 'info',
        source: 'RFC 5322 From',
        confidence: 'high',
        properties: domainProperties,
        evidence: domainEvidence.length > 0 ? domainEvidence : ['RFC 5322 From header domain'],
      });
    }

    // Edge: Root Email -> Sender Domain
    const domainEdgeId = `${rootEmailId}->${targetDomainId}:sent_from`;
    if (!edgesMap.has(domainEdgeId)) {
      edgesMap.set(domainEdgeId, {
        id: domainEdgeId,
        source: rootEmailId,
        target: targetDomainId,
        relationship: 'sent_from',
        label: 'SENT FROM',
        confidence: 'high',
        evidence: ['RFC 5322 From header match'],
      });
    }
  }

  // Embedded URL Payload Nodes
  const extractedUrls = data.security_analysis?.url_analysis?.urls || [];
  for (const urlObj of extractedUrls) {
    const directUrlId = `url:${urlObj.url.toLowerCase()}`;
    let targetUrlId: string | undefined;
    for (const [id, node] of nodesMap.entries()) {
      if (node.type === 'url' && (id.toLowerCase() === directUrlId || node.primaryValue.toLowerCase() === urlObj.url.toLowerCase())) {
        targetUrlId = id;
        break;
      }
    }

    if (!targetUrlId) {
      targetUrlId = directUrlId;
      const urlEvidence: string[] = [];
      if (urlObj.domain && /^(\d{1,3}\.){3}\d{1,3}$/.test(urlObj.domain)) {
        urlEvidence.push('Bare IP address in URL');
      }
      if (!urlObj.is_https) {
        urlEvidence.push('Unencrypted HTTP transport');
      }

      const urlObs = data.threat_intelligence?.observations?.find(
        (o) => o.entity_type === 'url' && o.entity.toLowerCase() === urlObj.url.toLowerCase()
      );
      if (urlObs?.evidence && Array.isArray(urlObs.evidence)) {
        urlEvidence.push(...urlObs.evidence);
      }

      const isSuspicious = !urlObj.is_https || (urlObs?.data?.malicious_votes as number) > 0;

      nodesMap.set(targetUrlId, {
        id: targetUrlId,
        type: 'url',
        label: urlObj.url,
        primaryValue: urlObj.url,
        secondaryMeta: urlObj.domain || 'URL Payload',
        severity: isSuspicious ? 'critical' : 'info',
        source: urlObj.source ? `Message Body (${urlObj.source})` : 'Message Body HTML',
        confidence: 'high',
        properties: {
          url: urlObj.url,
          is_https: urlObj.is_https,
          domain: urlObj.domain,
          scheme: urlObj.scheme,
          path: urlObj.path,
          ...(urlObs?.data || {}),
        },
        evidence: urlEvidence.length > 0 ? urlEvidence : ['Extracted message body URL'],
      });
    }

    // Edge: Root Email -> URL
    const urlEdgeId = `${rootEmailId}->${targetUrlId}:contains_link`;
    if (!edgesMap.has(urlEdgeId)) {
      edgesMap.set(urlEdgeId, {
        id: urlEdgeId,
        source: rootEmailId,
        target: targetUrlId,
        relationship: 'contains_link',
        label: 'CONTAINS LINK',
        confidence: 'high',
        evidence: ['Extracted message hyperlink payload'],
      });
    }

    // Edge: URL -> Relay IP (collocated host)
    if (relayAddress && urlObj.domain === relayAddress) {
      let matchedIpId: string | undefined;
      for (const [id, node] of nodesMap.entries()) {
        if (node.type === 'ip' && (id.toLowerCase() === `ip:${relayAddress.toLowerCase()}` || node.primaryValue === relayAddress)) {
          matchedIpId = id;
          break;
        }
      }
      if (matchedIpId) {
        const collocateEdgeId = `${targetUrlId}->${matchedIpId}:hosted_on`;
        if (!edgesMap.has(collocateEdgeId)) {
          edgesMap.set(collocateEdgeId, {
            id: collocateEdgeId,
            source: targetUrlId,
            target: matchedIpId,
            relationship: 'hosted_on',
            label: 'HOSTED ON',
            confidence: 'high',
            evidence: ['Direct IP target match with origin relay'],
          });
        }
      }
    }
  }

  // Reply-To Redirect Node if mismatch exists
  const replyToDomain = data.security_analysis?.authentication_results?.reply_to_domain;
  if (replyToDomain && replyToDomain !== fromDomain) {
    const directReplyId = `domain:${replyToDomain.toLowerCase()}`;
    let targetReplyId: string | undefined;
    for (const [id, node] of nodesMap.entries()) {
      if (node.type === 'domain' && (id.toLowerCase() === directReplyId || node.primaryValue.toLowerCase() === replyToDomain.toLowerCase())) {
        targetReplyId = id;
        break;
      }
    }

    if (!targetReplyId) {
      targetReplyId = directReplyId;
      nodesMap.set(targetReplyId, {
        id: targetReplyId,
        type: 'domain',
        label: replyToDomain,
        primaryValue: replyToDomain,
        secondaryMeta: 'Diverted Reply-To Channel',
        severity: 'medium',
        source: 'Reply-To Header',
        confidence: 'high',
        properties: {
          domain: replyToDomain,
          mismatch: true,
        },
        evidence: ['Differs from RFC 5322 From domain'],
      });
    }

    const replyEdgeId = `${rootEmailId}->${targetReplyId}:redirects_to`;
    if (!edgesMap.has(replyEdgeId)) {
      edgesMap.set(replyEdgeId, {
        id: replyEdgeId,
        source: rootEmailId,
        target: targetReplyId,
        relationship: 'redirects_to',
        label: 'REDIRECTS REPLIES TO',
        confidence: 'high',
        evidence: ['Reply-To header redirection'],
      });
    }
  }

  // 3. Process Verified ASN and Geolocation from Threat Intelligence Observations
  // STRICT FORENSIC INTEGRITY: Only create ASN or Geolocation nodes/edges if explicitly present in backend data.
  const observations = data.threat_intelligence?.observations || [];
  for (const obs of observations) {
    if (obs.status !== 'success' || !obs.data) continue;
    const obsData = obs.data as Record<string, unknown>;
    const obsConfidence: Confidence = (obs.confidence && obs.confidence !== 'none') ? obs.confidence : 'high';

    // Find parent entity node if present in graph
    let parentNodeId: string | undefined;
    if (obs.entity_type && obs.entity) {
      const directId = `${obs.entity_type}:${obs.entity.toLowerCase()}`;
      for (const [id, node] of nodesMap.entries()) {
        if (node.type === obs.entity_type && (id.toLowerCase() === directId || node.primaryValue.toLowerCase() === obs.entity.toLowerCase())) {
          parentNodeId = id;
          break;
        }
      }
    }

    // A. Verified ASN (only if explicitly present in observation data)
    const rawAsn = obsData.asn || obsData.as_number;
    if (rawAsn) {
      const asnStr = String(rawAsn).trim();
      const asnNodeId = `asn:${asnStr.toLowerCase()}`;
      if (!nodesMap.has(asnNodeId)) {
        const isp = typeof obsData.isp === 'string' ? obsData.isp : (typeof obsData.organization === 'string' ? obsData.organization : undefined);
        const properties: Record<string, unknown> = {
          asn: asnStr,
          ...(isp ? { isp } : {}),
          ...(typeof obsData.cidr === 'string' ? { cidr: obsData.cidr } : {}),
          ...(typeof obsData.network === 'string' ? { network: obsData.network } : {}),
        };
        nodesMap.set(asnNodeId, {
          id: asnNodeId,
          type: 'asn',
          label: isp ? `${asnStr} (${isp})` : asnStr,
          primaryValue: asnStr,
          secondaryMeta: isp || 'Autonomous System Routing Authority',
          severity: 'info',
          source: obs.provider || 'BGP Routing Telemetry',
          confidence: obsConfidence,
          properties,
          evidence: obs.evidence && obs.evidence.length > 0 ? obs.evidence : [`Announced by ${asnStr}`],
        });
      }

      if (parentNodeId) {
        const asnEdgeId = `${parentNodeId}->${asnNodeId}:announced_by`;
        if (!edgesMap.has(asnEdgeId)) {
          edgesMap.set(asnEdgeId, {
            id: asnEdgeId,
            source: parentNodeId,
            target: asnNodeId,
            relationship: 'announced_by',
            label: 'ANNOUNCED BY',
            confidence: obsConfidence,
            evidence: obs.evidence && obs.evidence.length > 0 ? obs.evidence : [`Routing announcement via ${asnStr}`],
          });
        }
      }
    }

    // B. Verified Geolocation (only if explicitly present in observation data)
    const country = typeof obsData.country === 'string' ? obsData.country : undefined;
    const countryCode = typeof obsData.country_code === 'string' ? obsData.country_code : undefined;
    const city = typeof obsData.city === 'string' ? obsData.city : undefined;
    const lat = typeof obsData.latitude === 'number' ? obsData.latitude : undefined;
    const lon = typeof obsData.longitude === 'number' ? obsData.longitude : undefined;

    if (country || countryCode || city || (lat !== undefined && lon !== undefined)) {
      const geoKey = (countryCode || country || city || 'location').toLowerCase().replace(/\s+/g, '_');
      const geoNodeId = `location:${geoKey}`;
      if (!nodesMap.has(geoNodeId)) {
        const labelParts = [city, country].filter(Boolean);
        let geoLabel = labelParts.length > 0 ? labelParts.join(', ') : (countryCode || 'Geolocation');
        if (countryCode && country && !geoLabel.includes(`[${countryCode}]`)) {
          geoLabel = `${geoLabel} [${countryCode}]`;
        }

        const geoProperties: Record<string, unknown> = {
          ...(country ? { country } : {}),
          ...(countryCode ? { country_code: countryCode } : {}),
          ...(city ? { city } : {}),
          ...(lat !== undefined ? { latitude: lat } : {}),
          ...(lon !== undefined ? { longitude: lon } : {}),
        };

        nodesMap.set(geoNodeId, {
          id: geoNodeId,
          type: 'location',
          label: geoLabel,
          primaryValue: country || city || countryCode || 'Location',
          secondaryMeta: (lat !== undefined && lon !== undefined)
            ? `Coordinates: ${lat}, ${lon}`
            : (country || city || countryCode),
          severity: 'info',
          source: obs.provider || 'IP Geolocation Telemetry',
          confidence: obsConfidence,
          properties: geoProperties,
          evidence: obs.evidence && obs.evidence.length > 0 ? obs.evidence : [`Geolocation telemetry: ${geoLabel}`],
        });
      }

      if (parentNodeId) {
        const geoEdgeId = `${parentNodeId}->${geoNodeId}:located_in`;
        if (!edgesMap.has(geoEdgeId)) {
          edgesMap.set(geoEdgeId, {
            id: geoEdgeId,
            source: parentNodeId,
            target: geoNodeId,
            relationship: 'located_in',
            label: 'LOCATED IN',
            confidence: obsConfidence,
            evidence: obs.evidence && obs.evidence.length > 0 ? obs.evidence : [`IP geolocation observed via ${obs.provider || 'telemetry'}`],
          });
        }
      }
    }
  }

  // 4. Process explicit threat intelligence relationships if present
  const tiRelationships = data.threat_intelligence?.relationships || [];
  for (const rel of tiRelationships) {
    let sourceId: string | undefined;
    let targetId: string | undefined;

    for (const [id, node] of nodesMap.entries()) {
      if (node.type === rel.source_type && (id.toLowerCase() === `${rel.source_type}:${rel.source.toLowerCase()}` || node.primaryValue.toLowerCase() === rel.source.toLowerCase())) {
        sourceId = id;
      }
      if (node.type === rel.target_type && (id.toLowerCase() === `${rel.target_type}:${rel.target.toLowerCase()}` || node.primaryValue.toLowerCase() === rel.target.toLowerCase())) {
        targetId = id;
      }
    }

    if (sourceId && targetId) {
      const edgeId = `${sourceId}->${targetId}:${rel.relationship}`;
      if (!edgesMap.has(edgeId)) {
        edgesMap.set(edgeId, {
          id: edgeId,
          source: sourceId,
          target: targetId,
          relationship: rel.relationship,
          label: rel.relationship.replace(/_/g, ' ').toUpperCase(),
          confidence: 'high',
          evidence: rel.providers ? [`Reported by ${rel.providers.join(', ')}`] : [],
        });
      }
    }
  }

  return {
    nodes: Array.from(nodesMap.values()),
    edges: Array.from(edgesMap.values()),
    correlationsCount: data.correlations?.length || 0,
  };
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
