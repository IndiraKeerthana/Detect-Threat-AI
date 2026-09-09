import React, { useEffect, useRef, useState, useMemo } from 'react';
import cytoscape from 'cytoscape';
import {
  Maximize2,
  RotateCcw,
  ZoomIn,
  ZoomOut,
  X,
  MapPin,
  Server,
  Link2,
  Globe,
  Mail,
  Network,
  Info,
  ChevronRight,
  AlertTriangle,
  CheckCircle2,
  HelpCircle,
  Eye,
  Layers,
} from 'lucide-react';
import type { EmailAnalysisResponse } from '../../types/investigation';
import {
  normalizeGraphData,
  normalizeInvestigationPath,
  generateWhyThisMatters,
} from '../../services/investigationAdapter';
import type {
  NormalizedGraphNode,
  ForensicNodeType,
} from '../../services/investigationAdapter';
import { useInvestigationVisual } from '../../context/InvestigationVisualContext';
import { SectionHeader } from '../investigation/SectionHeader';

interface AttackGraphProps {
  data: EmailAnalysisResponse;
}

export const AttackGraph: React.FC<AttackGraphProps> = ({ data }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const { selectedEntityId, setSelectedEntityId, focusMap } = useInvestigationVisual();

  const [selectedNode, setSelectedNode] = useState<NormalizedGraphNode | null>(null);
  const [showEdgeLabels, setShowEdgeLabels] = useState<boolean>(true);

  // Normalize data using the investigation adapter
  const graphData = useMemo(() => normalizeGraphData(data), [data]);
  const pathStages = useMemo(() => normalizeInvestigationPath(data), [data]);
  const whyMattersPoints = useMemo(() => generateWhyThisMatters(data), [data]);

  // Compute deterministic left-to-right positions based on rankColumn
  const nodePositions = useMemo(() => {
    const primaryNodes: Record<number, NormalizedGraphNode> = {};
    const secondaryNodes: NormalizedGraphNode[] = [];

    // Separate primary chain nodes (one per rankColumn 0..5) from secondary branch nodes
    for (const node of graphData.nodes) {
      const col = node.rankColumn ?? 1;
      const isSecondary = node.properties?.role === 'reply_to' || node.properties?.role === 'url_payload';
      if (!isSecondary && (!primaryNodes[col] || primaryNodes[col].status === 'unavailable')) {
        primaryNodes[col] = node;
      } else if (!isSecondary && !primaryNodes[col]) {
        primaryNodes[col] = node;
      } else {
        secondaryNodes.push(node);
      }
    }

    const positions: Record<string, { x: number; y: number }> = {};

    // Position primary chain nodes horizontally along y = 190
    for (const node of graphData.nodes) {
      const col = node.rankColumn ?? 1;
      const isPrimary = primaryNodes[col]?.id === node.id;

      if (isPrimary) {
        const x = 90 + col * 210;
        const y = 190;
        positions[node.id] = { x, y };
      }
    }

    // Position secondary branch nodes below main chain
    const secondaryColCounts: Record<number, number> = {};
    for (const node of secondaryNodes) {
      const col = node.rankColumn ?? 1;
      const count = secondaryColCounts[col] || 0;
      secondaryColCounts[col] = count + 1;

      const x = 90 + col * 210;
      const y = 320 + (count - 1) * 110;
      positions[node.id] = { x, y };
    }

    return positions;
  }, [graphData.nodes]);

  // Cytoscape initialization & updates
  useEffect(() => {
    if (!containerRef.current) return;

    const formatNodeCardLabel = (node: NormalizedGraphNode): string => {
      if (node.properties?.role === 'no_verified_infrastructure') {
        return 'NO VERIFIED ORIGIN\nINFRASTRUCTURE';
      }

      let header = node.type.toUpperCase();
      if (node.type === 'email') header = 'EMAIL ROOT';
      else if (node.properties?.role === 'reply_to') header = 'REPLY-TO';
      else if (node.type === 'identity' || node.type === 'domain') header = 'SENDER';
      else if (node.type === 'relay') header = 'SMTP RELAY';
      else if (node.type === 'ip') header = 'SOURCE IP';
      else if (node.type === 'asn') header = 'NETWORK / ASN';
      else if (node.type === 'location') header = 'GEOLOCATION';
      else if (node.type === 'url') header = 'URL PAYLOAD';

      if (node.status === 'unavailable') {
        return `${header}\n[Unavailable]`;
      }

      let val = node.primaryValue || node.label;
      if (val.length > 20) {
        val = val.slice(0, 18) + '...';
      }
      return `${header}\n${val}`;
    };

    const validNodeIds = new Set(graphData.nodes.map((n) => n.id));
    const safeEdges = graphData.edges.filter(
      (e) => validNodeIds.has(e.source) && validNodeIds.has(e.target) && e.source !== e.target
    );

    // Convert normalized nodes to Cytoscape elements
    const elements: cytoscape.ElementDefinition[] = [
      ...graphData.nodes.map((node) => ({
        data: {
          id: node.id,
          label: formatNodeCardLabel(node),
          fullLabel: node.label,
          type: node.type,
          status: node.status,
          role: (node.properties?.role as string) || undefined,
          primaryValue: node.primaryValue,
          secondaryMeta: node.secondaryMeta,
          severity: node.severity,
          source: node.source,
          confidence: node.confidence,
          properties: node.properties,
          evidence: node.evidence,
          whyItMatters: node.whyItMatters,
        },
        position: nodePositions[node.id] || { x: 100, y: 190 },
      })),
      ...safeEdges.map((edge) => ({
        data: {
          id: edge.id,
          source: edge.source,
          target: edge.target,
          label: edge.label,
          relationship: edge.relationship,
          isObserved: edge.isObserved,
          confidence: edge.confidence,
          evidence: edge.evidence,
        },
      })),
    ];

    let cy: cytoscape.Core | null = null;
    try {
      cy = cytoscape({
        container: containerRef.current,
        elements,
        boxSelectionEnabled: false,
        autounselectify: false,
        minZoom: 0.4,
        maxZoom: 2.0,
        style: [
        // Base Node Style (Forensic Card)
        {
          selector: 'node',
          style: {
            'shape': 'round-rectangle',
            'width': 165,
            'height': 56,
            'background-color': '#12151b',
            'border-width': 1.5,
            'border-color': '#2a3242',
            'label': 'data(label)',
            'color': '#f1f5f9',
            'font-family': 'JetBrains Mono, monospace',
            'font-size': '10px',
            'font-weight': 600,
            'text-valign': 'center',
            'text-halign': 'center',
            'text-wrap': 'wrap',
            'text-max-width': '148px',
            'line-height': 1.3,
            'padding': '6px',
          },
        },
        // Semantic Node Types
        {
          selector: 'node[type = "email"]',
          style: {
            'border-color': '#8b5cf6',
            'border-width': 2.5,
            'background-color': '#161224',
            'color': '#f1f5f9',
          },
        },
        {
          selector: 'node[type = "domain"]',
          style: {
            'border-color': '#3b82f6',
            'background-color': '#0f172a',
            'color': '#93c5fd',
          },
        },
        {
          selector: 'node[type = "relay"]',
          style: {
            'border-color': '#06b6d4',
            'background-color': '#0b1f26',
            'color': '#67e8f9',
          },
        },
        {
          selector: 'node[type = "url"]',
          style: {
            'border-color': '#ef4444',
            'background-color': '#241014',
            'color': '#fca5a5',
          },
        },
        {
          selector: 'node[type = "ip"]',
          style: {
            'border-color': '#06b6d4',
            'background-color': '#0b1f26',
            'color': '#67e8f9',
          },
        },
        {
          selector: 'node[type = "asn"]',
          style: {
            'border-color': '#64748b',
            'background-color': '#12151b',
            'color': '#94a3b8',
          },
        },
        {
          selector: 'node[type = "location"]',
          style: {
            'border-color': '#10b981',
            'background-color': '#0c2118',
            'color': '#6ee7b7',
          },
        },
        // Node Status Overrides
        {
          selector: 'node[status = "suspicious"]',
          style: {
            'border-color': '#f59e0b',
            'border-width': 2,
          },
        },
        {
          selector: 'node[status = "malicious"]',
          style: {
            'border-color': '#ef4444',
            'border-width': 2.5,
          },
        },
        {
          selector: 'node[status = "unavailable"]',
          style: {
            'border-color': '#334155',
            'border-style': 'dashed',
            'background-color': '#080a0f',
            'color': '#64748b',
            'opacity': 0.85,
          },
        },
        // Explanatory State Node Override (Informational/Neutral Empty State)
        {
          selector: 'node[role = "no_verified_infrastructure"]',
          style: {
            'width': 210,
            'height': 58,
            'border-color': '#475569',
            'border-style': 'dashed',
            'border-width': 1.5,
            'background-color': '#0f172a',
            'color': '#94a3b8',
            'font-size': '9.5px',
            'font-weight': 600,
            'text-max-width': '195px',
            'opacity': 1.0,
          },
        },
        // Selected Node State
        {
          selector: 'node:selected',
          style: {
            'border-width': 3,
            'border-color': '#f1f5f9',
            'background-color': '#1e232e',
          },
        },
        // Base Edge Style
        {
          selector: 'edge',
          style: {
            'curve-style': 'bezier',
            'target-arrow-shape': 'triangle',
            'target-arrow-color': '#475569',
            'line-color': '#475569',
            'width': 1.5,
            'arrow-scale': 0.85,
            'label': showEdgeLabels ? 'data(label)' : '',
            'font-family': 'JetBrains Mono, monospace',
            'font-size': '8px',
            'font-weight': 600,
            'color': '#94a3b8',
            'text-rotation': 'autorotate',
            'text-margin-y': -8,
            'text-background-opacity': 0.95,
            'text-background-color': '#08090d',
            'text-background-padding': '3px',
            'text-background-shape': 'roundrectangle',
          },
        },
        // Directly Observed Edge (Solid Line)
        {
          selector: 'edge[?isObserved]',
          style: {
            'line-style': 'solid',
            'line-color': '#64748b',
            'target-arrow-color': '#64748b',
            'width': 2,
          },
        },
        // OSINT / Threat Intel Enrichment Edge (Dashed Line)
        {
          selector: 'edge[!isObserved]',
          style: {
            'line-style': 'dashed',
            'line-dash-pattern': [6, 4],
            'line-color': '#475569',
            'target-arrow-color': '#475569',
            'width': 1.5,
          },
        },
        // Selected Edge Highlight
        {
          selector: 'edge:selected',
          style: {
            'line-color': '#8b5cf6',
            'target-arrow-color': '#8b5cf6',
            'color': '#c4b5fd',
            'width': 2.5,
          },
        },
      ],
      layout: {
        name: 'preset',
        positions: (node: any) => nodePositions[typeof node === 'string' ? node : node.id()] || { x: 100, y: 190 },
        fit: true,
        padding: 45,
      },
    });

    if (cy) {
      const activeCy = cy;
      activeCy.ready(() => {
        activeCy.fit(activeCy.nodes(), 45);
        if (activeCy.zoom() > 1.05) {
          activeCy.zoom(1.05);
          activeCy.center();
        }
      });

      // Handle node selection events
      activeCy.on('tap', 'node', (evt) => {
        const nodeData = evt.target.data();
        const matchedNode = graphData.nodes.find((n) => n.id === nodeData.id);
        if (matchedNode) {
          setSelectedNode(matchedNode);
          setSelectedEntityId(matchedNode.id);
        }
      });

      // Deselect when tapping on background
      activeCy.on('tap', (evt) => {
        if (evt.target === activeCy) {
          setSelectedNode(null);
          setSelectedEntityId(null);
        }
      });

      cyRef.current = activeCy;
    }
    } catch (err) {
      console.error('[AttackGraph] Failed to initialize Cytoscape graph:', err);
    }

    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [graphData, nodePositions, setSelectedEntityId, showEdgeLabels]);

  // Synchronize external selection
  useEffect(() => {
    if (!cyRef.current) return;
    const cy = cyRef.current;

    if (selectedEntityId) {
      const targetElement = cy.getElementById(selectedEntityId);
      if (targetElement && targetElement.length > 0) {
        cy.elements().unselect();
        targetElement.select();
        cy.animate({
          center: { eles: targetElement },
          duration: 300,
          zoom: Math.max(cy.zoom(), 0.9),
        });
        const matched = graphData.nodes.find((n) => n.id === selectedEntityId);
        if (matched) {
          setSelectedNode(matched);
        }
      }
    }
  }, [selectedEntityId, graphData.nodes]);

  // Control Handlers
  const handleFit = () => {
    if (!cyRef.current) return;
    cyRef.current.fit(cyRef.current.nodes(), 45);
    if (cyRef.current.zoom() > 1.05) {
      cyRef.current.zoom(1.05);
      cyRef.current.center();
    }
  };

  const handleReset = () => {
    if (!cyRef.current) return;
    cyRef.current
      .layout({
        name: 'preset',
        positions: (node: any) => nodePositions[typeof node === 'string' ? node : node.id()] || { x: 100, y: 190 },
        fit: true,
        padding: 45,
      })
      .run();
    if (cyRef.current.zoom() > 1.05) {
      cyRef.current.zoom(1.05);
      cyRef.current.center();
    }
  };

  const handleZoomIn = () => {
    if (!cyRef.current) return;
    cyRef.current.zoom({
      level: cyRef.current.zoom() * 1.25,
      renderedPosition: {
        x: cyRef.current.width() / 2,
        y: cyRef.current.height() / 2,
      },
    });
  };

  const handleZoomOut = () => {
    if (!cyRef.current) return;
    cyRef.current.zoom({
      level: cyRef.current.zoom() * 0.8,
      renderedPosition: {
        x: cyRef.current.width() / 2,
        y: cyRef.current.height() / 2,
      },
    });
  };

  const getNodeIcon = (type: ForensicNodeType) => {
    switch (type) {
      case 'email':
        return Mail;
      case 'ip':
        return Server;
      case 'url':
        return Link2;
      case 'domain':
        return Globe;
      case 'asn':
        return Network;
      case 'location':
        return MapPin;
      default:
        return Info;
    }
  };

  const renderStatusBadge = (status: string) => {
    switch (status) {
      case 'malicious':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-[#241014] text-[#fca5a5] border border-[#ef4444] text-[10px] font-bold uppercase">
            <AlertTriangle className="w-3 h-3 text-[#ef4444]" />
            MALICIOUS
          </span>
        );
      case 'suspicious':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-[#1f190e] text-[#fcd34d] border border-[#f59e0b] text-[10px] font-bold uppercase">
            <AlertTriangle className="w-3 h-3 text-[#f59e0b]" />
            SUSPICIOUS
          </span>
        );
      case 'unavailable':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-[#12151b] text-[#64748b] border border-[#334155] text-[10px] font-bold uppercase">
            <HelpCircle className="w-3 h-3 text-[#64748b]" />
            UNAVAILABLE
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-[#0c2118] text-[#6ee7b7] border border-[#10b981] text-[10px] font-bold uppercase">
            <CheckCircle2 className="w-3 h-3 text-[#10b981]" />
            VERIFIED
          </span>
        );
    }
  };

  return (
    <div className="surface-card p-6 border border-[#1e2430] space-y-4 relative font-mono select-none">
      {/* Section Header */}
      <SectionHeader
        index="05"
        tag="OBSERVABLE TOPOLOGY"
        title="Interactive Attack & Infrastructure Graph"
        subtitle="Deterministic left-to-right forensic relationship graph mapping email root, sender identity, relays, target infrastructure, and OSINT telemetry"
        action={
          <div className="flex items-center space-x-2 text-xs font-mono">
            <span className="text-[#64748b]">
              NODES: <strong className="text-[#f1f5f9]">{graphData.nodes.length}</strong>
            </span>
            <span>•</span>
            <span className="text-[#64748b]">
              EDGES: <strong className="text-[#f1f5f9]">{graphData.edges.length}</strong>
            </span>
            <span className="px-2 py-0.5 rounded bg-[#1e1533] text-[#c4b5fd] border border-[#432474] text-[10px] font-bold">
              LEFT-TO-RIGHT TOPOLOGY
            </span>
          </div>
        }
      />

      {/* 1. Investigation Path Bar (Above Graph) */}
      <div className="bg-[#0b0d12] border border-[#1e2430] rounded-lg p-3 overflow-x-auto">
        <div className="text-[10px] uppercase text-[#64748b] font-bold mb-2 flex items-center gap-1.5">
          <Layers className="w-3.5 h-3.5 text-[#8b5cf6]" />
          INVESTIGATION PATH TOPOLOGY:
        </div>
        <div className="flex items-center space-x-2 min-w-max text-xs">
          {pathStages.map((stage, idx) => (
            <React.Fragment key={stage.id}>
              <div
                className={`flex items-center space-x-2 px-3 py-1.5 rounded-md border text-xs ${
                  stage.status === 'malicious'
                    ? 'bg-[#241014] border-[#ef4444] text-[#fca5a5]'
                    : stage.status === 'suspicious'
                    ? 'bg-[#1f190e] border-[#f59e0b] text-[#fcd34d]'
                    : stage.status === 'unavailable'
                    ? 'bg-[#0f1217] border-[#2a3242] text-[#64748b]'
                    : 'bg-[#141824] border-[#2a3242] text-[#f1f5f9]'
                }`}
              >
                <div className="flex flex-col">
                  <span className="text-[9px] text-[#64748b] font-bold uppercase tracking-wider">
                    {stage.label}
                  </span>
                  <span className="font-semibold text-xs truncate max-w-[140px]" title={stage.value}>
                    {stage.value}
                  </span>
                </div>
                {stage.status === 'unavailable' && (
                  <span className="text-[9px] px-1.5 py-0.5 rounded bg-[#1e2430] text-[#64748b] font-bold">
                    N/A
                  </span>
                )}
              </div>
              {idx < pathStages.length - 1 && (
                <ChevronRight className="w-4 h-4 text-[#334155] flex-shrink-0" />
              )}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* 2. Main Graph Canvas Container */}
      <div className="relative w-full h-[480px] bg-[#08090d] border border-[#1e2430] rounded-lg overflow-hidden select-none">
        {/* Grid pattern background */}
        <div
          className="absolute inset-0 opacity-15 pointer-events-none"
          style={{
            backgroundImage: `radial-gradient(#2a3242 1px, transparent 1px)`,
            backgroundSize: '20px 20px',
          }}
        />

        {/* Cytoscape DOM Mount */}
        <div ref={containerRef} className="w-full h-full cursor-grab active:cursor-grabbing" />

        {/* Graph Control Toolbar (Top Right) */}
        <div className="absolute top-3 right-3 flex items-center bg-[#12151b]/90 backdrop-blur border border-[#1e2430] rounded-md p-1 space-x-1 z-10 shadow-md">
          <button
            onClick={handleZoomIn}
            className="p-1.5 rounded hover:bg-[#1e232e] text-[#94a3b8] hover:text-[#f1f5f9] transition-colors"
            title="Zoom in"
            aria-label="Zoom in"
          >
            <ZoomIn className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={handleZoomOut}
            className="p-1.5 rounded hover:bg-[#1e232e] text-[#94a3b8] hover:text-[#f1f5f9] transition-colors"
            title="Zoom out"
            aria-label="Zoom out"
          >
            <ZoomOut className="w-3.5 h-3.5" />
          </button>
          <div className="w-[1px] h-4 bg-[#1e2430] my-auto" />
          <button
            onClick={handleFit}
            className="p-1.5 rounded hover:bg-[#1e232e] text-[#94a3b8] hover:text-[#f1f5f9] transition-colors"
            title="Fit graph to viewport"
            aria-label="Fit to viewport"
          >
            <Maximize2 className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={handleReset}
            className="p-1.5 rounded hover:bg-[#1e232e] text-[#94a3b8] hover:text-[#f1f5f9] transition-colors"
            title="Reset topology layout"
            aria-label="Reset layout"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
          <div className="w-[1px] h-4 bg-[#1e2430] my-auto" />
          <button
            onClick={() => setShowEdgeLabels((prev) => !prev)}
            className={`p-1.5 rounded transition-colors ${
              showEdgeLabels
                ? 'bg-[#1e1533] text-[#c4b5fd] border border-[#432474]'
                : 'hover:bg-[#1e232e] text-[#64748b]'
            }`}
            title="Toggle relationship labels"
            aria-label="Toggle edge labels"
          >
            <Eye className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* 3. Node Detail Inspector Drawer */}
        {selectedNode && (
          <div className="absolute top-3 left-3 bottom-3 w-84 max-w-[calc(100%-24px)] bg-[#0f1217]/95 backdrop-blur-md border border-[#2a3242] rounded-lg p-4 z-20 shadow-2xl overflow-y-auto space-y-3 font-mono text-xs animate-in fade-in duration-200">
            {/* Inspector Header */}
            <div className="flex items-center justify-between pb-2 border-b border-[#1e2430]">
              <div className="flex items-center space-x-2">
                {React.createElement(getNodeIcon(selectedNode.type), {
                  className: 'w-4 h-4 text-[#8b5cf6]',
                })}
                <span className="text-[10px] text-[#64748b] uppercase tracking-wider font-bold">
                  ENTITY INSPECTOR
                </span>
              </div>
              <button
                onClick={() => {
                  setSelectedNode(null);
                  setSelectedEntityId(null);
                }}
                className="p-1 rounded hover:bg-[#171b23] text-[#64748b] hover:text-[#f1f5f9] transition-colors"
                title="Close Inspector"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Status & Category */}
            <div className="flex items-center justify-between">
              <span className="text-[10px] text-[#64748b] uppercase font-bold">
                {selectedNode.type} Observable
              </span>
              {renderStatusBadge(selectedNode.status)}
            </div>

            {/* Entity Value */}
            <div className="space-y-1">
              <div
                className="text-xs text-[#f1f5f9] font-bold break-all bg-[#171b23] p-2.5 rounded border border-[#2a3242]"
                title={selectedNode.primaryValue}
              >
                {selectedNode.primaryValue}
              </div>
            </div>

            {/* Context / Why It Matters */}
            {selectedNode.whyItMatters && (
              <div className="bg-[#161324] border border-[#3b2166] p-2.5 rounded text-[11px] text-[#c4b5fd] space-y-1">
                <span className="text-[9px] uppercase text-[#a78bfa] font-bold block">
                  WHY THIS MATTERS
                </span>
                <p className="leading-snug">{selectedNode.whyItMatters}</p>
              </div>
            )}

            {/* Metadata Fields */}
            <div className="space-y-1.5 text-[11px]">
              <div className="flex justify-between py-1 border-b border-[#1e2430]">
                <span className="text-[#64748b]">Telemetry Source:</span>
                <span className="text-[#94a3b8] text-right truncate max-w-[150px]" title={selectedNode.source}>
                  {selectedNode.source}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-[#1e2430]">
                <span className="text-[#64748b]">Confidence Level:</span>
                <span className="text-[#10b981] font-semibold uppercase">
                  {selectedNode.confidence}
                </span>
              </div>
              {selectedNode.secondaryMeta && (
                <div className="flex justify-between py-1 border-b border-[#1e2430]">
                  <span className="text-[#64748b]">Role / Metadata:</span>
                  <span className="text-[#c4b5fd] text-right truncate max-w-[150px]">{selectedNode.secondaryMeta}</span>
                </div>
              )}
            </div>

            {/* Properties */}
            {Object.keys(selectedNode.properties).length > 0 && (
              <div className="space-y-1 pt-1">
                <span className="text-[10px] text-[#64748b] uppercase block font-bold">
                  OBSERVED PROPERTIES & ATTRIBUTES
                </span>
                <div className="bg-[#0a0c10] border border-[#1e2430] p-2 rounded space-y-1 text-[10px]">
                  {Object.entries(selectedNode.properties)
                    .slice(0, 8)
                    .map(([k, v]) => (
                      <div key={k} className="flex justify-between gap-2">
                        <span className="text-[#64748b] truncate">{k}:</span>
                        <span className="text-[#f1f5f9] truncate max-w-[150px]" title={String(v)}>
                          {String(v)}
                        </span>
                      </div>
                    ))}
                </div>
              </div>
            )}

            {/* Evidence List */}
            {selectedNode.evidence && selectedNode.evidence.length > 0 && (
              <div className="space-y-1 pt-1">
                <span className="text-[10px] text-[#64748b] uppercase block font-bold">
                  SUPPORTING EVIDENCE
                </span>
                <div className="space-y-1">
                  {selectedNode.evidence.map((ev, i) => (
                    <div
                      key={i}
                      className="text-[10px] text-[#67e8f9] bg-[#0c232c] border border-[#154c5e] px-2 py-1 rounded"
                    >
                      • {ev}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Action button: Focus Map */}
            {(selectedNode.type === 'ip' || selectedNode.type === 'location') && (
              <div className="pt-2">
                <button
                  type="button"
                  onClick={() => focusMap()}
                  className="w-full py-2 px-3 rounded bg-[#0c232c] hover:bg-[#154c5e] text-[#67e8f9] border border-[#154c5e] text-[11px] font-mono flex items-center justify-center gap-1.5 transition-colors font-bold"
                >
                  <MapPin className="w-3.5 h-3.5" />
                  LOCATE IN GEOLOCATION MAP
                </button>
              </div>
            )}
          </div>
        )}
      </div>

      {/* 4. "Why This Matters" Evidence Rationale Section */}
      <div className="bg-[#0a0c10] border border-[#1e2430] rounded-lg p-4 space-y-2">
        <div className="flex items-center space-x-2 text-xs font-bold text-[#f1f5f9]">
          <Info className="w-4 h-4 text-[#06b6d4]" />
          <span>TOPOLOGY EVIDENCE ASSESSMENT — WHY THIS MATTERS:</span>
        </div>
        <div className="space-y-1.5 text-xs text-[#94a3b8] leading-relaxed">
          {whyMattersPoints.map((pt, i) => (
            <div key={i} className="flex items-start space-x-2">
              <span className="text-[#06b6d4] font-bold">•</span>
              <span>{pt}</span>
            </div>
          ))}
        </div>
      </div>

      {/* 5. Comprehensive Legend */}
      <div className="flex flex-wrap items-center justify-between gap-4 text-xs font-mono text-[#64748b] pt-1 border-t border-[#1e2430]">
        <div className="flex flex-wrap items-center gap-4 text-[11px]">
          <span className="text-[10px] uppercase font-bold text-[#94a3b8]">ENTITIES:</span>
          <span className="inline-flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-[#161224] border-2 border-[#8b5cf6]" />
            <span className="text-[#f1f5f9]">Email</span>
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-[#1f190e] border border-[#f59e0b]" />
            <span className="text-[#fcd34d]">Domain / Identity</span>
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-[#241014] border border-[#ef4444]" />
            <span className="text-[#fca5a5]">Payload URL</span>
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-[#0b1f26] border border-[#06b6d4]" />
            <span className="text-[#67e8f9]">Relay IP</span>
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-[#12151b] border border-[#64748b]" />
            <span className="text-[#94a3b8]">ASN / Network</span>
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-[#0c2118] border border-[#10b981]" />
            <span className="text-[#6ee7b7]">Location</span>
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-4 text-[11px]">
          <span className="text-[10px] uppercase font-bold text-[#94a3b8]">RELATIONSHIPS:</span>
          <span className="inline-flex items-center gap-1.5">
            <span className="w-4 h-0.5 bg-[#64748b]" />
            <span className="text-[#f1f5f9]">Observed (Headers/Relay)</span>
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="w-4 border-b border-dashed border-[#64748b]" />
            <span className="text-[#94a3b8]">OSINT / Enrichment</span>
          </span>
        </div>
      </div>
    </div>
  );
};
