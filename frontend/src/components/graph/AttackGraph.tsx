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
  generatePathInterpretation,
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
  const pathInterpretation = useMemo(() => generatePathInterpretation(data), [data]);

  // Compute deterministic left-to-right positions based on rankColumn
  const nodePositions = useMemo(() => {
    const primaryNodes: Record<number, NormalizedGraphNode> = {};
    const secondaryNodes: NormalizedGraphNode[] = [];

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

    for (const node of graphData.nodes) {
      const col = node.rankColumn ?? 1;
      const isPrimary = primaryNodes[col]?.id === node.id;

      if (isPrimary) {
        const x = 90 + col * 210;
        const y = 190;
        positions[node.id] = { x, y };
      }
    }

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
        return 'NO VERIFIED SOURCE\nINFRASTRUCTURE';
      }

      let header = node.type.toUpperCase();
      if (node.type === 'email') header = 'EMAIL';
      else if (node.properties?.role === 'reply_to') header = 'REPLY-TO';
      else if (node.type === 'identity' || node.type === 'domain') header = 'SENDER';
      else if (node.type === 'relay') header = 'OBSERVED RELAY / SOURCE';
      else if (node.type === 'ip') header = 'SOURCE IP';
      else if (node.type === 'asn') header = 'NETWORK';
      else if (node.type === 'location') header = 'VERIFIED GEOLOCATION';
      else if (node.type === 'url') header = 'URL PAYLOAD';

      if (node.status === 'unavailable') {
        return `${header}\n[Unavailable]`;
      }

      let val = node.primaryValue || node.label;
      if (val.length > 22) {
        val = val.slice(0, 20) + '...';
      }
      return `${header}\n${val}`;
    };

    const validNodeIds = new Set(graphData.nodes.map((n) => n.id));
    const safeEdges = graphData.edges.filter(
      (e) => validNodeIds.has(e.source) && validNodeIds.has(e.target) && e.source !== e.target
    );

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
          {
            selector: 'node',
            style: {
              'shape': 'round-rectangle',
              'width': 175,
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
              'text-max-width': '160px',
              'line-height': 1.3,
              'padding': '6px',
            },
          },
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
          {
            selector: 'node:selected',
            style: {
              'border-width': 3,
              'border-color': '#f1f5f9',
              'background-color': '#1e232e',
            },
          },
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
          {
            selector: 'edge[?isObserved]',
            style: {
              'line-style': 'solid',
              'line-color': '#64748b',
              'target-arrow-color': '#64748b',
              'width': 2,
            },
          },
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

        activeCy.on('tap', 'node', (evt) => {
          const nodeData = evt.target.data();
          const matchedNode = graphData.nodes.find((n) => n.id === nodeData.id);
          if (matchedNode) {
            setSelectedNode(matchedNode);
            setSelectedEntityId(matchedNode.id);
          }
        });

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
        index="04"
        title="Attack & Infrastructure Path"
        subtitle="Trace the email from the message to the observed relay, source infrastructure, network, and verified geolocation."
      />

      {/* 1. Observed Email Path Bar (Above Graph) */}
      <div className="bg-[#0b0d12] border border-[#1e2430] rounded-lg p-3 overflow-x-auto">
        <div className="text-[10px] uppercase text-[#64748b] font-bold mb-2 flex items-center gap-1.5 font-sans">
          <Layers className="w-3.5 h-3.5 text-[#8b5cf6]" />
          OBSERVED EMAIL PATH:
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
                  <span className="text-[9px] text-[#64748b] font-bold uppercase tracking-wider font-sans">
                    {stage.label}
                  </span>
                  <span className="font-semibold text-xs truncate max-w-[150px]" title={stage.value}>
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
        <div
          className="absolute inset-0 opacity-15 pointer-events-none"
          style={{
            backgroundImage: `radial-gradient(#2a3242 1px, transparent 1px)`,
            backgroundSize: '20px 20px',
          }}
        />

        <div ref={containerRef} className="w-full h-full cursor-grab active:cursor-grabbing" />

        {/* Toolbar */}
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
            <div className="flex items-center justify-between pb-2 border-b border-[#1e2430]">
              <div className="flex items-center space-x-2">
                {React.createElement(getNodeIcon(selectedNode.type), {
                  className: 'w-4 h-4 text-[#8b5cf6]',
                })}
                <span className="text-[10px] text-[#64748b] uppercase tracking-wider font-bold font-sans">
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

            <div className="flex items-center justify-between">
              <span className="text-[10px] text-[#64748b] uppercase font-bold font-sans">
                {selectedNode.type} Observable
              </span>
              {renderStatusBadge(selectedNode.status)}
            </div>

            <div className="space-y-1">
              <div
                className="text-xs text-[#f1f5f9] font-bold break-all bg-[#171b23] p-2.5 rounded border border-[#2a3242]"
                title={selectedNode.primaryValue}
              >
                {selectedNode.primaryValue}
              </div>
            </div>

            {selectedNode.whyItMatters && (
              <div className="bg-[#161324] border border-[#3b2166] p-2.5 rounded text-[11px] text-[#c4b5fd] space-y-1 font-sans">
                <span className="text-[9px] uppercase text-[#a78bfa] font-bold block">
                  WHY THIS MATTERS
                </span>
                <p className="leading-snug">{selectedNode.whyItMatters}</p>
              </div>
            )}

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

            {Object.keys(selectedNode.properties).length > 0 && (
              <div className="space-y-1 pt-1">
                <span className="text-[10px] text-[#64748b] uppercase block font-bold font-sans">
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

            {selectedNode.evidence && selectedNode.evidence.length > 0 && (
              <div className="space-y-1 pt-1">
                <span className="text-[10px] text-[#64748b] uppercase block font-bold font-sans">
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

            {(selectedNode.type === 'ip' || selectedNode.type === 'location' || selectedNode.type === 'relay') && (
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

      {/* 4. Compact "WHAT THIS PATH TELLS US" & "FORENSIC INTERPRETATION" */}
      <div className="bg-[var(--surface-subtle)] border border-[var(--border-subtle)] rounded-lg p-4 space-y-4 font-sans text-xs">
        <div className="space-y-2">
          <div className="flex items-center space-x-2 text-xs font-bold text-[var(--text)] uppercase tracking-wider">
            <Info className="w-4 h-4 text-[var(--identifier)]" />
            <span>WHAT THIS PATH TELLS US</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs bg-[var(--surface)] p-3 rounded border border-[var(--border-subtle)] font-mono">
            <div>
              <span className="text-[10px] text-[var(--text-dim)] uppercase block">Observed source infrastructure</span>
              <span className="font-bold text-[var(--identifier)]">{pathInterpretation.sourceIp || 'No verified candidate'}</span>
            </div>
            <div>
              <span className="text-[10px] text-[var(--text-dim)] uppercase block">Network</span>
              <span className="font-bold text-[var(--text)]">{pathInterpretation.network || 'Not resolved'}</span>
            </div>
            <div>
              <span className="text-[10px] text-[var(--text-dim)] uppercase block">Verified infrastructure location</span>
              <span className="font-bold text-[var(--text)]">{pathInterpretation.location || 'Unavailable'}</span>
            </div>
          </div>
        </div>

        <div className="space-y-1">
          <span className="text-[10px] uppercase font-bold text-[var(--text-dim)] tracking-wider block font-sans">
            FORENSIC INTERPRETATION
          </span>
          <p className="text-[var(--text-muted)] leading-relaxed font-sans">
            {pathInterpretation.summaryParagraph}
          </p>
          <p className="text-[11px] text-[var(--text-dim)] font-mono italic">
            Important: {pathInterpretation.disclaimer}
          </p>
        </div>

        {(pathInterpretation.secondaryReplyTo || pathInterpretation.secondaryUrl) && (
          <div className="pt-2 border-t border-[var(--border-subtle)] space-y-1.5 font-mono text-[11px]">
            <span className="text-[10px] uppercase font-bold text-[var(--text-dim)] font-sans block">Secondary evidence:</span>
            {pathInterpretation.secondaryReplyTo && (
              <div className="flex items-center gap-2 text-[var(--severity-medium)]">
                <span>• Reply-To →</span>
                <span className="font-bold">{pathInterpretation.secondaryReplyTo}</span>
              </div>
            )}
            {pathInterpretation.secondaryUrl && (
              <div className="flex items-center gap-2 text-[var(--severity-critical)]">
                <span>• URL →</span>
                <span className="font-bold truncate max-w-lg">{pathInterpretation.secondaryUrl}</span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* 5. Minimal Legend */}
      <div className="flex items-center justify-end gap-4 text-xs font-mono text-[var(--text-muted)] pt-1 border-t border-[var(--border-subtle)]">
        <div className="flex items-center gap-4 text-[11px]">
          <span className="inline-flex items-center gap-1.5">
            <span className="w-4 h-0.5 bg-[var(--text-muted)]" />
            <span className="text-[var(--text)] font-sans">Observed evidence</span>
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="w-4 border-b border-dashed border-[var(--text-dim)]" />
            <span className="text-[var(--text-muted)] font-sans">External enrichment</span>
          </span>
        </div>
      </div>
    </div>
  );
};
