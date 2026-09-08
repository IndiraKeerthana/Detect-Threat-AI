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
} from 'lucide-react';
import type { EmailAnalysisResponse } from '../../types/investigation';
import { normalizeGraphData } from '../../services/investigationAdapter';
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

  // Normalize data using the investigation adapter
  const graphData = useMemo(() => normalizeGraphData(data), [data]);

  // Cytoscape initialization & updates
  useEffect(() => {
    if (!containerRef.current) return;

    // Convert normalized nodes to Cytoscape elements
    const elements: cytoscape.ElementDefinition[] = [
      ...graphData.nodes.map((node) => ({
        data: {
          id: node.id,
          label: node.label.length > 28 ? node.label.slice(0, 25) + '...' : node.label,
          fullLabel: node.label,
          type: node.type,
          primaryValue: node.primaryValue,
          secondaryMeta: node.secondaryMeta,
          severity: node.severity,
          source: node.source,
          confidence: node.confidence,
          properties: node.properties,
          evidence: node.evidence,
        },
      })),
      ...graphData.edges.map((edge) => ({
        data: {
          id: edge.id,
          source: edge.source,
          target: edge.target,
          label: edge.label,
          relationship: edge.relationship,
          confidence: edge.confidence,
          evidence: edge.evidence,
        },
      })),
    ];

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      boxSelectionEnabled: false,
      autounselectify: false,
      minZoom: 0.3,
      maxZoom: 2.5,
      style: [
        // Base Node Style
        {
          selector: 'node',
          style: {
            'shape': 'round-rectangle',
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
            'text-max-width': '140px',
            'padding': '10px',
            'width': 'label',
            'height': '38px',
          },
        },
        // Semantic Node Border Themes
        {
          selector: 'node[type = "email"]',
          style: {
            'border-color': '#8b5cf6',
            'background-color': '#161224',
            'color': '#f1f5f9',
          },
        },
        {
          selector: 'node[type = "domain"]',
          style: {
            'border-color': '#f59e0b',
            'background-color': '#1f190e',
            'color': '#fcd34d',
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
            'target-arrow-color': '#2a3242',
            'line-color': '#2a3242',
            'width': 1.5,
            'arrow-scale': 0.8,
            'label': 'data(label)',
            'font-family': 'JetBrains Mono, monospace',
            'font-size': '8px',
            'color': '#64748b',
            'text-rotation': 'autorotate',
            'text-margin-y': -8,
            'text-background-opacity': 0.85,
            'text-background-color': '#0c0e12',
            'text-background-padding': '2px',
          },
        },
        // Active / Connected Edge Highlight
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
        name: 'cose',
        animate: false,
        nodeDimensionsIncludeLabels: true,
        fit: true,
        padding: 40,
        nodeRepulsion: () => 350000,
        idealEdgeLength: () => 120,
        edgeElasticity: () => 100,
        gravity: 40,
        numIter: 1000,
      },
    });

    // Handle node selection events
    cy.on('tap', 'node', (evt) => {
      const nodeData = evt.target.data();
      const matchedNode = graphData.nodes.find((n) => n.id === nodeData.id);
      if (matchedNode) {
        setSelectedNode(matchedNode);
        setSelectedEntityId(matchedNode.id);
      }
    });

    // Deselect when tapping on background
    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        setSelectedNode(null);
        setSelectedEntityId(null);
      }
    });

    cyRef.current = cy;

    return () => {
      cy.destroy();
    };
  }, [graphData, setSelectedEntityId]);

  // External selection synchronization from Timeline / Context
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
          zoom: Math.max(cy.zoom(), 1.0),
        });
        const matched = graphData.nodes.find((n) => n.id === selectedEntityId);
        if (matched) {
          setSelectedNode(matched);
        }
      }
    }
  }, [selectedEntityId, graphData.nodes]);

  // Controls actions
  const handleFit = () => {
    cyRef.current?.fit(undefined, 35);
  };

  const handleReset = () => {
    if (!cyRef.current) return;
    cyRef.current
      .layout({
        name: 'cose',
        animate: true,
        animationDuration: 400,
        padding: 40,
        nodeRepulsion: () => 350000,
        idealEdgeLength: () => 120,
      })
      .run();
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

  return (
    <div className="surface-card p-6 border border-[#1e2430] space-y-4 relative">
      {/* Section Header */}
      <SectionHeader
        index="05"
        tag="OBSERVABLE TOPOLOGY"
        title="Interactive Attack & Infrastructure Graph"
        subtitle="Forensic relationship graph mapping email root, senders, origin relays, bare-IP links, and BGP routing"
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
              CYTOSCAPE COSE
            </span>
          </div>
        }
      />

      {/* Main Graph Canvas Container */}
      <div className="relative w-full h-[460px] bg-[#08090d] border border-[#1e2430] rounded-lg overflow-hidden select-none">
        {/* Subtle grid pattern background */}
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
            title="Redistribute layout"
            aria-label="Reset layout"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Contextual Side Inspector / Detail Panel */}
        {selectedNode && (
          <div className="absolute top-3 left-3 bottom-3 w-80 max-w-[calc(100%-24px)] bg-[#0f1217]/95 backdrop-blur-md border border-[#2a3242] rounded-lg p-4 z-20 shadow-2xl overflow-y-auto space-y-3 font-mono text-xs animate-in fade-in duration-200">
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

            {/* Entity Identification */}
            <div className="space-y-1">
              <span className="text-[10px] text-[#64748b] uppercase block">
                {selectedNode.type} Observable
              </span>
              <div
                className="text-xs text-[#f1f5f9] font-bold break-all bg-[#171b23] p-2 rounded border border-[#2a3242]"
                title={selectedNode.primaryValue}
              >
                {selectedNode.primaryValue}
              </div>
            </div>

            {/* Metadata Fields */}
            <div className="space-y-1.5 text-[11px]">
              <div className="flex justify-between py-1 border-b border-[#1e2430]">
                <span className="text-[#64748b]">Source:</span>
                <span className="text-[#94a3b8] text-right truncate max-w-[150px]" title={selectedNode.source}>
                  {selectedNode.source}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-[#1e2430]">
                <span className="text-[#64748b]">Confidence:</span>
                <span className="text-[#10b981] font-semibold uppercase">
                  {selectedNode.confidence}
                </span>
              </div>
              {selectedNode.secondaryMeta && (
                <div className="flex justify-between py-1 border-b border-[#1e2430]">
                  <span className="text-[#64748b]">Role / Note:</span>
                  <span className="text-[#c4b5fd] text-right">{selectedNode.secondaryMeta}</span>
                </div>
              )}
            </div>

            {/* Properties */}
            {Object.keys(selectedNode.properties).length > 0 && (
              <div className="space-y-1 pt-1">
                <span className="text-[10px] text-[#64748b] uppercase block">
                  PROPERTIES & ATTRIBUTES
                </span>
                <div className="bg-[#0a0c10] border border-[#1e2430] p-2 rounded space-y-1 text-[10px]">
                  {Object.entries(selectedNode.properties)
                    .slice(0, 6)
                    .map(([k, v]) => (
                      <div key={k} className="flex justify-between gap-2">
                        <span className="text-[#64748b] truncate">{k}:</span>
                        <span className="text-[#f1f5f9] truncate max-w-[140px]" title={String(v)}>
                          {String(v)}
                        </span>
                      </div>
                    ))}
                </div>
              </div>
            )}

            {/* Evidence Chips */}
            {selectedNode.evidence && selectedNode.evidence.length > 0 && (
              <div className="space-y-1 pt-1">
                <span className="text-[10px] text-[#64748b] uppercase block">
                  SUPPORTING EVIDENCE
                </span>
                <div className="space-y-1">
                  {selectedNode.evidence.map((ev, i) => (
                    <div
                      key={i}
                      className="text-[10px] text-[#67e8f9] bg-[#0c232c] border border-[#154c5e] px-2 py-0.5 rounded"
                    >
                      • {ev}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Action buttons (e.g. Locate on Map) */}
            {(selectedNode.type === 'ip' || selectedNode.type === 'location') && (
              <div className="pt-2">
                <button
                  type="button"
                  onClick={() => focusMap()}
                  className="w-full py-1.5 px-2.5 rounded bg-[#0c232c] hover:bg-[#154c5e] text-[#67e8f9] border border-[#154c5e] text-[11px] font-mono flex items-center justify-center gap-1.5 transition-colors"
                >
                  <MapPin className="w-3.5 h-3.5" />
                  LOCATE IN GEOLOCATION MAP
                </button>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Compact Topology Legend */}
      <div className="flex flex-wrap items-center justify-between gap-3 text-xs font-mono text-[#64748b] pt-1">
        <div className="flex items-center space-x-2">
          <span className="text-[10px] uppercase font-bold text-[#94a3b8]">TOPOLOGY ENTITIES:</span>
        </div>

        <div className="flex flex-wrap items-center gap-3 text-[11px]">
          <span className="inline-flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-[#161224] border border-[#8b5cf6]" />
            <span className="text-[#f1f5f9]">Email</span>
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-[#1f190e] border border-[#f59e0b]" />
            <span className="text-[#fcd34d]">Domain</span>
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
            <span className="text-[#94a3b8]">ASN</span>
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-[#0c2118] border border-[#10b981]" />
            <span className="text-[#6ee7b7]">Location</span>
          </span>
        </div>
      </div>
    </div>
  );
};
