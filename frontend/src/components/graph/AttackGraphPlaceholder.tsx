import { Network, ArrowUpRight } from 'lucide-react';
import type { EvidenceGraph } from '../../types/investigation';
import { SectionHeader } from '../investigation/SectionHeader';

interface AttackGraphPlaceholderProps {
  graph?: EvidenceGraph | null;
}

export const AttackGraphPlaceholder: React.FC<AttackGraphPlaceholderProps> = ({ graph }) => {
  const nodeCount = graph?.nodes?.length || 5;
  const edgeCount = graph?.edges?.length || 5;

  return (
    <div className="surface-card p-6 border border-[#1e2430] space-y-4">
      {/* Standard Section Header */}
      <SectionHeader
        index="05"
        tag="OBSERVABLE TOPOLOGY"
        title="Attack Graph & Entity Relationships"
        subtitle="Graph representation correlating sender domains, relay ingress points, embedded URLs, and victim targets"
        action={
          <div className="flex items-center space-x-2 text-xs font-mono">
            <span className="text-[#64748b]">NODES: <strong className="text-[#f1f5f9]">{nodeCount}</strong></span>
            <span>•</span>
            <span className="text-[#64748b]">EDGES: <strong className="text-[#f1f5f9]">{edgeCount}</strong></span>
            <span className="px-2 py-0.5 rounded bg-[#0c232c] text-[#67e8f9] border border-[#154c5e] text-[10px] font-bold">
              STEP 8C ENGINE
            </span>
          </div>
        }
      />

      {/* Forensic Graph Blueprint Canvas */}
      <div className="relative h-80 w-full bg-[#08090d] border border-[#1e2430] rounded-lg overflow-hidden flex items-center justify-center p-6 select-none">
        {/* Subtle grid pattern background */}
        <div
          className="absolute inset-0 opacity-20"
          style={{
            backgroundImage: `radial-gradient(#2a3242 1px, transparent 1px)`,
            backgroundSize: '24px 24px',
          }}
        />

        {/* SVG Relationship Connector Lines */}
        <svg className="absolute inset-0 w-full h-full pointer-events-none stroke-[#2a3242]">
          <line x1="20%" y1="30%" x2="50%" y2="50%" strokeWidth="1.5" strokeDasharray="3 3" />
          <line x1="80%" y1="30%" x2="50%" y2="50%" strokeWidth="1.5" strokeDasharray="3 3" />
          <line x1="20%" y1="70%" x2="50%" y2="50%" strokeWidth="1.5" strokeDasharray="3 3" />
          <line x1="80%" y1="70%" x2="50%" y2="50%" strokeWidth="1.5" strokeDasharray="3 3" />
        </svg>

        {/* Abstract Topology Representation Layout */}
        <div className="relative z-10 w-full max-w-2xl h-full flex flex-col justify-between py-2">
          {/* Top Row: Sender Domain + Reply-To Domain */}
          <div className="flex items-center justify-between w-full">
            <div className="px-3 py-2 rounded bg-[#12151b] border border-[#5c1d24] text-xs font-mono text-[#fca5a5] shadow-sm flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[#ef4444]" />
              <div>
                <span className="text-[10px] text-[#64748b] block">FROM DOMAIN</span>
                sender.domain.example
              </div>
            </div>

            <div className="px-3 py-2 rounded bg-[#12151b] border border-[#5c3c12] text-xs font-mono text-[#fcd34d] shadow-sm flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[#f59e0b]" />
              <div>
                <span className="text-[10px] text-[#64748b] block">REPLY-TO REDIRECT</span>
                reply-to.domain.example
              </div>
            </div>
          </div>

          {/* Center Hub: Email Entity */}
          <div className="flex items-center justify-center my-2">
            <div className="px-4 py-2.5 rounded-lg bg-[#151221] border border-[#432474] text-xs font-mono text-[#f1f5f9] shadow-lg flex items-center gap-3">
              <Network className="w-4 h-4 text-[#8b5cf6]" />
              <div>
                <span className="text-[10px] text-[#c4b5fd] block uppercase">ROOT EMAIL ARTIFACT</span>
                <span className="font-semibold text-[#f1f5f9]">MESSAGE-ID-PLACEHOLDER</span>
              </div>
              <span className="px-1.5 py-0.5 rounded bg-[#1e1533] text-[#c4b5fd] text-[10px] font-bold">
                ROOT NODE
              </span>
            </div>
          </div>

          {/* Bottom Row: Relay Origin IP + Bare IP Payload URL */}
          <div className="flex items-center justify-between w-full">
            <div className="px-3 py-2 rounded bg-[#12151b] border border-[#154c5e] text-xs font-mono text-[#67e8f9] shadow-sm flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[#06b6d4]" />
              <div>
                <span className="text-[10px] text-[#64748b] block">RELAY INGRESS IP</span>
                Ingress Relay Host
              </div>
            </div>

            <div className="px-3 py-2 rounded bg-[#12151b] border border-[#5c1d24] text-xs font-mono text-[#fca5a5] shadow-sm flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[#ef4444]" />
              <div>
                <span className="text-[10px] text-[#64748b] block">PAYLOAD URL TARGET</span>
                http://target.payload.example/path
              </div>
            </div>
          </div>
        </div>

        {/* Interactive Engine Reservation Footer */}
        <div className="absolute bottom-2.5 right-4 text-[10px] font-mono text-[#64748b] flex items-center gap-2">
          <span>D3 / Cytoscape Engine slot</span>
          <span className="text-[#3e485e]">•</span>
          <span className="text-[#06b6d4] flex items-center gap-1">
            Active Layout Preview
            <ArrowUpRight className="w-3 h-3" />
          </span>
        </div>
      </div>
    </div>
  );
};
