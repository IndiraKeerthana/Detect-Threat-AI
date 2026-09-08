import { Network, GitFork } from 'lucide-react';
import type { EvidenceGraph } from '../../types/investigation';

interface AttackGraphPlaceholderProps {
  graph?: EvidenceGraph | null;
}

export const AttackGraphPlaceholder: React.FC<AttackGraphPlaceholderProps> = ({ graph }) => {
  const nodeCount = graph?.nodes?.length || 5;
  const edgeCount = graph?.edges?.length || 5;

  return (
    <div className="surface-card p-5 border border-[#1e2430] space-y-4">
      <div className="flex items-center justify-between pb-3 border-b border-[#1e2430]">
        <div className="flex items-center space-x-2">
          <Network className="w-4 h-4 text-[#06b6d4]" />
          <h3 className="text-sm font-semibold text-[#f1f5f9] tracking-tight">
            Attack Graph & Observable Topology
          </h3>
        </div>
        <div className="flex items-center space-x-2 text-xs font-mono text-[#64748b]">
          <span>NODES: <strong className="text-[#f1f5f9]">{nodeCount}</strong></span>
          <span>•</span>
          <span>EDGES: <strong className="text-[#f1f5f9]">{edgeCount}</strong></span>
          <span className="px-1.5 py-0.2 rounded bg-[#0c232c] text-[#67e8f9] border border-[#154c5e] text-[10px]">
            STEP 8B ENGINE
          </span>
        </div>
      </div>

      {/* Graph Visual Canvas Placeholder */}
      <div className="relative h-64 w-full bg-[#0a0c10] border border-[#1e2430] rounded-md overflow-hidden flex items-center justify-center p-6">
        {/* Subtle grid pattern background */}
        <div
          className="absolute inset-0 opacity-15"
          style={{
            backgroundImage: `radial-gradient(#3e485e 1px, transparent 1px)`,
            backgroundSize: '20px 20px',
          }}
        />

        {/* Abstract Topology Representation */}
        <div className="relative z-10 w-full max-w-lg flex flex-col items-center justify-between h-full py-2">
          <div className="flex items-center justify-between w-full">
            <div className="px-3 py-1.5 rounded bg-[#171b23] border border-[#2a3242] text-[11px] font-mono text-[#f1f5f9] shadow-sm">
              <span className="text-[#64748b]">EMAIL:</span> 20260908.7B39E
            </div>
            <div className="px-3 py-1.5 rounded bg-[#171b23] border border-[#2a3242] text-[11px] font-mono text-[#fca5a5] shadow-sm">
              <span className="text-[#64748b]">FROM:</span> secure-alerts-update.com
            </div>
          </div>

          <div className="flex items-center justify-center space-x-4 my-2 text-xs font-mono text-[#64748b]">
            <span className="flex items-center gap-1">
              <GitFork className="w-3.5 h-3.5 text-[#06b6d4]" />
              5 Correlated Edges
            </span>
          </div>

          <div className="flex items-center justify-between w-full">
            <div className="px-3 py-1.5 rounded bg-[#171b23] border border-[#2a3242] text-[11px] font-mono text-[#67e8f9] shadow-sm">
              <span className="text-[#64748b]">RELAY IP:</span> 198.51.100.10
            </div>
            <div className="px-3 py-1.5 rounded bg-[#171b23] border border-[#2a3242] text-[11px] font-mono text-[#fca5a5] shadow-sm">
              <span className="text-[#64748b]">PAYLOAD:</span> http://198.51.100.10/verify
            </div>
          </div>
        </div>

        <div className="absolute bottom-2 right-3 text-[10px] font-mono text-[#475569]">
          D3/Cytoscape Canvas Foundation
        </div>
      </div>
    </div>
  );
};
