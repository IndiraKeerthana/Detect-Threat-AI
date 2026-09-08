import { ArrowRight, ShieldCheck, AlertCircle } from 'lucide-react';
import type { RelayHop } from '../../types/investigation';
import { SectionHeader } from '../investigation/SectionHeader';

interface EvidenceTimelinePlaceholderProps {
  hops?: RelayHop[];
}

export const EvidenceTimelinePlaceholder: React.FC<EvidenceTimelinePlaceholderProps> = ({
  hops = [],
}) => {
  return (
    <div className="surface-card p-6 border border-[#1e2430] space-y-4">
      {/* Section Header */}
      <SectionHeader
        index="06B"
        tag="EVIDENCE TIMELINE"
        title="Chronological Relay Delivery Trace"
        subtitle="Ordered reconstruction of Received headers tracing email transit from external origin to perimeter gateway"
        action={
          <div className="flex items-center space-x-2 text-xs font-mono">
            <span className="text-[#64748b]">TOTAL HOPS: <strong className="text-[#f1f5f9]">{hops.length || 3}</strong></span>
            <span className="px-2 py-0.5 rounded bg-[#171b23] text-[#94a3b8] border border-[#2a3242] text-[10px] font-bold">
              CHRONO RECONSTRUCTED
            </span>
          </div>
        }
      />

      {/* Vertical Chronological Trace */}
      <div className="relative pl-6 space-y-3 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-[#1e2430]">
        {/* Hop 1 */}
        <div className="relative group">
          <div className="absolute -left-6 top-2 w-5 h-5 rounded-full bg-[#12151b] border-2 border-[#8b5cf6] flex items-center justify-center -translate-x-1/2">
            <span className="text-[9px] font-mono font-bold text-[#c4b5fd]">01</span>
          </div>
          <div className="bg-[#12151b] border border-[#1e2430] hover:border-[#2a3242] p-3 rounded-md text-xs font-mono space-y-1.5 transition-colors">
            <div className="flex items-center justify-between">
              <span className="font-bold text-[#f1f5f9] flex items-center gap-1.5">
                HOP #1 // EXTERNAL CLIENT INJECTION
              </span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#171b23] text-[#fcd34d] border border-[#5c3c12]">
                UNTRUSTED SOURCE
              </span>
            </div>
            <div className="text-[11px] text-[#94a3b8] flex items-center gap-1">
              <span>client.origin.example [IP Redacted]</span>
              <ArrowRight className="w-3.5 h-3.5 text-[#64748b]" />
              <span className="text-[#f1f5f9]">ingress.gateway.example</span>
            </div>
            <div className="text-[10px] text-[#64748b]">
              Protocol: ESMTP • Origin Submission
            </div>
          </div>
        </div>

        {/* Hop 2 */}
        <div className="relative group">
          <div className="absolute -left-6 top-2 w-5 h-5 rounded-full bg-[#12151b] border-2 border-[#ef4444] flex items-center justify-center -translate-x-1/2">
            <span className="text-[9px] font-mono font-bold text-[#fca5a5]">02</span>
          </div>
          <div className="bg-[#17121b] border border-[#5c1d24] p-3 rounded-md text-xs font-mono space-y-1.5 transition-colors">
            <div className="flex items-center justify-between">
              <span className="font-bold text-[#fca5a5] flex items-center gap-1.5">
                <AlertCircle className="w-3.5 h-3.5 text-[#ef4444]" />
                HOP #2 // CRITICAL PERIMETER INGRESS ENTRY
              </span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#261114] text-[#fca5a5] border border-[#5c1d24] font-bold">
                PROBABLE RELAY IP
              </span>
            </div>
            <div className="text-[11px] text-[#94a3b8] flex items-center gap-1">
              <span className="text-[#fca5a5] font-bold">ingress.gateway.example [IP Redacted]</span>
              <ArrowRight className="w-3.5 h-3.5 text-[#64748b]" />
              <span className="text-[#67e8f9]">mx1.target.example</span>
            </div>
            <div className="text-[10px] text-[#64748b]">
              Protocol: ESMTP • External public hop before internal boundary
            </div>
          </div>
        </div>

        {/* Hop 3 */}
        <div className="relative group">
          <div className="absolute -left-6 top-2 w-5 h-5 rounded-full bg-[#12151b] border-2 border-[#10b981] flex items-center justify-center -translate-x-1/2">
            <span className="text-[9px] font-mono font-bold text-[#6ee7b7]">03</span>
          </div>
          <div className="bg-[#12151b] border border-[#1e2430] hover:border-[#2a3242] p-3 rounded-md text-xs font-mono space-y-1.5 transition-colors">
            <div className="flex items-center justify-between">
              <span className="font-bold text-[#f1f5f9] flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-[#10b981]" />
                HOP #3 // INTERNAL BOUNDARY HANDOFF
              </span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#0e241b] text-[#6ee7b7] border border-[#164e3b]">
                INTERNAL GATEWAY
              </span>
            </div>
            <div className="text-[11px] text-[#94a3b8] flex items-center gap-1">
              <span>mx1.target.example</span>
              <ArrowRight className="w-3.5 h-3.5 text-[#64748b]" />
              <span className="text-[#f1f5f9]">mail.target.example</span>
            </div>
            <div className="text-[10px] text-[#64748b]">
              Protocol: ESMTP with id 4VxQ8z • Delivered to recipient mailbox
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
