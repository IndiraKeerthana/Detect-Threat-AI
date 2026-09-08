import React from 'react';
import { Mail, Globe, Link2, Server, Network } from 'lucide-react';

export const PipelineVisual: React.FC = () => {
  const steps = [
    { label: 'EMAIL', desc: 'Headers & Body', icon: Mail },
    { label: 'DOMAIN', desc: 'From & Reply-To', icon: Globe },
    { label: 'URL', desc: 'Normalized Links', icon: Link2 },
    { label: 'IP', desc: 'Relay Origins', icon: Server },
    { label: 'INFRASTRUCTURE', desc: 'ASN & Telemetry', icon: Network },
  ];

  return (
    <div className="w-full bg-[#12151b] border border-[#1e2430] rounded-md p-4">
      <div className="flex items-center justify-between text-[11px] font-mono text-[#64748b] mb-3 px-1">
        <span>DETERMINISTIC & AUTONOMOUS RECONSTRUCTION FLOW</span>
        <span className="text-[#06b6d4]">EVIDENCE CORRELATION</span>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 items-center">
        {steps.map((step, idx) => {
          const Icon = step.icon;
          return (
            <React.Fragment key={step.label}>
              <div className="bg-[#171b23] border border-[#2a3242] rounded p-3 text-left hover:border-[#3e485e] transition-colors">
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-[10px] font-mono text-[#64748b]">0{idx + 1}</span>
                  <Icon className="w-3.5 h-3.5 text-[#94a3b8]" />
                </div>
                <div className="text-xs font-mono font-semibold tracking-wider text-[#f1f5f9]">
                  {step.label}
                </div>
                <div className="text-[10px] text-[#64748b] font-sans truncate mt-0.5">
                  {step.desc}
                </div>
              </div>
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
};
