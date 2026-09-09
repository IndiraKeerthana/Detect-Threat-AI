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
    <div className="w-full bg-[var(--surface-subtle)] border border-[var(--border-subtle)] rounded-md p-4">
      <div className="flex items-center justify-between text-[11px] font-mono text-[var(--text-dim)] mb-3 px-1">
        <span>DETERMINISTIC & AUTONOMOUS RECONSTRUCTION FLOW</span>
        <span className="text-[var(--identifier)]">EVIDENCE CORRELATION</span>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 items-center">
        {steps.map((step, idx) => {
          const Icon = step.icon;
          return (
            <React.Fragment key={step.label}>
              <div className="bg-[var(--surface)] border border-[var(--border-subtle)] rounded p-3 text-left hover:border-[var(--border)] transition-colors">
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-[10px] font-mono text-[var(--text-dim)]">0{idx + 1}</span>
                  <Icon className="w-3.5 h-3.5 text-[var(--text-muted)]" />
                </div>
                <div className="text-xs font-mono font-semibold tracking-wider text-[var(--text)]">
                  {step.label}
                </div>
                <div className="text-[10px] text-[var(--text-muted)] font-sans truncate mt-0.5">
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
