import React from 'react';
import { Mail, Globe, Link2, MapPin, ShieldCheck } from 'lucide-react';

export const PipelineVisual: React.FC = () => {
  const steps = [
    { label: 'EMAIL HEADER', desc: 'From, To, Subject', icon: Mail },
    { label: 'SECURITY CHECKS', desc: 'SPF, DKIM, DMARC Seals', icon: ShieldCheck },
    { label: 'SENDER LOCATION', desc: 'IP & Origin Country', icon: MapPin },
    { label: 'LINK INSPECTION', desc: 'Links & Attachments', icon: Link2 },
    { label: 'SAFETY VERDICT', desc: 'Risk Rating & Reasons', icon: Globe },
  ];

  return (
    <div className="w-full bg-[var(--surface-subtle)] border border-[var(--border-subtle)] rounded-xl p-4 font-sans">
      <div className="flex items-center justify-between text-xs text-[var(--text-dim)] mb-3 px-1">
        <span className="font-semibold uppercase text-[11px] tracking-wider">How DetectThreat Protects You</span>
        <span className="text-[var(--identifier)] font-mono text-[11px]">AUTOMATED CHECK FLOW</span>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 items-center">
        {steps.map((step, idx) => {
          const Icon = step.icon;
          return (
            <div
              key={step.label}
              className="bg-[var(--surface)] border border-[var(--border-subtle)] rounded-lg p-3 text-left hover:border-[var(--border)] transition-colors"
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-[10px] font-mono text-[var(--text-dim)] font-bold">0{idx + 1}</span>
                <Icon className="w-4 h-4 text-[var(--identifier)]" />
              </div>
              <div className="text-xs font-semibold text-[var(--text)] tracking-tight">
                {step.label}
              </div>
              <div className="text-[11px] text-[var(--text-muted)] truncate mt-0.5">
                {step.desc}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
