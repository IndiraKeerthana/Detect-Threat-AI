import React from 'react';

interface ReportSectionProps {
  index: string;
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}

export const ReportSection: React.FC<ReportSectionProps> = ({
  index,
  title,
  subtitle,
  children,
}) => {
  return (
    <section className="surface-card p-6 border border-[#1e2430] space-y-4">
      <div className="border-b border-[#1e2430] pb-2.5">
        <div className="flex items-center space-x-2">
          <span className="text-xs font-mono text-[#8b5cf6] font-bold">
            [{index}]
          </span>
          <h2 className="text-sm font-semibold tracking-tight text-[#f1f5f9] uppercase">
            {title}
          </h2>
        </div>
        {subtitle && (
          <p className="text-[11px] font-mono text-[#64748b] mt-0.5">
            {subtitle}
          </p>
        )}
      </div>

      <div className="pt-1">{children}</div>
    </section>
  );
};
