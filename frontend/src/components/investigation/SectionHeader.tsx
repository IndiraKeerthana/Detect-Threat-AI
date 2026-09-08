import React from 'react';

interface SectionHeaderProps {
  index?: string;
  tag?: string;
  title: string;
  subtitle?: string;
  action?: React.ReactNode;
}

export const SectionHeader: React.FC<SectionHeaderProps> = ({
  index,
  tag,
  title,
  subtitle,
  action,
}) => {
  return (
    <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-2 pb-3 border-b border-[#1e2430]">
      <div className="space-y-0.5">
        <div className="flex items-center space-x-2 text-[10px] font-mono tracking-wider text-[#64748b] uppercase">
          {index && <span className="text-[#8b5cf6] font-semibold">{index}</span>}
          {index && tag && <span>//</span>}
          {tag && <span>{tag}</span>}
        </div>
        <h2 className="text-base font-semibold text-[#f1f5f9] tracking-tight">
          {title}
        </h2>
        {subtitle && (
          <p className="text-xs text-[#94a3b8] font-sans">
            {subtitle}
          </p>
        )}
      </div>

      {action && (
        <div className="flex items-center space-x-2 shrink-0">
          {action}
        </div>
      )}
    </div>
  );
};
