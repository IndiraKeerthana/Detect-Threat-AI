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
  title,
  subtitle,
  action,
}) => {
  return (
    <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-2 pb-3 border-b border-[var(--border-subtle)]">
      <div className="space-y-0.5">
        {index && (
          <div className="text-[var(--ai)] font-mono font-bold text-xs tracking-wider">
            {index}
          </div>
        )}
        <h2 className="text-base font-semibold text-[var(--text)] tracking-tight font-sans">
          {title}
        </h2>
        {subtitle && (
          <p className="text-xs text-[var(--text-muted)] font-sans">
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

