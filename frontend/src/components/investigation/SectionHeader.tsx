import React from 'react';

interface SectionHeaderProps {
  index?: string | number;
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
    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[var(--border-subtle)] font-sans">
      <div className="flex items-start gap-3">
        {index !== undefined && (
          <div className="w-8 h-8 rounded-full bg-[var(--surface-elevated)] border border-[var(--border-active)] text-[var(--text)] font-mono font-bold text-sm flex items-center justify-center shrink-0 mt-0.5 shadow-xs">
            {index}
          </div>
        )}
        <div className="space-y-0.5">
          <h2 className="text-lg font-bold text-[var(--text)] tracking-tight">
            {title}
          </h2>
          {subtitle && (
            <p className="text-xs text-[var(--text-muted)]">
              {subtitle}
            </p>
          )}
        </div>
      </div>

      {action && (
        <div className="flex items-center space-x-2 shrink-0 self-start sm:self-auto">
          {action}
        </div>
      )}
    </div>
  );
};
