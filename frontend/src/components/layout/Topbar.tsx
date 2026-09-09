import React from 'react';
import { Search, UserCheck, RefreshCw, Sun, Moon } from 'lucide-react';
import { useTheme } from '../../context/ThemeContext';

interface TopbarProps {
  currentContext: string;
  onRefresh?: () => void;
  isAnalyzing?: boolean;
}

export const Topbar: React.FC<TopbarProps> = ({
  currentContext,
  onRefresh,
  isAnalyzing = false,
}) => {
  const { theme, toggleTheme } = useTheme();

  return (
    <header className="h-14 bg-[var(--surface-subtle)] border-b border-[var(--border-subtle)] px-6 flex items-center justify-between shrink-0 select-none transition-colors">
      {/* Context Breadcrumb */}
      <div className="flex items-center space-x-2 text-xs">
        <span className="font-mono text-[var(--text-dim)]">WORKSTATION</span>
        <span className="text-[var(--border)]">/</span>
        <span className="font-medium text-[var(--text)] tracking-wide">{currentContext}</span>
        {isAnalyzing && (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono badge-ai">
            <RefreshCw className="w-3 h-3 animate-spin text-[var(--ai)]" />
            RUNNING INVESTIGATION...
          </span>
        )}
      </div>

      {/* Global Quick Search */}
      <div className="flex-1 max-w-md mx-8 hidden md:block">
        <div className="relative">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-dim)]" />
          <input
            id="global-search-input"
            type="text"
            placeholder="Search indicators, domains, IPs, message-IDs (Ctrl+K)..."
            className="w-full bg-[var(--surface)] border border-[var(--border-subtle)] hover:border-[var(--border)] focus:border-[var(--border-active)] rounded px-3 py-1.5 pl-9 text-xs text-[var(--text)] placeholder-[var(--text-disabled)] font-mono outline-none transition-colors"
          />
          <kbd className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[9px] font-mono text-[var(--text-dim)] bg-[var(--surface-elevated)] border border-[var(--border-subtle)] px-1.5 py-0.5 rounded">
            Ctrl+K
          </kbd>
        </div>
      </div>

      {/* System Status, Theme Toggle & Analyst Profile */}
      <div className="flex items-center space-x-3">
        {onRefresh && (
          <button
            type="button"
            onClick={onRefresh}
            title="Refresh state"
            className="text-[var(--text-muted)] hover:text-[var(--text)] p-1.5 rounded hover:bg-[var(--surface-elevated)] transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        )}

        {/* Theme Toggle Button */}
        <button
          type="button"
          onClick={toggleTheme}
          title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} theme`}
          aria-label={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} theme`}
          className="p-1.5 rounded bg-[var(--surface)] border border-[var(--border-subtle)] text-[var(--text-muted)] hover:text-[var(--text)] hover:bg-[var(--surface-hover)] transition-colors inline-flex items-center justify-center cursor-pointer"
        >
          {theme === 'dark' ? (
            <Sun className="w-4 h-4 text-[#f59e0b]" />
          ) : (
            <Moon className="w-4 h-4 text-[#38bdf8]" />
          )}
        </button>

        <div className="h-4 w-[1px] bg-[var(--border-subtle)]" />

        {/* Threat Level Global Indicator */}
        <div className="flex items-center space-x-2 text-[11px] font-mono">
          <span className="w-2 h-2 rounded-full bg-[var(--state-pass)]" />
          <span className="text-[var(--text-muted)] hidden lg:inline">ENGINE:</span>
          <span className="text-[var(--text)] font-semibold">ARMED</span>
        </div>

        <div className="h-4 w-[1px] bg-[var(--border-subtle)]" />

        {/* Analyst Identity */}
        <div className="flex items-center space-x-2 bg-[var(--surface)] border border-[var(--border-subtle)] px-2.5 py-1 rounded">
          <UserCheck className="w-3.5 h-3.5 text-[var(--identifier)]" />
          <div className="text-[11px] font-mono text-[var(--text-muted)]">
            <span className="text-[var(--text)] font-medium">ANALYST</span>-01
          </div>
          <span className="text-[9px] font-mono px-1 py-0.2 bg-[var(--surface-elevated)] text-[var(--identifier)] rounded border border-[var(--border-subtle)] font-bold">
            TIER-3
          </span>
        </div>
      </div>
    </header>
  );
};
