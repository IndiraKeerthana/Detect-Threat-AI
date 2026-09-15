import React from 'react';
import { Search, UserCheck, RefreshCw, Sun, Moon, Menu } from 'lucide-react';
import { useTheme } from '../../context/ThemeContext';

interface TopbarProps {
  currentContext: string;
  onRefresh?: () => void;
  isAnalyzing?: boolean;
  onOpenMobile?: () => void;
}

export const Topbar: React.FC<TopbarProps> = ({
  currentContext,
  onRefresh,
  isAnalyzing = false,
  onOpenMobile,
}) => {
  const { theme, toggleTheme } = useTheme();

  return (
    <header className="h-14 bg-[var(--surface-subtle)] border-b border-[var(--border-subtle)] px-4 sm:px-6 flex items-center justify-between shrink-0 select-none transition-colors">
      {/* Context Breadcrumb & Mobile Menu Toggle */}
      <div className="flex items-center space-x-3 text-xs">
        {onOpenMobile && (
          <button
            type="button"
            onClick={onOpenMobile}
            className="lg:hidden p-1.5 rounded-lg text-[var(--text-muted)] hover:text-[var(--text)] hover:bg-[var(--surface-hover)] transition-colors cursor-pointer"
            aria-label="Open Navigation Menu"
          >
            <Menu className="w-5 h-5" />
          </button>
        )}
        <div className="flex items-center space-x-2">
          <span className="font-mono text-[var(--text-dim)] hidden sm:inline">CONSOLE</span>
          <span className="text-[var(--border)] hidden sm:inline">/</span>
          <span className="font-medium text-[var(--text)] tracking-wide font-sans">{currentContext}</span>
        </div>
        {isAnalyzing && (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-mono badge-ai animate-pulse">
            <RefreshCw className="w-3 h-3 animate-spin text-[var(--ai)]" />
            <span>ANALYZING EMAIL...</span>
          </span>
        )}
      </div>

      {/* Global Quick Search */}
      <div className="flex-1 max-w-md mx-4 lg:mx-8 hidden md:block">
        <div className="relative">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-dim)]" />
          <input
            id="global-search-input"
            type="text"
            placeholder="Search email subject, sender, indicators (Ctrl+K)..."
            className="w-full bg-[var(--surface)] border border-[var(--border-subtle)] hover:border-[var(--border)] focus:border-[var(--border-active)] rounded-xl px-3 py-1.5 pl-9 text-xs text-[var(--text)] placeholder-[var(--text-disabled)] font-sans outline-none transition-colors"
          />
          <kbd className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[9px] font-mono text-[var(--text-dim)] bg-[var(--surface-elevated)] border border-[var(--border-subtle)] px-1.5 py-0.5 rounded-md">
            Ctrl+K
          </kbd>
        </div>
      </div>

      {/* System Status, Theme Toggle & User Info */}
      <div className="flex items-center space-x-2 sm:space-x-3">
        {onRefresh && (
          <button
            type="button"
            onClick={onRefresh}
            title="Refresh status"
            className="text-[var(--text-muted)] hover:text-[var(--text)] p-1.5 rounded-lg hover:bg-[var(--surface-elevated)] transition-colors cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        )}

        {/* Theme Toggle Button */}
        <button
          type="button"
          onClick={toggleTheme}
          title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} mode`}
          aria-label={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} mode`}
          className="p-1.5 rounded-xl bg-[var(--surface)] border border-[var(--border-subtle)] text-[var(--text-muted)] hover:text-[var(--text)] hover:bg-[var(--surface-hover)] transition-colors inline-flex items-center justify-center cursor-pointer shadow-xs"
        >
          {theme === 'dark' ? (
            <Sun className="w-4 h-4 text-amber-400" />
          ) : (
            <Moon className="w-4 h-4 text-sky-500" />
          )}
        </button>

        <div className="h-4 w-[1px] bg-[var(--border-subtle)] hidden sm:block" />

        {/* Safety Engine Status Indicator */}
        <div className="hidden sm:flex items-center space-x-2 text-[11px] font-sans">
          <span className="w-2 h-2 rounded-full bg-[var(--state-pass)] animate-pulse" />
          <span className="text-[var(--text-muted)] hidden lg:inline">Safety Engine:</span>
          <span className="text-[var(--text)] font-semibold font-mono">READY</span>
        </div>

        <div className="h-4 w-[1px] bg-[var(--border-subtle)] hidden sm:block" />

        {/* Analyst Identity Pill */}
        <div className="flex items-center space-x-1.5 sm:space-x-2 bg-[var(--surface)] border border-[var(--border-subtle)] px-2.5 py-1 rounded-xl">
          <UserCheck className="w-3.5 h-3.5 text-[var(--identifier)]" />
          <div className="text-[11px] font-sans text-[var(--text-muted)]">
            <span className="text-[var(--text)] font-medium">Analyst</span> Console
          </div>
        </div>
      </div>
    </header>
  );
};

