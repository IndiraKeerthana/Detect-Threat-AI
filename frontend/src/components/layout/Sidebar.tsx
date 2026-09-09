import React from 'react';
import {
  PlusCircle,
  Search,
  FolderLock,
  FileSpreadsheet,
  Settings,
  Activity,
  TerminalSquare,
  Sparkles,
} from 'lucide-react';

export type NavTab =
  | 'home'
  | 'investigation'
  | 'cases'
  | 'report'
  | 'settings';

interface SidebarProps {
  currentTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  apiOnline?: boolean;
  casesCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  apiOnline = true,
  casesCount = 0,
}) => {
  const navItems = [
    { id: 'home' as NavTab, label: 'New Investigation', icon: PlusCircle, badge: 'Upload' },
    { id: 'investigation' as NavTab, label: 'Investigations', icon: Search, badge: 'Live' },
    { id: 'cases' as NavTab, label: 'Cases', icon: FolderLock, badge: String(casesCount) },
    { id: 'report' as NavTab, label: 'Reports', icon: FileSpreadsheet, badge: null },
    { id: 'settings' as NavTab, label: 'Settings', icon: Settings, badge: null },
  ];

  return (
    <aside className="w-64 shrink-0 bg-[var(--surface-subtle)] border-r border-[var(--border-subtle)] flex flex-col justify-between h-screen select-none transition-colors">
      {/* Brand Header */}
      <div>
        <div className="px-5 py-5 border-b border-[var(--border-subtle)]">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 rounded bg-[var(--surface-elevated)] border border-[var(--border)] flex items-center justify-center text-[var(--text)]">
              <TerminalSquare className="w-4 h-4 text-[var(--text)]" />
            </div>
            <div>
              <div className="text-[12px] font-mono tracking-widest text-[var(--text-dim)] leading-tight">
                DETECT
              </div>
              <div className="text-sm font-semibold tracking-wider text-[var(--text)] flex items-center gap-1.5">
                THREAT AI
                <span className="text-[9px] font-mono font-normal px-1 py-0.2 bg-[var(--surface-hover)] text-[var(--text-muted)] rounded border border-[var(--border-subtle)]">
                  v1.0
                </span>
              </div>
            </div>
          </div>
          <div className="mt-2 text-[10px] font-mono text-[var(--text-dim)]">
            PS SIH26106 • FORENSICS WORKSTATION
          </div>
        </div>

        {/* Primary Navigation */}
        <nav className="p-3 space-y-1">
          <div className="px-3 py-1.5 text-[10px] font-mono tracking-wider text-[var(--text-dim)] uppercase">
            Platform Navigation
          </div>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => onSelectTab(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded transition-colors duration-150 cursor-pointer ${
                  isActive
                    ? 'bg-[var(--surface-elevated)] text-[var(--text)] border border-[var(--border)] shadow-sm'
                    : 'text-[var(--text-muted)] hover:bg-[var(--surface)] hover:text-[var(--text)] border border-transparent'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <Icon
                    className={`w-4 h-4 ${
                      isActive ? 'text-[var(--text)]' : 'text-[var(--text-dim)]'
                    }`}
                  />
                  <span>{item.label}</span>
                </div>
                {item.badge && (
                  <span
                    className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                      isActive
                        ? 'bg-[var(--surface-hover)] text-[var(--text)] border border-[var(--border-subtle)] font-bold'
                        : 'bg-[var(--surface)] text-[var(--text-dim)] border border-[var(--border-subtle)]'
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        {/* Section Divider */}
        <div className="px-5 py-2">
          <div className="border-t border-[var(--border-subtle)]" />
        </div>

        {/* Forensic Tools Capabilities */}
        <div className="px-5 py-2">
          <div className="text-[10px] font-mono tracking-wider text-[var(--text-dim)] uppercase mb-2">
            Forensic Registry
          </div>
          <div className="space-y-1 text-[11px] font-mono text-[var(--text-muted)]">
            <div className="flex items-center justify-between py-0.5">
              <span className="text-[var(--text-dim)]">DNS / RDAP</span>
              <span className="text-[var(--state-pass)] text-[10px] font-bold">ACTIVE</span>
            </div>
            <div className="flex items-center justify-between py-0.5">
              <span className="text-[var(--text-dim)]">IP TELEMETRY</span>
              <span className="text-[var(--state-pass)] text-[10px] font-bold">ACTIVE</span>
            </div>
            <div className="flex items-center justify-between py-0.5">
              <span className="text-[var(--text-dim)]">EVIDENCE GRAPH</span>
              <span className="text-[var(--identifier)] text-[10px] font-bold">READY</span>
            </div>
            <div className="flex items-center justify-between py-0.5">
              <span className="text-[var(--text-dim)]">AUTH RFC8601</span>
              <span className="text-[var(--state-pass)] text-[10px] font-bold">PARSING</span>
            </div>
          </div>
        </div>
      </div>

      {/* System Status Footer */}
      <div className="p-3 border-t border-[var(--border-subtle)] bg-[var(--background)] space-y-2">
        <div className="bg-[var(--surface)] border border-[var(--border-subtle)] rounded p-2.5 space-y-2">
          <div className="flex items-center justify-between text-[11px]">
            <span className="flex items-center gap-1.5 text-[var(--text-muted)]">
              <Activity className="w-3.5 h-3.5 text-[var(--text-dim)]" />
              Forensic API
            </span>
            <span className="flex items-center gap-1 text-[10px] font-mono font-bold text-[var(--state-pass)]">
              <span className={`w-1.5 h-1.5 rounded-full ${apiOnline ? 'bg-[var(--state-pass)]' : 'bg-[var(--state-fail)]'}`} />
              {apiOnline ? ':8001' : 'OFFLINE'}
            </span>
          </div>

          <div className="flex items-center justify-between text-[11px]">
            <span className="flex items-center gap-1.5 text-[var(--text-muted)]">
              <Sparkles className="w-3.5 h-3.5 text-[var(--ai)]" />
              AI Agent
            </span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded badge-ai font-bold">
              Groq (LLaMA-3)
            </span>
          </div>
        </div>

        <div className="text-[10px] font-mono text-[var(--text-disabled)] text-center">
          INVESTIGATION RUNTIME • BOUNDED
        </div>
      </div>
    </aside>
  );
};
