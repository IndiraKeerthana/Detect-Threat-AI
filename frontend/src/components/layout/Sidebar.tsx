import React from 'react';
import {
  ShieldCheck,
  Search,
  FolderLock,
  FileSpreadsheet,
  Settings,
  Activity,
  Sparkles,
  X,
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
  mobileOpen?: boolean;
  onCloseMobile?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  apiOnline = true,
  casesCount = 0,
  mobileOpen = false,
  onCloseMobile,
}) => {
  const navItems = [
    { id: 'home' as NavTab, label: 'Check Email', icon: ShieldCheck, badge: 'New' },
    { id: 'investigation' as NavTab, label: 'Active Investigation', icon: Search, badge: 'Live' },
    { id: 'cases' as NavTab, label: 'All Cases', icon: FolderLock, badge: casesCount > 0 ? String(casesCount) : null },
    { id: 'report' as NavTab, label: 'Reports', icon: FileSpreadsheet, badge: null },
    { id: 'settings' as NavTab, label: 'Settings', icon: Settings, badge: null },
  ];

  const handleNavClick = (tab: NavTab) => {
    onSelectTab(tab);
    if (onCloseMobile) onCloseMobile();
  };

  return (
    <>
      {/* Mobile Overlay */}
      {mobileOpen && (
        <div
          onClick={onCloseMobile}
          className="fixed inset-0 bg-slate-900/40 backdrop-blur-xs z-40 lg:hidden"
        />
      )}

      <aside
        className={`fixed lg:static top-0 left-0 z-50 h-screen w-64 shrink-0 bg-[var(--surface-subtle)] border-r border-[var(--border-subtle)] flex flex-col justify-between select-none transition-transform duration-200 ease-in-out ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        {/* Brand Header */}
        <div>
          <div className="px-5 py-5 border-b border-[var(--border-subtle)] flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center text-white shadow-sm">
                <ShieldCheck className="w-5 h-5 text-white" />
              </div>
              <div>
                <div className="text-base font-bold tracking-tight text-[var(--text)] flex items-center gap-1.5 font-sans">
                  DetectThreat
                  <span className="text-[10px] font-mono font-medium px-1.5 py-0.2 bg-[var(--surface-hover)] text-[var(--text-muted)] rounded-full border border-[var(--border-subtle)]">
                    v1.0
                  </span>
                </div>
                <div className="text-[11px] text-[var(--text-muted)] font-sans">
                  Email Safety & Threat Analysis
                </div>
              </div>
            </div>

            {onCloseMobile && (
              <button
                type="button"
                onClick={onCloseMobile}
                className="lg:hidden p-1.5 rounded-lg text-[var(--text-muted)] hover:text-[var(--text)] hover:bg-[var(--surface-hover)]"
              >
                <X className="w-5 h-5" />
              </button>
            )}
          </div>

          {/* Primary Navigation */}
          <nav className="p-3 space-y-1">
            <div className="px-3 py-1.5 text-[10px] font-mono tracking-wider text-[var(--text-dim)] uppercase font-semibold">
              Navigation
            </div>
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => handleNavClick(item.id)}
                  className={`w-full flex items-center justify-between px-3.5 py-2.5 text-xs font-medium rounded-xl transition-all duration-150 cursor-pointer ${
                    isActive
                      ? 'bg-[var(--surface-elevated)] text-[var(--text)] border border-[var(--border)] shadow-xs font-semibold'
                      : 'text-[var(--text-muted)] hover:bg-[var(--surface)] hover:text-[var(--text)] border border-transparent'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <Icon
                      className={`w-4 h-4 ${
                        isActive ? 'text-[var(--identifier)]' : 'text-[var(--text-dim)]'
                      }`}
                    />
                    <span className="font-sans">{item.label}</span>
                  </div>
                  {item.badge && (
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded-full ${
                        isActive
                          ? 'bg-sky-500/10 text-sky-600 dark:text-sky-400 font-bold border border-sky-500/20'
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

          {/* System Capabilities List */}
          <div className="px-5 py-2 space-y-2">
            <div className="text-[10px] font-mono tracking-wider text-[var(--text-dim)] uppercase font-semibold">
              Safety Checks
            </div>
            <div className="space-y-1.5 text-xs text-[var(--text-muted)] font-sans">
              <div className="flex items-center justify-between py-0.5">
                <span className="text-[var(--text-dim)]">Email Security</span>
                <span className="text-[var(--state-pass)] text-[10px] font-mono font-bold">ACTIVE</span>
              </div>
              <div className="flex items-center justify-between py-0.5">
                <span className="text-[var(--text-dim)]">Online Safety</span>
                <span className="text-[var(--state-pass)] text-[10px] font-mono font-bold">ACTIVE</span>
              </div>
              <div className="flex items-center justify-between py-0.5">
                <span className="text-[var(--text-dim)]">Connection Map</span>
                <span className="text-[var(--identifier)] text-[10px] font-mono font-bold">READY</span>
              </div>
              <div className="flex items-center justify-between py-0.5">
                <span className="text-[var(--text-dim)]">AI Investigation</span>
                <span className="text-purple-600 dark:text-purple-400 text-[10px] font-mono font-bold">READY</span>
              </div>
            </div>
          </div>
        </div>

        {/* System Status Footer */}
        <div className="p-3 border-t border-[var(--border-subtle)] bg-[var(--background)] space-y-2">
          <div className="bg-[var(--surface)] border border-[var(--border-subtle)] rounded-xl p-3 space-y-2">
            <div className="flex items-center justify-between text-xs font-sans">
              <span className="flex items-center gap-2 text-[var(--text-muted)]">
                <Activity className="w-3.5 h-3.5 text-[var(--text-dim)]" />
                Backend Status
              </span>
              <span className="flex items-center gap-1.5 text-[10px] font-mono font-bold text-[var(--state-pass)]">
                <span className={`w-2 h-2 rounded-full ${apiOnline ? 'bg-[var(--state-pass)]' : 'bg-[var(--state-fail)]'}`} />
                {apiOnline ? 'ONLINE' : 'OFFLINE'}
              </span>
            </div>

            <div className="flex items-center justify-between text-xs font-sans">
              <span className="flex items-center gap-2 text-[var(--text-muted)]">
                <Sparkles className="w-3.5 h-3.5 text-purple-500" />
                AI Model
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-purple-500/10 text-purple-700 dark:text-purple-300 font-bold border border-purple-500/20">
                Groq AI
              </span>
            </div>
          </div>

          <div className="text-[10px] font-sans text-[var(--text-disabled)] text-center">
            DetectThreatAI • Professional Email Safety
          </div>
        </div>
      </aside>
    </>
  );
};

