import React from 'react';
import {
  ShieldAlert,
  Search,
  FolderLock,
  FileSpreadsheet,
  Activity,
  TerminalSquare,
  Sparkles,
} from 'lucide-react';

export type NavTab = 'home' | 'investigation' | 'cases' | 'report';

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
  casesCount = 5,
}) => {
  const navItems = [
    { id: 'home' as NavTab, label: 'Overview', icon: ShieldAlert, badge: 'Upload' },
    { id: 'investigation' as NavTab, label: 'Investigations', icon: Search, badge: 'Live' },
    { id: 'cases' as NavTab, label: 'Cases', icon: FolderLock, badge: String(casesCount) },
    { id: 'report' as NavTab, label: 'Reports', icon: FileSpreadsheet, badge: null },
  ];

  return (
    <aside className="w-64 shrink-0 bg-[#0f1217] border-r border-[#1e2430] flex flex-col justify-between h-screen select-none">
      {/* Brand Header */}
      <div>
        <div className="px-5 py-5 border-b border-[#1e2430]">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 rounded bg-[#171b23] border border-[#2a3242] flex items-center justify-center text-[#c4b5fd]">
              <TerminalSquare className="w-4 h-4 text-[#8b5cf6]" />
            </div>
            <div>
              <div className="text-[12px] font-mono tracking-widest text-[#64748b] leading-tight">
                DETECT
              </div>
              <div className="text-sm font-semibold tracking-wider text-[#f1f5f9] flex items-center gap-1.5">
                THREAT AI
                <span className="text-[9px] font-mono font-normal px-1 py-0.2 bg-[#1e232e] text-[#94a3b8] rounded border border-[#2a3242]">
                  v1.0
                </span>
              </div>
            </div>
          </div>
          <div className="mt-2 text-[10px] font-mono text-[#64748b]">
            PS SIH26106 • FORENSICS WORKSTATION
          </div>
        </div>

        {/* Primary Navigation */}
        <nav className="p-3 space-y-1">
          <div className="px-3 py-1.5 text-[10px] font-mono tracking-wider text-[#64748b] uppercase">
            Platform Navigation
          </div>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectTab(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded transition-colors duration-150 ${
                  isActive
                    ? 'bg-[#171b23] text-[#f1f5f9] border border-[#2a3242]'
                    : 'text-[#94a3b8] hover:bg-[#12151b] hover:text-[#f1f5f9] border border-transparent'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <Icon
                    className={`w-4 h-4 ${
                      isActive ? 'text-[#8b5cf6]' : 'text-[#64748b]'
                    }`}
                  />
                  <span>{item.label}</span>
                </div>
                {item.badge && (
                  <span
                    className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                      isActive
                        ? 'bg-[#1e1533] text-[#c4b5fd] border border-[#432474]'
                        : 'bg-[#12151b] text-[#64748b] border border-[#1e2430]'
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
          <div className="border-t border-[#1e2430]" />
        </div>

        {/* Forensic Tools Capabilities */}
        <div className="px-5 py-2">
          <div className="text-[10px] font-mono tracking-wider text-[#64748b] uppercase mb-2">
            Forensic Registry
          </div>
          <div className="space-y-1 text-[11px] font-mono text-[#94a3b8]">
            <div className="flex items-center justify-between py-0.5">
              <span className="text-[#64748b]">DNS / RDAP</span>
              <span className="text-[#10b981] text-[10px]">ACTIVE</span>
            </div>
            <div className="flex items-center justify-between py-0.5">
              <span className="text-[#64748b]">IP TELEMETRY</span>
              <span className="text-[#10b981] text-[10px]">ACTIVE</span>
            </div>
            <div className="flex items-center justify-between py-0.5">
              <span className="text-[#64748b]">EVIDENCE GRAPH</span>
              <span className="text-[#06b6d4] text-[10px]">READY</span>
            </div>
            <div className="flex items-center justify-between py-0.5">
              <span className="text-[#64748b]">AUTH RFC8601</span>
              <span className="text-[#10b981] text-[10px]">PARSING</span>
            </div>
          </div>
        </div>
      </div>

      {/* System Status Footer */}
      <div className="p-3 border-t border-[#1e2430] bg-[#0c0e12] space-y-2">
        <div className="bg-[#12151b] border border-[#1e2430] rounded p-2.5 space-y-2">
          <div className="flex items-center justify-between text-[11px]">
            <span className="flex items-center gap-1.5 text-[#94a3b8]">
              <Activity className="w-3.5 h-3.5 text-[#64748b]" />
              Forensic API
            </span>
            <span className="flex items-center gap-1 text-[10px] font-mono text-[#10b981]">
              <span className={`w-1.5 h-1.5 rounded-full ${apiOnline ? 'bg-[#10b981]' : 'bg-[#ef4444]'}`} />
              {apiOnline ? ':8001' : 'OFFLINE'}
            </span>
          </div>

          <div className="flex items-center justify-between text-[11px]">
            <span className="flex items-center gap-1.5 text-[#94a3b8]">
              <Sparkles className="w-3.5 h-3.5 text-[#8b5cf6]" />
              AI Agent
            </span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#1e1533] border border-[#432474] text-[#c4b5fd]">
              AI AGENT
            </span>
          </div>
        </div>

        <div className="text-[10px] font-mono text-[#475569] text-center">
          INVESTIGATION RUNTIME • BOUNDED
        </div>
      </div>
    </aside>
  );
};
