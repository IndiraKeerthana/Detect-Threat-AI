import React, { useState } from 'react';
import { Sidebar } from './Sidebar';
import type { NavTab } from './Sidebar';
import { Topbar } from './Topbar';

interface AppShellProps {
  currentTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  contextTitle: string;
  isAnalyzing?: boolean;
  apiOnline?: boolean;
  casesCount?: number;
  children: React.ReactNode;
}

export const AppShell: React.FC<AppShellProps> = ({
  currentTab,
  onSelectTab,
  contextTitle,
  isAnalyzing = false,
  apiOnline = true,
  casesCount,
  children,
}) => {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[var(--background)] text-[var(--text)] transition-colors">
      {/* Sidebar (Desktop & Mobile Drawer) */}
      <Sidebar
        currentTab={currentTab}
        onSelectTab={onSelectTab}
        apiOnline={apiOnline}
        casesCount={casesCount}
        mobileOpen={mobileOpen}
        onCloseMobile={() => setMobileOpen(false)}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 h-full overflow-hidden">
        <Topbar
          currentContext={contextTitle}
          isAnalyzing={isAnalyzing}
          onOpenMobile={() => setMobileOpen(true)}
        />

        {/* Scrollable Workstation Canvas */}
        <main className="flex-1 overflow-y-auto overflow-x-hidden bg-[var(--background)] p-4 sm:p-6 lg:p-8">
          <div className="max-w-7xl mx-auto space-y-6">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
};

