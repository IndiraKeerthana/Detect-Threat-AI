import React from 'react';
import { Sidebar } from './Sidebar';
import type { NavTab } from './Sidebar';
import { Topbar } from './Topbar';

interface AppShellProps {
  currentTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  contextTitle: string;
  isAnalyzing?: boolean;
  apiOnline?: boolean;
  children: React.ReactNode;
}

export const AppShell: React.FC<AppShellProps> = ({
  currentTab,
  onSelectTab,
  contextTitle,
  isAnalyzing = false,
  apiOnline = true,
  children,
}) => {
  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#0c0e12] text-[#f1f5f9]">
      {/* Fixed Left Sidebar */}
      <Sidebar currentTab={currentTab} onSelectTab={onSelectTab} apiOnline={apiOnline} />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 h-full overflow-hidden">
        <Topbar currentContext={contextTitle} isAnalyzing={isAnalyzing} />
        
        {/* Scrollable Workstation Canvas */}
        <main className="flex-1 overflow-y-auto overflow-x-hidden bg-[#0c0e12] p-6 lg:p-8">
          <div className="max-w-7xl mx-auto space-y-6">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
};
