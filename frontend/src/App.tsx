import React, { useState, useEffect } from 'react';
import { AppShell } from './components/layout/AppShell';
import type { NavTab } from './components/layout/Sidebar';
import { Home } from './pages/Home';
import { Investigation } from './pages/Investigation';
import { Cases } from './pages/Cases';
import { Report } from './pages/Report';
import { checkBackendHealth } from './services/api';
import { caseStore, type CaseRecord, type CaseStatus } from './services/caseStore';
import { FolderLock, ArrowLeft } from 'lucide-react';
import { ErrorBoundary } from './components/common/ErrorBoundary';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<NavTab>('cases');
  const [activeCase, setActiveCase] = useState<CaseRecord>(caseStore.getActiveCase());
  const [casesList, setCasesList] = useState<CaseRecord[]>(caseStore.getCases());
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [apiOnline, setApiOnline] = useState<boolean>(true);

  // Subscribe to caseStore changes
  useEffect(() => {
    const unsubscribe = caseStore.subscribe(() => {
      setCasesList(caseStore.getCases());
      setActiveCase(caseStore.getActiveCase());
    });
    return unsubscribe;
  }, []);

  // Check health on load
  useEffect(() => {
    let isMounted = true;
    checkBackendHealth()
      .then((res) => {
        if (isMounted) setApiOnline(res.healthy);
      })
      .catch(() => {
        if (isMounted) setApiOnline(false);
      });
    return () => {
      isMounted = false;
    };
  }, []);

  const handleInvestigationComplete = (data: any) => {
    const newCase = caseStore.createCaseFromAnalysis(data);
    setActiveCase(newCase);
    setCurrentTab('investigation');
  };

  const handleSelectCase = (caseRecord: CaseRecord) => {
    caseStore.setActiveCaseId(caseRecord.id);
    setActiveCase(caseRecord);
    setCurrentTab('investigation');
  };

  const handleStatusChange = (newStatus: CaseStatus) => {
    if (activeCase) {
      caseStore.updateCaseStatus(activeCase.id, newStatus);
      const updated = caseStore.getCaseById(activeCase.id);
      if (updated) {
        setActiveCase(updated);
      }
    }
  };

  const handleViewReport = () => {
    setCurrentTab('report');
  };

  const getContextTitle = (): string => {
    switch (currentTab) {
      case 'home':
        return 'OVERVIEW & INTAKE CONSOLE';
      case 'investigation':
        return activeCase
          ? `ACTIVE INVESTIGATION • ${activeCase.id}`
          : 'ACTIVE FORENSIC INVESTIGATION';
      case 'cases':
        return 'CASE MANAGEMENT & TRIAGE QUEUE';
      case 'report':
        return activeCase
          ? `FORENSIC INTELLIGENCE DOSSIER • ${activeCase.id}`
          : 'FORENSIC INTELLIGENCE REPORT';
      default:
        return 'FORENSIC WORKSTATION';
    }
  };

  return (
    <AppShell
      currentTab={currentTab}
      onSelectTab={setCurrentTab}
      contextTitle={getContextTitle()}
      isAnalyzing={isAnalyzing}
      apiOnline={apiOnline}
      casesCount={casesList.length}
    >
      {currentTab === 'home' && (
        <ErrorBoundary>
          <Home
            onInvestigationComplete={handleInvestigationComplete}
            isAnalyzing={isAnalyzing}
            setIsAnalyzing={setIsAnalyzing}
          />
        </ErrorBoundary>
      )}

      {currentTab === 'investigation' && (
        <ErrorBoundary>
          {activeCase ? (
            <Investigation
              data={activeCase.investigationData}
              caseRecord={activeCase}
              onNavigateHome={() => setCurrentTab('cases')}
              onViewReport={handleViewReport}
              onStatusChange={handleStatusChange}
            />
          ) : (
            /* Operational Error State: Case Record Not Found */
            <div className="surface-card p-12 text-center max-w-lg mx-auto space-y-4 border border-[#2a3242] rounded-lg">
              <div className="w-12 h-12 rounded bg-[#171b23] border border-[#2a3242] mx-auto flex items-center justify-center text-[#8b5cf6]">
                <FolderLock className="w-6 h-6 text-[#ef4444]" />
              </div>
              <div className="space-y-1">
                <h2 className="text-sm font-bold font-mono tracking-wider text-[#f1f5f9] uppercase">
                  CASE RECORD NOT FOUND
                </h2>
                <p className="text-xs text-[#94a3b8] font-sans">
                  The requested case identifier does not exist or has been purged from the session cache.
                </p>
              </div>
              <button
                onClick={() => setCurrentTab('cases')}
                className="px-4 py-2 rounded bg-[#171b23] hover:bg-[#1e232e] text-[#f1f5f9] border border-[#2a3242] text-xs font-mono inline-flex items-center gap-1.5 transition-colors"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                RETURN TO CASES QUEUE
              </button>
            </div>
          )}
        </ErrorBoundary>
      )}

      {currentTab === 'cases' && (
        <ErrorBoundary>
          <Cases onSelectCase={handleSelectCase} />
        </ErrorBoundary>
      )}

      {currentTab === 'report' && (
        <ErrorBoundary>
          {activeCase ? (
            <Report
              data={activeCase.investigationData}
              caseRecord={activeCase}
              onNavigateHome={() => setCurrentTab('investigation')}
            />
          ) : (
            <div className="surface-card p-12 text-center max-w-lg mx-auto space-y-4 border border-[#2a3242] rounded-lg">
              <h2 className="text-sm font-bold font-mono text-[#f1f5f9] uppercase">
                NO ACTIVE DOSSIER SPECIFIED
              </h2>
              <button
                onClick={() => setCurrentTab('cases')}
                className="px-4 py-2 rounded bg-[#171b23] hover:bg-[#1e232e] text-[#f1f5f9] border border-[#2a3242] text-xs font-mono inline-flex items-center gap-1.5"
              >
                SELECT A CASE
              </button>
            </div>
          )}
        </ErrorBoundary>
      )}
    </AppShell>
  );
};

export default App;
