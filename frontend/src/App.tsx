import React, { useState, useEffect } from 'react';
import { ThemeProvider } from './context/ThemeContext';
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

export const AppContent: React.FC = () => {
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

  // Global Keyboard Shortcuts (Ctrl+K focus search, U for Upload, C for Cases)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Do not trigger if typing inside input / textarea
      const target = e.target as HTMLElement;
      if (target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable)) {
        if (e.key === 'Escape') {
          target.blur();
        }
        return;
      }

      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        const searchInput = document.getElementById('global-search-input');
        if (searchInput) {
          searchInput.focus();
        }
      } else if (e.key.toLowerCase() === 'u' && !e.ctrlKey && !e.altKey && !e.metaKey) {
        e.preventDefault();
        setCurrentTab('home');
      } else if (e.key.toLowerCase() === 'c' && !e.ctrlKey && !e.altKey && !e.metaKey) {
        e.preventDefault();
        setCurrentTab('cases');
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
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
        return 'NEW INVESTIGATION • EMAIL INTAKE CONSOLE';
      case 'investigation':
        return activeCase
          ? `ACTIVE INVESTIGATION • ${activeCase.id}`
          : 'ACTIVE FORENSIC INVESTIGATION';
      case 'cases':
        return 'CASE MANAGEMENT & TRIAGE QUEUE';
      case 'report':
        return 'FORENSIC REPORT LIBRARY';
      case 'settings':
        return 'SYSTEM SETTINGS & CONFIGURATION';
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
            <div className="surface-card p-12 text-center max-w-lg mx-auto space-y-4 border border-[var(--border-subtle)] rounded-lg font-mono text-xs">
              <div className="w-12 h-12 rounded bg-[var(--surface-elevated)] border border-[var(--border-subtle)] mx-auto flex items-center justify-center text-[var(--severity-critical)]">
                <FolderLock className="w-6 h-6 text-[var(--severity-critical)]" />
              </div>
              <div className="space-y-1">
                <h2 className="text-sm font-bold tracking-wider text-[var(--text)] uppercase">
                  CASE RECORD NOT FOUND
                </h2>
                <p className="text-xs text-[var(--text-muted)] font-sans">
                  The requested case identifier does not exist or has been purged from the session cache.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setCurrentTab('cases')}
                className="px-4 py-2 rounded bg-[var(--surface-elevated)] hover:bg-[var(--surface-hover)] text-[var(--text)] border border-[var(--border)] text-xs font-mono inline-flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                <span>RETURN TO CASES QUEUE</span>
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
          <Report
            onSelectCase={handleSelectCase}
            onNavigateNewInvestigation={() => setCurrentTab('home')}
          />
        </ErrorBoundary>
      )}

      {currentTab === 'settings' && (
        <ErrorBoundary>
          <div className="surface-card p-8 text-center border border-[var(--border-subtle)] rounded-lg space-y-4 max-w-lg mx-auto my-8 font-mono text-xs">
            <h2 className="text-sm font-bold text-[var(--text)] uppercase tracking-wider">
              SETTINGS & CONFIGURATION REGISTRY
            </h2>
            <p className="text-xs text-[var(--text-muted)] font-sans leading-relaxed">
              Forensic analysis models and API configurations are managed via environment variables.
            </p>
            <div className="flex items-center justify-center gap-3 pt-2">
              <button
                type="button"
                onClick={() => setCurrentTab('home')}
                className="px-3.5 py-2 rounded bg-[var(--surface-elevated)] hover:bg-[var(--surface-hover)] border border-[var(--border)] text-[var(--text)] font-semibold cursor-pointer"
              >
                START NEW INVESTIGATION
              </button>
              <button
                type="button"
                onClick={() => setCurrentTab('cases')}
                className="px-3.5 py-2 rounded bg-[var(--surface)] hover:bg-[var(--surface-elevated)] border border-[var(--border-subtle)] text-[var(--text-muted)] cursor-pointer"
              >
                VIEW CASES QUEUE
              </button>
            </div>
          </div>
        </ErrorBoundary>
      )}
    </AppShell>
  );
};

export const App: React.FC = () => {
  return (
    <ThemeProvider>
      <AppContent />
    </ThemeProvider>
  );
};

export default App;
