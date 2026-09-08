import React, { useState, useEffect } from 'react';
import { AppShell } from './components/layout/AppShell';
import type { NavTab } from './components/layout/Sidebar';
import { Home } from './pages/Home';
import { Investigation } from './pages/Investigation';
import { Cases } from './pages/Cases';
import { Report } from './pages/Report';
import { checkBackendHealth } from './services/api';
import { MOCK_INVESTIGATION_DATA } from './data/mockInvestigation';
import type { EmailAnalysisResponse } from './types/investigation';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<NavTab>('home');
  const [investigationData, setInvestigationData] = useState<EmailAnalysisResponse>(MOCK_INVESTIGATION_DATA);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [apiOnline, setApiOnline] = useState<boolean>(true);

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

  const handleInvestigationComplete = (data: EmailAnalysisResponse) => {
    setInvestigationData(data);
    setCurrentTab('investigation');
  };

  const getContextTitle = (): string => {
    switch (currentTab) {
      case 'home':
        return 'OVERVIEW & INTAKE';
      case 'investigation':
        return 'ACTIVE FORENSIC INVESTIGATION';
      case 'cases':
        return 'CASE TRIAGE & AUDIT LOG';
      case 'report':
        return 'EXAMINATION DOSSIER EXPORT';
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
    >
      {currentTab === 'home' && (
        <Home
          onInvestigationComplete={handleInvestigationComplete}
          isAnalyzing={isAnalyzing}
          setIsAnalyzing={setIsAnalyzing}
        />
      )}

      {currentTab === 'investigation' && (
        <Investigation
          data={investigationData}
          onNavigateHome={() => setCurrentTab('home')}
        />
      )}

      {currentTab === 'cases' && (
        <Cases
          onSelectCase={(data) => {
            setInvestigationData(data);
            setCurrentTab('investigation');
          }}
        />
      )}

      {currentTab === 'report' && (
        <Report
          data={investigationData}
          onNavigateHome={() => setCurrentTab('investigation')}
        />
      )}
    </AppShell>
  );
};

export default App;
