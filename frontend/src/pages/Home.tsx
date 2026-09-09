import React, { useState, useRef, useEffect } from 'react';
import { FileUpload } from '../components/upload/FileUpload';
import { PipelineVisual } from '../components/upload/PipelineVisual';
import { analyzeEmail } from '../services/api';
import { MOCK_INVESTIGATION_DATA } from '../data/mockInvestigation';
import type { EmailAnalysisResponse } from '../types/investigation';
import { caseStore, type CaseRecord } from '../services/caseStore';
import { Activity, ArrowUpRight } from 'lucide-react';

interface HomeProps {
  onInvestigationComplete: (data: EmailAnalysisResponse) => void;
  isAnalyzing: boolean;
  setIsAnalyzing: (state: boolean) => void;
}

export const Home: React.FC<HomeProps> = ({
  onInvestigationComplete,
  isAnalyzing,
  setIsAnalyzing,
}) => {
  const [error, setError] = useState<string | null>(null);
  const [completedCaseId, setCompletedCaseId] = useState<string | null>(null);
  const [cases, setCases] = useState<CaseRecord[]>(() => caseStore.getCases());
  const abortControllerRef = useRef<AbortController | null>(null);

  useEffect(() => {
    const unsub = caseStore.subscribe(() => {
      setCases(caseStore.getCases());
    });
    return unsub;
  }, []);

  // Clean up in-flight requests on unmount
  useEffect(() => {
    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, []);

  const handleAnalyze = async (file: File) => {
    setIsAnalyzing(true);
    setError(null);
    setCompletedCaseId(null);
    const controller = new AbortController();
    abortControllerRef.current = controller;

    try {
      const result = await analyzeEmail(file, { signal: controller.signal });
      const newCase = caseStore.createCaseFromAnalysis(result);
      setCompletedCaseId(newCase.id);
      onInvestigationComplete(result);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Analysis failed. Please check backend connection and retry.';
      setError(message);
    } finally {
      abortControllerRef.current = null;
      setIsAnalyzing(false);
    }
  };

  const handleLoadMock = () => {
    setError(null);
    setCompletedCaseId(null);
    setIsAnalyzing(true);
    setTimeout(() => {
      setIsAnalyzing(false);
      const newCase = caseStore.createCaseFromAnalysis(MOCK_INVESTIGATION_DATA);
      setCompletedCaseId(newCase.id);
      onInvestigationComplete(MOCK_INVESTIGATION_DATA);
    }, 400);
  };

  // Build real-data sparkline metrics from caseStore
  const recentScores = cases.slice(0, 10).map((c) => c.riskScore);
  const maxScore = Math.max(...recentScores, 100);

  return (
    <div className="space-y-8 max-w-5xl mx-auto py-4">
      {/* Hero Headline Section */}
      <div className="space-y-3">
        <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded bg-[var(--surface-elevated)] border border-[var(--border-subtle)] text-[11px] font-mono text-[var(--text-muted)] uppercase tracking-wider">
          <span className="w-1.5 h-1.5 rounded-full bg-[var(--ai)]" />
          NEW INVESTIGATION INTAKE CONSOLE
        </div>

        <h1 className="text-3xl sm:text-4xl font-bold tracking-tight text-[var(--text)] leading-[1.1] font-sans uppercase">
          New Investigation
        </h1>

        <p className="text-sm md:text-base text-[var(--text-muted)] max-w-2xl leading-relaxed font-sans">
          Upload an email (.eml) to begin forensic analysis. Combines deterministic RFC parsing, relay reconstruction, and multi-turn autonomous AI tool execution.
        </p>
      </div>

      {/* Post-Analysis Case Saved Confirmation Box */}
      {completedCaseId && (
        <div className="p-4 bg-[var(--surface-elevated)] border border-[var(--state-pass)] rounded-lg flex items-center justify-between gap-4 font-mono text-xs">
          <div className="flex items-center space-x-3">
            <span className="w-2 h-2 rounded-full bg-[var(--state-pass)]" />
            <div>
              <span className="text-[var(--text-muted)]">CASE SAVED: </span>
              <strong className="text-[var(--text)]">{completedCaseId}</strong>
              <span className="text-[var(--text-dim)] text-[10px] ml-2">Persisted to case registry</span>
            </div>
          </div>
          <button
            type="button"
            onClick={() => {
              const matched = caseStore.getCaseById(completedCaseId);
              if (matched) {
                caseStore.setActiveCaseId(matched.id);
              }
            }}
            className="px-3 py-1.5 rounded bg-[var(--surface)] hover:bg-[var(--surface-hover)] text-[var(--text)] border border-[var(--border-subtle)] text-xs font-bold inline-flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            <span>VIEW CASE</span>
            <ArrowUpRight className="w-3.5 h-3.5 text-[var(--identifier)]" />
          </button>
        </div>
      )}

      {/* Upload Experience */}
      <div className="surface-card p-6 border border-[var(--border-subtle)]">
        <FileUpload
          onAnalyze={handleAnalyze}
          onLoadMock={handleLoadMock}
          isAnalyzing={isAnalyzing}
          error={error}
        />
      </div>

      {/* Dashboard Real-Data Mini Sparkline & Stats Row */}
      <div className="surface-card p-4 border border-[var(--border-subtle)] space-y-3 font-mono">
        <div className="flex items-center justify-between text-xs text-[var(--text-dim)] pb-2 border-b border-[var(--border-subtle)]">
          <span className="flex items-center gap-1.5 font-bold uppercase tracking-wider">
            <Activity className="w-3.5 h-3.5 text-[var(--identifier)]" />
            Real case volume & risk trend ({cases.length} stored cases)
          </span>
          <span className="text-[10px]">REAL PERSISTED METRICS ONLY</span>
        </div>

        {recentScores.length > 0 ? (
          <div className="flex items-center gap-4 pt-1">
            {/* SVG Sparkline */}
            <div className="flex-1 h-12 flex items-end gap-1.5 pt-2">
              {recentScores.map((score, idx) => {
                const heightPct = Math.max((score / maxScore) * 100, 10);
                let barColor = 'bg-[var(--state-pass)]';
                if (score >= 70) barColor = 'bg-[var(--severity-critical)]';
                else if (score >= 40) barColor = 'bg-[var(--severity-medium)]';

                return (
                  <div key={idx} className="flex-1 flex flex-col items-center gap-1 group">
                    <div
                      className={`w-full ${barColor} rounded-t transition-all group-hover:opacity-80`}
                      style={{ height: `${heightPct}%` }}
                      title={`Case Score: ${score}/100`}
                    />
                  </div>
                );
              })}
            </div>

            <div className="text-right text-xs shrink-0 border-l border-[var(--border-subtle)] pl-4">
              <div className="text-[10px] text-[var(--text-dim)]">AVERAGE SCORE</div>
              <div className="text-lg font-bold text-[var(--text)]">
                {Math.round(recentScores.reduce((a, b) => a + b, 0) / recentScores.length)}/100
              </div>
            </div>
          </div>
        ) : (
          <div className="text-center text-xs text-[var(--text-dim)] py-2">
            No completed cases recorded in local persistence yet.
          </div>
        )}
      </div>

      {/* Abstract Investigation Network Visual */}
      <div className="space-y-3">
        <PipelineVisual />
      </div>

      {/* System Specifications Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
        <div className="bg-[var(--surface-subtle)] border border-[var(--border-subtle)] p-3.5 rounded space-y-1">
          <div className="text-[10px] text-[var(--text-dim)] uppercase">SPEC 01 • DETERMINISTIC</div>
          <div className="text-[var(--text)] font-medium font-sans">RFC 8601 & Hop Analysis</div>
          <p className="text-[11px] text-[var(--text-muted)] font-sans">
            Strict SPF/DKIM/DMARC matrix validation and perimeter relay hop identification.
          </p>
        </div>

        <div className="bg-[var(--surface-subtle)] border border-[var(--border-subtle)] p-3.5 rounded space-y-1">
          <div className="text-[10px] text-[var(--text-dim)] uppercase">SPEC 02 • TELEMETRY</div>
          <div className="text-[var(--text)] font-medium font-sans">Reputation & DNS/RDAP</div>
          <p className="text-[11px] text-[var(--text-muted)] font-sans">
            AbuseIPDB and VirusTotal live telemetry normalized to evidence graph nodes.
          </p>
        </div>

        <div className="bg-[var(--surface-subtle)] border border-[var(--border-subtle)] p-3.5 rounded space-y-1">
          <div className="text-[10px] text-[var(--text-dim)] uppercase">SPEC 03 • AI AGENT</div>
          <div className="text-[var(--text)] font-medium font-sans">Groq Multi-Turn Tool Loop</div>
          <p className="text-[11px] text-[var(--text-muted)] font-sans">
            Bounded autonomous tool calling with strict infrastructure-only attribution grounding.
          </p>
        </div>
      </div>
    </div>
  );
};
