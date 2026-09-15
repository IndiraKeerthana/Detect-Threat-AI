import React, { useState, useRef, useEffect } from 'react';
import { FileUpload } from '../components/upload/FileUpload';
import { PipelineVisual } from '../components/upload/PipelineVisual';
import { analyzeEmail } from '../services/api';
import { SAMPLE_INVESTIGATION_EML } from '../data/sampleEml';
import type { EmailAnalysisResponse } from '../types/investigation';
import { caseStore, type CaseRecord } from '../services/caseStore';
import { ShieldAlert, ShieldCheck, FileCheck, ArrowRight, Clock, AlertTriangle } from 'lucide-react';
import { formatISTTimestamp } from '../utils/dateFormatter';

interface HomeProps {
  onInvestigationComplete: (data: EmailAnalysisResponse) => void;
  isAnalyzing: boolean;
  setIsAnalyzing: (state: boolean) => void;
  onSelectCase?: (caseRecord: CaseRecord) => void;
}

export const Home: React.FC<HomeProps> = ({
  onInvestigationComplete,
  isAnalyzing,
  setIsAnalyzing,
  onSelectCase,
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
      const result = await analyzeEmail(file, {
        signal: controller.signal,
        sampleUpload: file.name === 'sample_bec_investigation.eml',
      });
      const newCase = caseStore.createCaseFromAnalysis(result);
      setCompletedCaseId(newCase.id);
      onInvestigationComplete(result);
    } catch (err: unknown) {
      const message =
        err instanceof Error
          ? err.message
          : 'We could not analyze this email right now. Please verify your connection and try again.';
      setError(message);
    } finally {
      abortControllerRef.current = null;
      setIsAnalyzing(false);
    }
  };

  const handleLoadMock = async () => {
    const sampleFile = new File([SAMPLE_INVESTIGATION_EML], 'sample_bec_investigation.eml', {
      type: 'message/rfc822',
    });
    await handleAnalyze(sampleFile);
  };

  // Dashboard Metrics derived from real stored cases
  const totalCases = cases.length;
  const safeCount = cases.filter((c) => c.riskScore < 40).length;
  const warningCount = cases.filter((c) => c.riskScore >= 40 && c.riskScore < 70).length;
  const highRiskCount = cases.filter((c) => c.riskScore >= 70).length;
  const recentCases = cases.slice(0, 5);

  const getSeverityBadgeClass = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
      case 'high':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/20';
      case 'medium':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
      default:
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
    }
  };

  return (
    <div className="space-y-8 max-w-5xl mx-auto py-2">
      {/* Friendly Hero Header */}
      <div className="space-y-3">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[var(--surface-elevated)] border border-[var(--border-subtle)] text-xs text-[var(--text-muted)]">
          <span className="w-2 h-2 rounded-full bg-[var(--ai)] animate-pulse" />
          <span>Email Safety & Threat Analysis</span>
        </div>

        <h1 className="text-3xl sm:text-4xl font-bold tracking-tight text-[var(--text)] font-sans">
          Check an Email
        </h1>

        <p className="text-base text-[var(--text-muted)] max-w-2xl leading-relaxed font-sans">
          Upload an <span className="font-semibold text-[var(--text)]">.eml file</span> to see whether it looks suspicious, check the sender&apos;s location, and review automated safety seals.
        </p>
      </div>

      {/* Post-Analysis Saved Case Banner */}
      {completedCaseId && (
        <div className="p-4 bg-[var(--surface-elevated)] border border-emerald-500/30 rounded-xl flex items-center justify-between gap-4 text-xs font-sans">
          <div className="flex items-center space-x-3">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping" />
            <div>
              <span className="text-[var(--text-muted)]">Analysis Complete: </span>
              <strong className="text-[var(--text)]">{completedCaseId}</strong>
              <span className="text-[var(--text-dim)] text-[11px] ml-2">Saved to your recent checks</span>
            </div>
          </div>
          <button
            type="button"
            onClick={() => {
              const matched = caseStore.getCaseById(completedCaseId);
              if (matched) {
                caseStore.setActiveCaseId(matched.id);
                if (onSelectCase) onSelectCase(matched);
              }
            }}
            className="px-3.5 py-1.5 rounded-lg bg-[var(--surface)] hover:bg-[var(--surface-hover)] text-[var(--text)] border border-[var(--border-subtle)] text-xs font-medium inline-flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm"
          >
            <span>View Full Details</span>
            <ArrowRight className="w-3.5 h-3.5 text-[var(--identifier)]" />
          </button>
        </div>
      )}

      {/* Main File Upload Area */}
      <div className="surface-card p-6 border border-[var(--border-subtle)] rounded-2xl">
        <FileUpload
          onAnalyze={handleAnalyze}
          onLoadMock={handleLoadMock}
          isAnalyzing={isAnalyzing}
          error={error}
        />
      </div>

      {/* Real Dashboard Metrics Overview */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 font-sans">
        <div className="bg-[var(--surface-subtle)] border border-[var(--border-subtle)] p-4 rounded-xl space-y-1">
          <div className="flex items-center justify-between text-xs text-[var(--text-dim)]">
            <span>Emails Checked</span>
            <FileCheck className="w-4 h-4 text-[var(--identifier)]" />
          </div>
          <div className="text-2xl font-bold text-[var(--text)] font-mono">{totalCases}</div>
          <div className="text-[11px] text-[var(--text-muted)]">Total analyzed in this session</div>
        </div>

        <div className="bg-[var(--surface-subtle)] border border-[var(--border-subtle)] p-4 rounded-xl space-y-1">
          <div className="flex items-center justify-between text-xs text-[var(--text-dim)]">
            <span>Safe Emails</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400 font-mono">{safeCount}</div>
          <div className="text-[11px] text-[var(--text-muted)]">Low risk score (&lt; 40)</div>
        </div>

        <div className="bg-[var(--surface-subtle)] border border-[var(--border-subtle)] p-4 rounded-xl space-y-1">
          <div className="flex items-center justify-between text-xs text-[var(--text-dim)]">
            <span>Suspicious Emails</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-400 font-mono">{warningCount}</div>
          <div className="text-[11px] text-[var(--text-muted)]">Moderate warning signs (40-69)</div>
        </div>

        <div className="bg-[var(--surface-subtle)] border border-[var(--border-subtle)] p-4 rounded-xl space-y-1">
          <div className="flex items-center justify-between text-xs text-[var(--text-dim)]">
            <span>High-Risk Emails</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-rose-400 font-mono">{highRiskCount}</div>
          <div className="text-[11px] text-[var(--text-muted)]">High risk score (70+)</div>
        </div>
      </div>

      {/* Pipeline Explanation Cards */}
      <div className="space-y-3">
        <PipelineVisual />
      </div>

      {/* Recent Checks List */}
      {recentCases.length > 0 && (
        <div className="surface-card p-5 border border-[var(--border-subtle)] rounded-2xl space-y-4 font-sans">
          <div className="flex items-center justify-between border-b border-[var(--border-subtle)] pb-3">
            <div className="flex items-center gap-2 text-sm font-semibold text-[var(--text)]">
              <Clock className="w-4 h-4 text-[var(--identifier)]" />
              <span>Recent Checks</span>
            </div>
            <span className="text-xs text-[var(--text-dim)] font-mono">{recentCases.length} stored items</span>
          </div>

          <div className="divide-y divide-[var(--border-subtle)]">
            {recentCases.map((c) => (
              <div
                key={c.id}
                onClick={() => {
                  caseStore.setActiveCaseId(c.id);
                  if (onSelectCase) onSelectCase(c);
                }}
                className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-[var(--surface-hover)] p-2 rounded-xl transition-colors cursor-pointer"
              >
                <div className="space-y-1 min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold text-[var(--identifier)]">{c.id}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase border ${getSeverityBadgeClass(c.severity)}`}>
                      {c.severity}
                    </span>
                    <span className="text-xs text-[var(--text-muted)] font-mono">Risk Score: <strong className="text-[var(--text)]">{c.riskScore}/100</strong></span>
                  </div>
                  <div className="text-xs font-medium text-[var(--text)] truncate">{c.subject || '(No Subject)'}</div>
                  <div className="text-[11px] text-[var(--text-dim)] truncate">From: {c.sender}</div>
                </div>

                <div className="flex items-center gap-3 shrink-0 text-xs">
                  <span className="text-[11px] text-[var(--text-dim)] hidden sm:inline">{formatISTTimestamp(c.createdAt)}</span>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      caseStore.setActiveCaseId(c.id);
                      if (onSelectCase) onSelectCase(c);
                    }}
                    className="px-3 py-1.5 rounded-lg bg-[var(--surface-elevated)] hover:bg-[var(--surface-hover)] text-[var(--text)] border border-[var(--border-subtle)] text-xs font-medium inline-flex items-center gap-1 transition-colors cursor-pointer"
                  >
                    <span>View Details</span>
                    <ArrowRight className="w-3.5 h-3.5 text-[var(--identifier)]" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Quick 3-Step Guide */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs font-sans">
        <div className="bg-[var(--surface-subtle)] border border-[var(--border-subtle)] p-4 rounded-xl space-y-1.5">
          <div className="w-6 h-6 rounded-full bg-[var(--surface-elevated)] border border-[var(--border-subtle)] flex items-center justify-center font-bold font-mono text-[var(--identifier)]">1</div>
          <div className="text-sm font-semibold text-[var(--text)]">Upload .eml File</div>
          <p className="text-[11px] text-[var(--text-muted)] leading-relaxed">
            Drag &amp; drop any saved email file or try our sample email.
          </p>
        </div>

        <div className="bg-[var(--surface-subtle)] border border-[var(--border-subtle)] p-4 rounded-xl space-y-1.5">
          <div className="w-6 h-6 rounded-full bg-[var(--surface-elevated)] border border-[var(--border-subtle)] flex items-center justify-center font-bold font-mono text-[var(--identifier)]">2</div>
          <div className="text-sm font-semibold text-[var(--text)]">Automated Safety Checks</div>
          <p className="text-[11px] text-[var(--text-muted)] leading-relaxed">
            We check email security seals (SPF/DKIM/DMARC), links, and sender location.
          </p>
        </div>

        <div className="bg-[var(--surface-subtle)] border border-[var(--border-subtle)] p-4 rounded-xl space-y-1.5">
          <div className="w-6 h-6 rounded-full bg-[var(--surface-elevated)] border border-[var(--border-subtle)] flex items-center justify-center font-bold font-mono text-[var(--identifier)]">3</div>
          <div className="text-sm font-semibold text-[var(--text)]">Clear Safety Verdict</div>
          <p className="text-[11px] text-[var(--text-muted)] leading-relaxed">
            Get an instant safety rating with human-readable explanations and next steps.
          </p>
        </div>
      </div>
    </div>
  );
};
