import React, { useState, useRef, useEffect } from 'react';
import { FileUpload } from '../components/upload/FileUpload';
import { PipelineVisual } from '../components/upload/PipelineVisual';
import { analyzeEmail } from '../services/api';
import { MOCK_INVESTIGATION_DATA } from '../data/mockInvestigation';
import type { EmailAnalysisResponse } from '../types/investigation';

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
  const abortControllerRef = useRef<AbortController | null>(null);

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
    const controller = new AbortController();
    abortControllerRef.current = controller;

    try {
      const result = await analyzeEmail(file, { signal: controller.signal });
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
    setIsAnalyzing(true);
    setTimeout(() => {
      setIsAnalyzing(false);
      onInvestigationComplete(MOCK_INVESTIGATION_DATA);
    }, 400);
  };

  return (
    <div className="space-y-8 max-w-5xl mx-auto py-4">
      {/* Hero Headline Section */}
      <div className="space-y-3">
        <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded bg-[#171b23] border border-[#2a3242] text-[11px] font-mono text-[#94a3b8]">
          <span className="w-1.5 h-1.5 rounded-full bg-[#8b5cf6]" />
          SIH 2026 • PS SIH26106 • AUTONOMOUS FORENSIC SYSTEM
        </div>

        <h1 className="text-3xl sm:text-4xl md:text-5xl font-bold tracking-tight text-[#f1f5f9] leading-[1.1]">
          EMAIL FORENSICS,<br />
          <span className="text-[#94a3b8]">RECONSTRUCTED.</span>
        </h1>

        <p className="text-sm md:text-base text-[#94a3b8] max-w-2xl leading-relaxed">
          Turn a suspicious email into an explainable investigation of the infrastructure behind it.
          Combines deterministic RFC parsing, relay reconstruction, and multi-turn autonomous AI tool execution.
        </p>
      </div>

      {/* Upload Experience */}
      <div className="surface-card p-6 border border-[#1e2430]">
        <FileUpload
          onAnalyze={handleAnalyze}
          onLoadMock={handleLoadMock}
          isAnalyzing={isAnalyzing}
          error={error}
        />
      </div>

      {/* Abstract Investigation Network Visual */}
      <div className="space-y-3">
        <PipelineVisual />
      </div>

      {/* System Specifications Grid (Subtle, non-marketing) */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
        <div className="bg-[#12151b] border border-[#1e2430] p-3.5 rounded space-y-1">
          <div className="text-[10px] text-[#64748b] uppercase">SPEC 01 • DETERMINISTIC</div>
          <div className="text-[#f1f5f9] font-medium">RFC 8601 & Hop Analysis</div>
          <p className="text-[11px] text-[#64748b] font-sans">
            Strict SPF/DKIM/DMARC matrix validation and perimeter relay hop identification.
          </p>
        </div>

        <div className="bg-[#12151b] border border-[#1e2430] p-3.5 rounded space-y-1">
          <div className="text-[10px] text-[#64748b] uppercase">SPEC 02 • TELEMETRY</div>
          <div className="text-[#f1f5f9] font-medium">Reputation & DNS/RDAP</div>
          <p className="text-[11px] text-[#64748b] font-sans">
            AbuseIPDB and VirusTotal live telemetry normalized to evidence graph nodes.
          </p>
        </div>

        <div className="bg-[#12151b] border border-[#1e2430] p-3.5 rounded space-y-1">
          <div className="text-[10px] text-[#64748b] uppercase">SPEC 03 • AI AGENT</div>
          <div className="text-[#f1f5f9] font-medium">Groq Multi-Turn Tool Loop</div>
          <p className="text-[11px] text-[#64748b] font-sans">
            Bounded autonomous tool calling with strict infrastructure-only attribution grounding.
          </p>
        </div>
      </div>
    </div>
  );
};
