import React, { useState, useRef, useEffect } from 'react';
import type { DragEvent, ChangeEvent } from 'react';
import {
  X,
  UploadCloud,
  FileCheck2,
  Trash2,
  AlertCircle,
  Sparkles,
  ArrowRight,
  Shield,
  Clock,
  Terminal,
} from 'lucide-react';
import { analyzeEmail, ApiError } from '../../services/api';
import { caseStore, type CaseRecord } from '../../services/caseStore';
import { MOCK_INVESTIGATION_DATA } from '../../data/mockInvestigation';

interface NewInvestigationModalProps {
  isOpen: boolean;
  onClose: () => void;
  onInvestigationCreated: (newCase: CaseRecord) => void;
}

export const NewInvestigationModal: React.FC<NewInvestigationModalProps> = ({
  isOpen,
  onClose,
  onInvestigationCreated,
}) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [caseTitle, setCaseTitle] = useState<string>('');
  const [analystNotes, setAnalystNotes] = useState<string>('');
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [analysisStep, setAnalysisStep] = useState<string>('');
  const [errorTitle, setErrorTitle] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState<boolean>(false);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const modalRef = useRef<HTMLDivElement>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  // Clean up in-flight requests and timers on unmount
  useEffect(() => {
    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, []);

  const handleClose = React.useCallback(() => {
    if (isAnalyzing) {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
      return;
    }
    setSelectedFile(null);
    setCaseTitle('');
    setAnalystNotes('');
    setIsAnalyzing(false);
    setAnalysisStep('');
    setErrorTitle(null);
    setErrorMessage(null);
    onClose();
  }, [isAnalyzing, onClose]);

  // Handle escape key to dismiss or cancel in-flight analysis
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        handleClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, handleClose]);

  if (!isOpen) return null;

  const validateFile = (file: File) => {
    setErrorTitle(null);
    setErrorMessage(null);
    if (!file.name.toLowerCase().endsWith('.eml')) {
      setErrorTitle('INVALID FILE FORMAT');
      setErrorMessage('Only standard RFC 822/5322 (.eml) email files are accepted for forensic parsing.');
      setSelectedFile(null);
      return false;
    }
    if (file.size > 10 * 1024 * 1024) {
      setErrorTitle('FORENSIC THRESHOLD EXCEEDED');
      setErrorMessage('The selected file exceeds the 10 MB maximum forensic inspection threshold.');
      setSelectedFile(null);
      return false;
    }
    setSelectedFile(file);
    if (!caseTitle) {
      setCaseTitle(file.name.replace(/\.eml$/i, ''));
    }
    return true;
  };

  const handleDragOver = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(true);
  };

  const handleDragLeave = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(false);
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      validateFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileInputChange = (e: ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      validateFile(e.target.files[0]);
    }
  };

  const handleRemoveFile = (e: React.MouseEvent) => {
    e.stopPropagation();
    setSelectedFile(null);
    setErrorTitle(null);
    setErrorMessage(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleAnalyze = async () => {
    if (!selectedFile) {
      setErrorTitle('MISSING FORENSIC ARTIFACT');
      setErrorMessage('Please select or drop an RFC 822/5322 (.eml) file to commence investigation.');
      return;
    }

    const controller = new AbortController();
    abortControllerRef.current = controller;

    setIsAnalyzing(true);
    setErrorTitle(null);
    setErrorMessage(null);
    setAnalysisStep('PARSING RFC 822 / 5322 HEADERS & MIME STRUCTURE...');

    let stepTimer1: ReturnType<typeof setTimeout> | undefined;
    let stepTimer2: ReturnType<typeof setTimeout> | undefined;

    try {
      // Step timer updates for realistic forensic feedback
      stepTimer1 = setTimeout(() => {
        setAnalysisStep('RECONSTRUCTING PERIMETER RELAY HOPS & RESOLVING GEOLOCATION...');
      }, 700);

      stepTimer2 = setTimeout(() => {
        setAnalysisStep('INVOKING AUTONOMOUS FORENSIC AGENT & COMPUTING THREAT ARC...');
      }, 1600);

      const result = await analyzeEmail(selectedFile, { signal: controller.signal });

      const newCase = caseStore.createCaseFromAnalysis(
        result,
        selectedFile,
        caseTitle.trim() || undefined,
        analystNotes.trim() || undefined
      );

      onInvestigationCreated(newCase);
      onClose();
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        if (err.status === 408) {
          setErrorTitle('INVESTIGATION TIMEOUT');
          setErrorMessage(err.message);
        } else if (err.status === 0) {
          if (err.detail === 'ABORTED') {
            setErrorTitle('INVESTIGATION CANCELLED');
            setErrorMessage('The forensic investigation was cancelled.');
          } else {
            setErrorTitle('ANALYSIS SERVICE UNAVAILABLE');
            setErrorMessage(
              'Forensic backend at :8001 is offline or unreachable. Ensure the FastAPI server is running or use the sample file below.'
            );
          }
        } else {
          setErrorTitle(`FORENSIC EXTRACTION FAILED (HTTP ${err.status})`);
          setErrorMessage(err.detail || err.message);
        }
      } else {
        const msg = err instanceof Error ? err.message : 'Unknown parsing failure occurred.';
        setErrorTitle('ANALYSIS PIPELINE FAILURE');
        setErrorMessage(msg);
      }
    } finally {
      if (stepTimer1 !== undefined) clearTimeout(stepTimer1);
      if (stepTimer2 !== undefined) clearTimeout(stepTimer2);
      abortControllerRef.current = null;
      setIsAnalyzing(false);
      setAnalysisStep('');
    }
  };

  const handleLoadSample = () => {
    setIsAnalyzing(true);
    setErrorTitle(null);
    setErrorMessage(null);
    setAnalysisStep('LOADING VALIDATED FORENSIC SPECIMEN (security_signals.eml)...');

    setTimeout(() => {
      const sampleCase = caseStore.createCaseFromAnalysis(
        MOCK_INVESTIGATION_DATA,
        undefined,
        caseTitle.trim() || 'Verified Security Signals Specimen',
        analystNotes.trim() || 'Loaded from offline verified test corpus (PS SIH26106).'
      );
      setIsAnalyzing(false);
      onInvestigationCreated(sampleCase);
      onClose();
    }, 600);
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#0a0c10]/85 backdrop-blur-sm animate-fadeIn">
      {/* Modal Dialog Card */}
      <div
        ref={modalRef}
        className="w-full max-w-xl bg-[#0f1217] border border-[#2a3242] rounded-lg shadow-2xl overflow-hidden flex flex-col max-h-[90vh]"
      >
        {/* Header Bar */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2430] bg-[#12151b]">
          <div className="space-y-0.5">
            <div className="flex items-center space-x-2">
              <span className="w-2 h-2 rounded-full bg-[#8b5cf6] animate-pulse" />
              <h2 className="text-sm font-bold font-mono tracking-wider text-[#f1f5f9] uppercase">
                NEW INVESTIGATION
              </h2>
            </div>
            <p className="text-xs text-[#64748b] font-sans">
              Ingest and analyze raw .eml message for forensic indicators.
            </p>
          </div>

          <button
            onClick={handleClose}
            className="p-1.5 rounded text-[#64748b] hover:text-[#f1f5f9] hover:bg-[#171b23] border border-transparent hover:border-[#2a3242] transition-colors"
            title={isAnalyzing ? 'Cancel analysis (Esc)' : 'Close modal (Esc)'}
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-5 overflow-y-auto font-sans">
          {/* File Dropzone Area */}
          <div>
            <label className="block text-xs font-mono text-[#94a3b8] uppercase tracking-wider mb-2">
              1. Email Artifact (.eml) <span className="text-[#ef4444]">*</span>
            </label>

            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={() => !isAnalyzing && fileInputRef.current?.click()}
              className={`border-2 border-dashed rounded-md p-6 text-center cursor-pointer transition-all select-none ${
                dragOver
                  ? 'border-[#8b5cf6] bg-[#1a152e]'
                  : selectedFile
                  ? 'border-[#3e485e] bg-[#12151b]'
                  : 'border-[#1e2430] bg-[#0c0e12] hover:border-[#3e485e] hover:bg-[#12151b]'
              }`}
            >
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileInputChange}
                accept=".eml,message/rfc822"
                className="hidden"
                disabled={isAnalyzing}
              />

              {!selectedFile ? (
                <div className="space-y-2">
                  <div className="w-10 h-10 rounded bg-[#171b23] border border-[#2a3242] mx-auto flex items-center justify-center text-[#94a3b8]">
                    <UploadCloud className="w-5 h-5 text-[#8b5cf6]" />
                  </div>
                  <div>
                    <span className="text-xs text-[#f1f5f9] font-medium">
                      Click to browse or drop an <code className="font-mono text-[#06b6d4]">.eml</code> file
                    </span>
                    <p className="text-[11px] text-[#64748b] font-mono mt-0.5">
                      Max file threshold 10 MB • RFC 822/5322 Standard
                    </p>
                  </div>
                </div>
              ) : (
                <div className="flex items-center justify-between gap-3 p-3 bg-[#171b23] border border-[#2a3242] rounded text-left">
                  <div className="flex items-center space-x-3 truncate">
                    <div className="w-8 h-8 rounded bg-[#1e2430] border border-[#3e485e] flex items-center justify-center text-[#10b981] shrink-0">
                      <FileCheck2 className="w-4 h-4" />
                    </div>
                    <div className="truncate">
                      <div className="text-xs font-mono text-[#f1f5f9] font-medium truncate">
                        {selectedFile.name}
                      </div>
                      <div className="text-[10px] font-mono text-[#64748b]">
                        {formatFileSize(selectedFile.size)} • Ready for ingestion
                      </div>
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={handleRemoveFile}
                    disabled={isAnalyzing}
                    className="p-1.5 text-[#64748b] hover:text-[#ef4444] rounded hover:bg-[#261114] transition-colors"
                    title="Remove artifact"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Optional Metadata Fields */}
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-mono text-[#94a3b8] uppercase tracking-wider mb-1.5">
                2. Case Title <span className="text-[#64748b] font-normal font-sans">(Optional)</span>
              </label>
              <input
                type="text"
                value={caseTitle}
                onChange={(e) => setCaseTitle(e.target.value)}
                disabled={isAnalyzing}
                placeholder="e.g. Executive Phishing Dispatch - Sep 2026"
                className="w-full bg-[#12151b] border border-[#1e2430] focus:border-[#3e485e] rounded px-3 py-2 text-xs text-[#f1f5f9] placeholder-[#475569] font-mono outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-mono text-[#94a3b8] uppercase tracking-wider mb-1.5">
                3. Analyst Intake Notes <span className="text-[#64748b] font-normal font-sans">(Optional)</span>
              </label>
              <textarea
                rows={2}
                value={analystNotes}
                onChange={(e) => setAnalystNotes(e.target.value)}
                disabled={isAnalyzing}
                placeholder="Add internal SOC ticket ID, observed telemetry, or dispatcher priority..."
                className="w-full bg-[#12151b] border border-[#1e2430] focus:border-[#3e485e] rounded px-3 py-2 text-xs text-[#f1f5f9] placeholder-[#475569] font-sans outline-none resize-none"
              />
            </div>
          </div>

          {/* Progress / Analyzing Indicator State */}
          {isAnalyzing && (
            <div className="p-4 bg-[#12151b] border border-[#3e485e] rounded-md space-y-2.5 animate-pulse">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="flex items-center gap-2 text-[#c4b5fd]">
                  <span className="w-2 h-2 rounded-full bg-[#8b5cf6] animate-ping" />
                  PROCESSING FORENSIC EXTRACTION
                </span>
                <span className="text-[#64748b]">ENGINE ACTIVE</span>
              </div>
              <div className="h-1.5 w-full bg-[#1a202c] rounded-full overflow-hidden">
                <div className="h-full bg-gradient-to-r from-[#8b5cf6] to-[#06b6d4] w-2/3 rounded-full animate-[progress_1.5s_ease-in-out_infinite]" />
              </div>
              <div className="flex items-center gap-2 text-[11px] font-mono text-[#94a3b8]">
                <Terminal className="w-3.5 h-3.5 text-[#06b6d4] shrink-0" />
                <span className="truncate">{analysisStep}</span>
              </div>
            </div>
          )}

          {/* Operational Error State */}
          {errorTitle && (
            <div className="p-3 bg-[#261114] border border-[#5c1d24] rounded-md flex items-start gap-3 text-xs">
              <AlertCircle className="w-4 h-4 text-[#ef4444] shrink-0 mt-0.5" />
              <div className="space-y-0.5">
                <div className="font-mono font-bold text-[#fca5a5]">{errorTitle}</div>
                <div className="text-[#fca5a5]/90 leading-relaxed font-sans">{errorMessage}</div>
              </div>
            </div>
          )}

          {/* Engine Capability Footer Tag */}
          <div className="flex items-center justify-between pt-2 border-t border-[#1e2430] text-[11px] font-mono text-[#64748b]">
            <span className="flex items-center gap-1.5">
              <Shield className="w-3.5 h-3.5 text-[#8b5cf6]" />
              Multi-turn Autonomous Agent & RFC Verification
            </span>
            <span className="flex items-center gap-1">
              <Clock className="w-3 h-3" />
              ~2-4s Runtime
            </span>
          </div>
        </div>

        {/* Modal Actions Footer */}
        <div className="px-6 py-4 bg-[#12151b] border-t border-[#1e2430] flex flex-col sm:flex-row items-center justify-between gap-3">
          <button
            type="button"
            onClick={handleLoadSample}
            disabled={isAnalyzing}
            className="w-full sm:w-auto inline-flex items-center justify-center gap-1.5 px-3 py-1.5 rounded bg-[#171b23] hover:bg-[#1e232e] text-[#c4b5fd] hover:text-white border border-[#2a3242] text-xs font-mono transition-colors disabled:opacity-50"
          >
            <Sparkles className="w-3.5 h-3.5 text-[#8b5cf6]" />
            LOAD SAMPLE SPECIMEN
          </button>

          <div className="flex items-center space-x-2 w-full sm:w-auto">
            <button
              type="button"
              onClick={handleClose}
              className="flex-1 sm:flex-none px-4 py-2 rounded bg-[#171b23] hover:bg-[#1e232e] text-[#94a3b8] hover:text-[#f1f5f9] border border-[#2a3242] text-xs font-mono transition-colors"
            >
              {isAnalyzing ? 'CANCEL ANALYSIS' : 'CANCEL'}
            </button>

            <button
              type="button"
              onClick={handleAnalyze}
              disabled={isAnalyzing || !selectedFile}
              className="flex-1 sm:flex-none px-5 py-2 rounded bg-[#8b5cf6] hover:bg-[#7c3aed] text-white text-xs font-mono font-medium flex items-center justify-center gap-1.5 shadow-sm transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {isAnalyzing ? (
                <>
                  <span className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  ANALYZING...
                </>
              ) : (
                <>
                  ANALYZE EMAIL
                  <ArrowRight className="w-3.5 h-3.5" />
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
