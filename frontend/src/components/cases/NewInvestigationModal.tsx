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
import { SAMPLE_INVESTIGATION_EML } from '../../data/sampleEml';

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

  // Clean up in-flight requests on unmount
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

  // Handle escape key
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
              'The forensic analysis backend is unreachable. Please verify the backend service is running and try again.'
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

  const handleLoadSample = async () => {
    const sampleFile = new File([SAMPLE_INVESTIGATION_EML], 'sample_bec_investigation.eml', {
      type: 'message/rfc822',
    });
    setSelectedFile(sampleFile);

    setIsAnalyzing(true);
    setErrorTitle(null);
    setErrorMessage(null);
    setAnalysisStep('LOADING SYNTHETIC BEC/PHISHING SPECIMEN (sample_bec_investigation.eml)...');

    const controller = new AbortController();
    abortControllerRef.current = controller;

    let stepTimer1: ReturnType<typeof setTimeout> | undefined;
    let stepTimer2: ReturnType<typeof setTimeout> | undefined;

    try {
      stepTimer1 = setTimeout(() => {
        setAnalysisStep('RECONSTRUCTING SMTP RELAYS & EVALUATING RFC 8601 SIGNALS...');
      }, 700);

      stepTimer2 = setTimeout(() => {
        setAnalysisStep('INVOKING AUTONOMOUS FORENSIC AGENT & COMPUTING THREAT ARC...');
      }, 1600);

      const result = await analyzeEmail(sampleFile, { signal: controller.signal });

      const sampleCase = caseStore.createCaseFromAnalysis(
        result,
        sampleFile,
        caseTitle.trim() || 'Synthetic BEC / Phishing Specimen',
        analystNotes.trim() || 'Vendor banking details update required before today\'s payment run (SIH26106).'
      );
      setIsAnalyzing(false);
      onInvestigationCreated(sampleCase);
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
              'The forensic analysis backend is unreachable. Please verify the backend service is running and try again.'
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

  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fadeIn">
      {/* Modal Dialog Card */}
      <div
        ref={modalRef}
        className="w-full max-w-xl bg-[var(--surface)] border border-[var(--border)] rounded-lg shadow-2xl overflow-hidden flex flex-col max-h-[90vh]"
      >
        {/* Header Bar */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[var(--border-subtle)] bg-[var(--surface-subtle)]">
          <div className="space-y-0.5">
            <div className="flex items-center space-x-2">
              <span className="w-2 h-2 rounded-full bg-[var(--ai)] animate-pulse" />
              <h2 className="text-sm font-bold font-mono tracking-wider text-[var(--text)] uppercase">
                NEW INVESTIGATION
              </h2>
            </div>
            <p className="text-xs text-[var(--text-muted)] font-sans">
              Ingest and analyze raw .eml message for forensic indicators.
            </p>
          </div>

          <button
            type="button"
            onClick={handleClose}
            className="p-1.5 rounded text-[var(--text-dim)] hover:text-[var(--text)] hover:bg-[var(--surface-elevated)] border border-transparent hover:border-[var(--border-subtle)] transition-colors cursor-pointer"
            title={isAnalyzing ? 'Cancel analysis (Esc)' : 'Close modal (Esc)'}
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-5 overflow-y-auto font-sans">
          {/* File Dropzone Area */}
          <div>
            <label className="block text-xs font-mono text-[var(--text-muted)] uppercase tracking-wider mb-2">
              1. Email Artifact (.eml) <span className="text-[var(--severity-critical)]">*</span>
            </label>

            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={() => !isAnalyzing && fileInputRef.current?.click()}
              className={`border-2 border-dashed rounded-md p-6 text-center cursor-pointer transition-all select-none ${
                dragOver
                  ? 'border-[var(--ai)] bg-[var(--surface-elevated)]'
                  : selectedFile
                  ? 'border-[var(--border)] bg-[var(--surface-subtle)]'
                  : 'border-[var(--border-subtle)] bg-[var(--surface-subtle)] hover:border-[var(--border)] hover:bg-[var(--surface)]'
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
                  <div className="w-10 h-10 rounded bg-[var(--surface)] border border-[var(--border-subtle)] mx-auto flex items-center justify-center text-[var(--text-muted)]">
                    <UploadCloud className="w-5 h-5 text-[var(--ai)]" />
                  </div>
                  <div>
                    <span className="text-xs text-[var(--text)] font-medium">
                      Click to browse or drop an <code className="font-mono text-[var(--identifier)]">.eml</code> file
                    </span>
                    <p className="text-[11px] text-[var(--text-dim)] font-mono mt-0.5">
                      Max file threshold 10 MB • RFC 822/5322 Standard
                    </p>
                  </div>
                </div>
              ) : (
                <div className="flex items-center justify-between gap-3 p-3 bg-[var(--surface)] border border-[var(--border-subtle)] rounded text-left">
                  <div className="flex items-center space-x-3 truncate">
                    <div className="w-8 h-8 rounded bg-[var(--surface-elevated)] border border-[var(--border-subtle)] flex items-center justify-center text-[var(--state-pass)] shrink-0">
                      <FileCheck2 className="w-4 h-4" />
                    </div>
                    <div className="truncate">
                      <div className="text-xs font-mono text-[var(--text)] font-medium truncate">
                        {selectedFile.name}
                      </div>
                      <div className="text-[10px] font-mono text-[var(--text-muted)]">
                        {formatFileSize(selectedFile.size)} • Ready for ingestion
                      </div>
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={handleRemoveFile}
                    disabled={isAnalyzing}
                    className="p-1.5 text-[var(--text-dim)] hover:text-[var(--severity-critical)] rounded hover:bg-[var(--surface-elevated)] transition-colors cursor-pointer"
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
              <label className="block text-xs font-mono text-[var(--text-muted)] uppercase tracking-wider mb-1.5">
                2. Case Title <span className="text-[var(--text-dim)] font-normal font-sans">(Optional)</span>
              </label>
              <input
                type="text"
                value={caseTitle}
                onChange={(e) => setCaseTitle(e.target.value)}
                disabled={isAnalyzing}
                placeholder="e.g. Executive Phishing Dispatch - Sep 2026"
                className="w-full bg-[var(--surface-subtle)] border border-[var(--border-subtle)] focus:border-[var(--border-active)] rounded px-3 py-2 text-xs text-[var(--text)] placeholder-[var(--text-disabled)] font-mono outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-mono text-[var(--text-muted)] uppercase tracking-wider mb-1.5">
                3. Analyst Intake Notes <span className="text-[var(--text-dim)] font-normal font-sans">(Optional)</span>
              </label>
              <textarea
                rows={2}
                value={analystNotes}
                onChange={(e) => setAnalystNotes(e.target.value)}
                disabled={isAnalyzing}
                placeholder="Add internal SOC ticket ID, observed telemetry, or dispatcher priority..."
                className="w-full bg-[var(--surface-subtle)] border border-[var(--border-subtle)] focus:border-[var(--border-active)] rounded px-3 py-2 text-xs text-[var(--text)] placeholder-[var(--text-disabled)] font-sans outline-none resize-none"
              />
            </div>
          </div>

          {/* Progress / Analyzing Indicator State */}
          {isAnalyzing && (
            <div className="p-4 bg-[var(--surface-subtle)] border border-[var(--border)] rounded-md space-y-2.5 animate-pulse">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="flex items-center gap-2 text-[var(--ai)]">
                  <span className="w-2 h-2 rounded-full bg-[var(--ai)] animate-ping" />
                  PROCESSING FORENSIC EXTRACTION
                </span>
                <span className="text-[var(--text-dim)]">ENGINE ACTIVE</span>
              </div>
              <div className="h-1.5 w-full bg-[var(--surface-elevated)] rounded-full overflow-hidden">
                <div className="h-full bg-gradient-to-r from-[var(--ai)] to-[var(--identifier)] w-2/3 rounded-full animate-[progress_1.5s_ease-in-out_infinite]" />
              </div>
              <div className="flex items-center gap-2 text-[11px] font-mono text-[var(--text-muted)]">
                <Terminal className="w-3.5 h-3.5 text-[var(--identifier)] shrink-0" />
                <span className="truncate">{analysisStep}</span>
              </div>
            </div>
          )}

          {/* Operational Error State */}
          {errorTitle && (
            <div className="p-3 bg-[var(--surface-elevated)] border border-[var(--severity-critical)] rounded-md flex items-start gap-3 text-xs">
              <AlertCircle className="w-4 h-4 text-[var(--severity-critical)] shrink-0 mt-0.5" />
              <div className="space-y-0.5">
                <div className="font-mono font-bold text-[var(--severity-critical)]">{errorTitle}</div>
                <div className="text-[var(--text-muted)] leading-relaxed font-sans">{errorMessage}</div>
              </div>
            </div>
          )}

          {/* Engine Capability Footer Tag */}
          <div className="flex items-center justify-between pt-2 border-t border-[var(--border-subtle)] text-[11px] font-mono text-[var(--text-dim)]">
            <span className="flex items-center gap-1.5">
              <Shield className="w-3.5 h-3.5 text-[var(--ai)]" />
              Multi-turn Autonomous Agent & RFC Verification
            </span>
            <span className="flex items-center gap-1">
              <Clock className="w-3 h-3" />
              ~2-4s Runtime
            </span>
          </div>
        </div>

        {/* Modal Actions Footer */}
        <div className="px-6 py-4 bg-[var(--surface-subtle)] border-t border-[var(--border-subtle)] flex flex-col sm:flex-row items-center justify-between gap-3">
          <button
            type="button"
            onClick={handleLoadSample}
            disabled={isAnalyzing}
            className="w-full sm:w-auto inline-flex items-center justify-center gap-1.5 px-3 py-1.5 rounded badge-ai text-xs font-mono transition-colors disabled:opacity-50 cursor-pointer"
          >
            <Sparkles className="w-3.5 h-3.5 text-[var(--ai)]" />
            LOAD SAMPLE SPECIMEN
          </button>

          <div className="flex items-center space-x-2 w-full sm:w-auto">
            <button
              type="button"
              onClick={handleClose}
              className="flex-1 sm:flex-none px-4 py-2 rounded bg-[var(--surface-elevated)] hover:bg-[var(--surface-hover)] text-[var(--text-muted)] hover:text-[var(--text)] border border-[var(--border-subtle)] text-xs font-mono transition-colors cursor-pointer"
            >
              {isAnalyzing ? 'CANCEL ANALYSIS' : 'CANCEL'}
            </button>

            <button
              type="button"
              onClick={handleAnalyze}
              disabled={isAnalyzing || !selectedFile}
              className="flex-1 sm:flex-none px-5 py-2 rounded bg-[var(--text)] hover:opacity-90 text-[var(--background)] text-xs font-mono font-medium flex items-center justify-center gap-1.5 shadow-sm transition-colors disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
            >
              {isAnalyzing ? (
                <>
                  <span className="w-3 h-3 border-2 border-[var(--background)]/30 border-t-[var(--background)] rounded-full animate-spin" />
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
