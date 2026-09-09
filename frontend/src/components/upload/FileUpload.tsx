import React, { useState, useRef } from 'react';
import type { DragEvent, ChangeEvent } from 'react';
import { UploadCloud, FileCheck2, Trash2, AlertCircle, ArrowRight, Sparkles, Loader2 } from 'lucide-react';

interface FileUploadProps {
  onAnalyze: (file: File) => void;
  onLoadMock: () => void;
  isAnalyzing: boolean;
  error?: string | null;
}

export const FileUpload: React.FC<FileUploadProps> = ({
  onAnalyze,
  onLoadMock,
  isAnalyzing,
  error,
}) => {
  const [dragOver, setDragOver] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [validationError, setValidationError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const capabilities = [
    { label: 'SPF', desc: 'RFC 7208' },
    { label: 'DKIM', desc: 'RFC 6376' },
    { label: 'DMARC', desc: 'RFC 7489' },
    { label: 'IP INTELLIGENCE', desc: 'AbuseIPDB/VT' },
    { label: 'DNS', desc: 'Resolvers/RDAP' },
    { label: 'AI FORENSICS', desc: 'Groq Multi-turn' },
  ];

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

  const validateAndSet = (file: File) => {
    setValidationError(null);
    if (!file.name.toLowerCase().endsWith('.eml')) {
      setValidationError('Invalid file format. Please upload a standard RFC 822/5322 (.eml) email file.');
      setSelectedFile(null);
      return;
    }
    if (file.size > 10 * 1024 * 1024) {
      setValidationError('File exceeds the 10 MB forensic size threshold.');
      setSelectedFile(null);
      return;
    }
    setSelectedFile(file);
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      validateAndSet(e.dataTransfer.files[0]);
    }
  };

  const handleFileInputChange = (e: ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      validateAndSet(e.target.files[0]);
    }
  };

  const handleRemove = (e: React.MouseEvent) => {
    e.stopPropagation();
    setSelectedFile(null);
    setValidationError(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  return (
    <div className="w-full space-y-4">
      {/* Capability Indicator Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 px-3.5 py-2 bg-[var(--surface-subtle)] border border-[var(--border-subtle)] rounded text-xs">
        <span className="text-[11px] font-mono text-[var(--text-dim)]">INSPECTION ENGINE:</span>
        <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono">
          {capabilities.map((c, i) => (
            <span key={c.label} className="inline-flex items-center gap-1.5 text-[var(--text-muted)]">
              <span className="w-1.5 h-1.5 rounded-full bg-[var(--state-pass)]" />
              <span className="text-[var(--text)]">{c.label}</span>
              <span className="text-[var(--text-dim)] text-[10px]">({c.desc})</span>
              {i < capabilities.length - 1 && <span className="text-[var(--border-subtle)] ml-1.5">|</span>}
            </span>
          ))}
        </div>
      </div>

      {/* Main Upload Dropzone */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`relative border-2 border-dashed rounded-lg p-8 md:p-10 transition-all cursor-pointer select-none text-center ${
          dragOver
            ? 'border-[var(--identifier)] bg-[var(--surface-hover)]'
            : selectedFile
            ? 'border-[var(--border-active)] bg-[var(--surface)]'
            : 'border-[var(--border-subtle)] bg-[var(--surface-subtle)] hover:border-[var(--border)] hover:bg-[var(--surface)]'
        }`}
      >
        <input
          type="file"
          ref={fileInputRef}
          onChange={handleFileInputChange}
          accept=".eml,message/rfc822"
          className="hidden"
        />

        {!selectedFile ? (
          <div className="space-y-3">
            <div className="w-12 h-12 rounded-md bg-[var(--surface-elevated)] border border-[var(--border-subtle)] mx-auto flex items-center justify-center text-[var(--text-muted)]">
              <UploadCloud className="w-6 h-6 text-[var(--text-muted)]" />
            </div>
            <div>
              <p className="text-sm font-medium text-[var(--text)] font-sans">
                Drop raw <code className="font-mono text-[var(--identifier)]">.eml</code> file here, or{' '}
                <span className="text-[var(--identifier)] underline underline-offset-4 font-mono">browse local storage</span>
              </p>
              <p className="text-xs text-[var(--text-dim)] mt-1 font-mono">
                Standard RFC 822/5322 formatted email • Up to 10 MB per investigation
              </p>
            </div>
          </div>
        ) : (
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 p-4 bg-[var(--surface-elevated)] border border-[var(--border)] rounded-md text-left">
            <div className="flex items-center space-x-3 truncate">
              <div className="w-9 h-9 rounded bg-[var(--surface)] border border-[var(--border-subtle)] flex items-center justify-center text-[var(--state-pass)] shrink-0">
                <FileCheck2 className="w-5 h-5" />
              </div>
              <div className="truncate">
                <div className="text-sm font-mono text-[var(--text)] truncate font-medium">
                  {selectedFile.name}
                </div>
                <div className="text-xs font-mono text-[var(--text-dim)]">
                  {formatFileSize(selectedFile.size)} • RFC 822 Validated
                </div>
              </div>
            </div>

            <div className="flex items-center space-x-2 shrink-0">
              <button
                type="button"
                onClick={handleRemove}
                disabled={isAnalyzing}
                className="p-2 text-[var(--text-dim)] hover:text-[var(--severity-critical)] rounded hover:bg-[var(--surface-hover)] border border-transparent transition-colors cursor-pointer"
                title="Remove file"
              >
                <Trash2 className="w-4 h-4" />
              </button>

              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  onAnalyze(selectedFile);
                }}
                disabled={isAnalyzing}
                className="px-4 py-2 bg-[var(--surface)] hover:bg-[var(--surface-hover)] text-[var(--text)] border border-[var(--border)] text-xs font-mono font-medium rounded flex items-center gap-2 shadow-sm transition-colors disabled:opacity-50 cursor-pointer"
              >
                {isAnalyzing ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin text-[var(--identifier)]" />
                    <span>ANALYZING EVIDENCE...</span>
                  </>
                ) : (
                  <>
                    <span>ANALYZE .EML</span>
                    <ArrowRight className="w-3.5 h-3.5 text-[var(--text-dim)]" />
                  </>
                )}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Validation or API Error Banner */}
      {(validationError || error) && (
        <div className="p-3.5 bg-[var(--surface-elevated)] border border-[var(--severity-critical)] rounded-md flex items-start gap-2.5 text-xs text-[var(--severity-critical)]">
          <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold font-mono">FORENSIC REJECTION:</span>{' '}
            {validationError || error}
          </div>
        </div>
      )}

      {/* Quick Sample Loader */}
      <div className="flex items-center justify-between text-xs text-[var(--text-dim)] pt-1">
        <span>No sample file at hand?</span>
        <button
          type="button"
          onClick={onLoadMock}
          className="inline-flex items-center gap-1.5 text-xs font-mono text-[var(--text-muted)] hover:text-[var(--text)] transition-colors cursor-pointer"
        >
          <Sparkles className="w-3.5 h-3.5 text-[var(--ai)]" />
          Load Verified Forensic Sample (security_signals.eml)
        </button>
      </div>
    </div>
  );
};
