import React, { useState, useRef } from 'react';
import type { DragEvent, ChangeEvent } from 'react';
import { UploadCloud, FileCheck2, Trash2, ShieldCheck, Sparkles, Loader2, ShieldAlert } from 'lucide-react';

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
    { label: 'Email Security', desc: 'SPF / DKIM / DMARC' },
    { label: 'Sender Location', desc: 'IP & Country' },
    { label: 'Online Safety', desc: 'Known Reputation' },
    { label: 'AI Investigation', desc: 'Groq AI Agent' },
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
      setValidationError('Please upload a standard email file (.eml).');
      setSelectedFile(null);
      return;
    }
    if (file.size > 10 * 1024 * 1024) {
      setValidationError('File exceeds the 10 MB limit.');
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
    <div className="w-full space-y-5">
      {/* Capability Indicator Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 bg-[var(--surface-subtle)] border border-[var(--border-subtle)] rounded-xl text-xs font-sans">
        <span className="text-xs font-semibold text-[var(--text-muted)]">AUTOMATED CHECKS:</span>
        <div className="flex flex-wrap items-center gap-3.5 text-xs">
          {capabilities.map((c, i) => (
            <span key={c.label} className="inline-flex items-center gap-1.5 text-[var(--text-muted)] font-medium">
              <span className="w-2 h-2 rounded-full bg-[var(--state-pass)]" />
              <span className="text-[var(--text)]">{c.label}</span>
              <span className="text-[var(--text-dim)] text-[11px]">({c.desc})</span>
              {i < capabilities.length - 1 && <span className="text-[var(--border-subtle)] ml-2">|</span>}
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
        className={`relative border-2 border-dashed rounded-2xl p-8 sm:p-10 transition-all cursor-pointer select-none text-center ${
          dragOver
            ? 'border-[var(--accent)] bg-[var(--accent-soft)]'
            : selectedFile
            ? 'border-[var(--border-active)] bg-[var(--surface)]'
            : 'border-[var(--border-subtle)] bg-[var(--surface-subtle)] hover:border-[var(--border-active)] hover:bg-[var(--surface)]'
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
          <div className="space-y-4">
            <div className="w-14 h-14 rounded-2xl bg-[var(--surface-elevated)] border border-[var(--border-subtle)] mx-auto flex items-center justify-center text-[var(--accent)] shadow-xs">
              <UploadCloud className="w-7 h-7" />
            </div>
            <div className="space-y-1">
              <h3 className="text-base font-bold text-[var(--text)] font-sans">
                Drop your <span className="text-[var(--accent)] font-mono">.eml</span> email file here
              </h3>
              <p className="text-xs text-[var(--text-muted)] font-sans">
                Or click to browse your files • Standard .eml format up to 10 MB
              </p>
            </div>
          </div>
        ) : (
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 p-4 bg-[var(--surface-elevated)] border border-[var(--border)] rounded-xl text-left">
            <div className="flex items-center space-x-3.5 truncate">
              <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-500 shrink-0">
                <FileCheck2 className="w-5 h-5" />
              </div>
              <div className="truncate">
                <div className="text-sm font-semibold text-[var(--text)] font-sans truncate">
                  {selectedFile.name}
                </div>
                <div className="text-xs text-[var(--text-muted)] font-sans">
                  {formatFileSize(selectedFile.size)} • Ready for analysis
                </div>
              </div>
            </div>

            <div className="flex items-center space-x-2 shrink-0">
              <button
                type="button"
                onClick={handleRemove}
                disabled={isAnalyzing}
                className="p-2 text-[var(--text-dim)] hover:text-rose-500 rounded-lg hover:bg-[var(--surface-hover)] transition-colors cursor-pointer"
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
                className="px-5 py-2.5 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white font-bold text-xs rounded-xl flex items-center gap-2 shadow-xs transition-all disabled:opacity-50 cursor-pointer"
              >
                {isAnalyzing ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin text-white" />
                    <span>Checking this email...</span>
                  </>
                ) : (
                  <>
                    <ShieldCheck className="w-4 h-4 text-white" />
                    <span>Analyze Email Now</span>
                  </>
                )}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Validation or API Error Banner */}
      {(validationError || error) && (
        <div className="p-4 bg-rose-500/10 border border-rose-500/20 rounded-xl flex items-start gap-3 text-xs text-rose-400 font-sans">
          <ShieldAlert className="w-5 h-5 shrink-0 text-rose-500 mt-0.5" />
          <div>
            <strong className="font-semibold block mb-0.5">We couldn't analyze this email right now</strong>
            <span>{validationError || error}</span>
          </div>
        </div>
      )}

      {/* Quick Sample Loader Option */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-2 text-xs text-[var(--text-muted)] font-sans pt-1">
        <span>Don't have an .eml file ready?</span>
        <button
          type="button"
          onClick={onLoadMock}
          disabled={isAnalyzing}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--surface-elevated)] hover:bg-[var(--surface-hover)] border border-[var(--border-subtle)] text-xs font-semibold text-[var(--accent)] transition-colors cursor-pointer disabled:opacity-50"
        >
          <Sparkles className="w-4 h-4 text-[var(--accent)]" />
          <span>Try Sample Email</span>
        </button>
      </div>
    </div>
  );
};
