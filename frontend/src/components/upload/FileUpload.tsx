import React, { useState, useRef } from 'react';
import type { DragEvent, ChangeEvent } from 'react';
import { UploadCloud, FileCheck2, Trash2, AlertCircle, ArrowRight, Sparkles } from 'lucide-react';

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
      <div className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 bg-[#12151b] border border-[#1e2430] rounded text-xs">
        <span className="text-[11px] font-mono text-[#64748b]">INSPECTION ENGINE:</span>
        <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono">
          {capabilities.map((c, i) => (
            <span key={c.label} className="inline-flex items-center gap-1.5 text-[#94a3b8]">
              <span className="w-1.5 h-1.5 rounded-full bg-[#3e485e]" />
              <span className="text-[#f1f5f9]">{c.label}</span>
              <span className="text-[#64748b] text-[10px]">({c.desc})</span>
              {i < capabilities.length - 1 && <span className="text-[#2a3242] ml-1.5">|</span>}
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
            ? 'border-[#8b5cf6] bg-[#171424]'
            : selectedFile
            ? 'border-[#2a3242] bg-[#12151b]'
            : 'border-[#1e2430] bg-[#101319] hover:border-[#2a3242] hover:bg-[#12151b]'
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
            <div className="w-12 h-12 rounded-md bg-[#171b23] border border-[#2a3242] mx-auto flex items-center justify-center text-[#94a3b8]">
              <UploadCloud className="w-6 h-6 text-[#94a3b8]" />
            </div>
            <div>
              <p className="text-sm font-medium text-[#f1f5f9]">
                Drop raw <code className="font-mono text-[#06b6d4]">.eml</code> file here, or{' '}
                <span className="text-[#8b5cf6] underline underline-offset-4">browse local storage</span>
              </p>
              <p className="text-xs text-[#64748b] mt-1 font-mono">
                Standard RFC 822/5322 formatted email • Up to 10 MB per investigation
              </p>
            </div>
          </div>
        ) : (
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 p-4 bg-[#171b23] border border-[#2a3242] rounded-md text-left">
            <div className="flex items-center space-x-3 truncate">
              <div className="w-9 h-9 rounded bg-[#1e232e] border border-[#3e485e] flex items-center justify-center text-[#10b981] shrink-0">
                <FileCheck2 className="w-5 h-5" />
              </div>
              <div className="truncate">
                <div className="text-sm font-mono text-[#f1f5f9] truncate font-medium">
                  {selectedFile.name}
                </div>
                <div className="text-xs font-mono text-[#64748b]">
                  {formatFileSize(selectedFile.size)} • RFC 822 Validated
                </div>
              </div>
            </div>

            <div className="flex items-center space-x-2 shrink-0">
              <button
                type="button"
                onClick={handleRemove}
                disabled={isAnalyzing}
                className="p-2 text-[#64748b] hover:text-[#ef4444] rounded hover:bg-[#261114] border border-transparent hover:border-[#5c1d24] transition-colors"
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
                className="px-4 py-2 bg-[#8b5cf6] hover:bg-[#7c3aed] text-white text-xs font-mono font-medium rounded flex items-center gap-2 shadow-sm transition-colors disabled:opacity-50"
              >
                {isAnalyzing ? (
                  <>
                    <span className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    ANALYZING EVIDENCE...
                  </>
                ) : (
                  <>
                    ANALYZE .EML
                    <ArrowRight className="w-3.5 h-3.5" />
                  </>
                )}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Validation or API Error Banner */}
      {(validationError || error) && (
        <div className="p-3 bg-[#261114] border border-[#5c1d24] rounded-md flex items-start gap-2.5 text-xs text-[#fca5a5]">
          <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-[#ef4444]" />
          <div>
            <span className="font-semibold font-mono">FORENSIC REJECTION:</span>{' '}
            {validationError || error}
          </div>
        </div>
      )}

      {/* Quick Demo Loader */}
      <div className="flex items-center justify-between text-xs text-[#64748b] pt-1">
        <span>No sample file at hand?</span>
        <button
          type="button"
          onClick={onLoadMock}
          className="inline-flex items-center gap-1.5 text-xs font-mono text-[#c4b5fd] hover:text-white transition-colors"
        >
          <Sparkles className="w-3.5 h-3.5 text-[#8b5cf6]" />
          Load Verified Forensic Sample (security_signals.eml)
        </button>
      </div>
    </div>
  );
};
