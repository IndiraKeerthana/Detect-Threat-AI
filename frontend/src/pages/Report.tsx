import React, { useState, useEffect, useMemo } from 'react';
import {
  FileSpreadsheet,
  Search,
  Download,
  ExternalLink,
  Loader2,
  PlusCircle,
} from 'lucide-react';
import { caseStore, type CaseRecord } from '../services/caseStore';
import { formatISTTimestamp } from '../utils/dateFormatter';
import { downloadForensicReportPdf } from '../services/api';
import { deriveEmailCategory } from '../services/investigationAdapter';

interface ReportProps {
  onSelectCase?: (caseRecord: CaseRecord) => void;
  onNavigateNewInvestigation?: () => void;
}

export const Report: React.FC<ReportProps> = ({
  onSelectCase,
  onNavigateNewInvestigation,
}) => {
  const [cases, setCases] = useState<CaseRecord[]>(() => caseStore.getCases());
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');
  const [filterCategory, setFilterCategory] = useState<string>('ALL');
  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  useEffect(() => {
    const unsub = caseStore.subscribe(() => {
      setCases(caseStore.getCases());
    });
    return unsub;
  }, []);

  // Compute canonical email category for each case using deriveEmailCategory
  const enrichedCases = useMemo(() => {
    return cases.map((c) => {
      const cat = deriveEmailCategory(c.investigationData);
      return {
        ...c,
        primaryCategory: cat.primaryCategory,
      };
    });
  }, [cases]);

  // Extract unique categories represented across cases
  const availableCategories = useMemo(() => {
    const set = new Set<string>();
    enrichedCases.forEach((c) => {
      if (c.primaryCategory) {
        set.add(c.primaryCategory);
      }
    });
    return Array.from(set).sort();
  }, [enrichedCases]);

  // Filtered reports
  const filteredReports = useMemo(() => {
    return enrichedCases.filter((c) => {
      if (filterSeverity !== 'ALL' && c.severity.toUpperCase() !== filterSeverity.toUpperCase()) {
        return false;
      }
      if (filterCategory !== 'ALL' && c.primaryCategory !== filterCategory) {
        return false;
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const matchId = c.id.toLowerCase().includes(q);
        const matchSubject = c.subject.toLowerCase().includes(q);
        const matchSender = c.sender.toLowerCase().includes(q);
        const matchCat = c.primaryCategory.toLowerCase().includes(q);
        return matchId || matchSubject || matchSender || matchCat;
      }
      return true;
    });
  }, [enrichedCases, filterSeverity, filterCategory, searchQuery]);

  const handleDownloadReport = async (c: CaseRecord) => {
    setDownloadingId(c.id);
    try {
      const blob = await downloadForensicReportPdf(c.investigationData, c.id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `Forensic_Investigation_Report_${c.id}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch {
      window.print();
    } finally {
      setDownloadingId(null);
    }
  };

  const getSeverityBadgeClass = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
        return 'text-[var(--severity-critical)] bg-[var(--surface-elevated)] border-[var(--border-subtle)]';
      case 'high':
        return 'text-[var(--severity-critical)] bg-[var(--surface-elevated)] border-[var(--border-subtle)]';
      case 'medium':
        return 'text-[var(--severity-medium)] bg-[var(--surface-elevated)] border-[var(--border-subtle)]';
      default:
        return 'text-[var(--severity-low)] bg-[var(--surface-elevated)] border-[var(--border-subtle)]';
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto py-2 font-sans select-none">
      {/* Header Section */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-[var(--border-subtle)]">
        <div>
          <div className="flex items-center space-x-2 text-xs font-mono text-[var(--text-dim)] uppercase tracking-widest mb-1">
            <FileSpreadsheet className="w-4 h-4 text-[var(--identifier)]" />
            <span>Forensic Dossiers & Export Library</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-[var(--text)] uppercase font-mono">
            Reports
          </h1>
          <p className="text-xs text-[var(--text-muted)] mt-1">
            Completed forensic investigation reports available for inspection and PDF export.
          </p>
        </div>

        {onNavigateNewInvestigation && (
          <button
            type="button"
            onClick={onNavigateNewInvestigation}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded bg-[var(--surface-elevated)] hover:bg-[var(--surface-hover)] border border-[var(--border)] text-xs font-mono font-semibold text-[var(--text)] transition-colors cursor-pointer self-start md:self-auto"
          >
            <PlusCircle className="w-4 h-4 text-[var(--identifier)]" />
            <span>START NEW INVESTIGATION</span>
          </button>
        )}
      </div>

      {/* Filter Controls & Search */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-3 text-xs font-mono">
        {/* Search Input */}
        <div className="md:col-span-6 relative">
          <Search className="w-3.5 h-3.5 absolute left-3 top-3 text-[var(--text-dim)] pointer-events-none" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search reports by Case ID, Subject, Sender, or Category..."
            className="w-full pl-9 pr-3 py-2 bg-[var(--surface-subtle)] border border-[var(--border-subtle)] rounded text-[var(--text)] placeholder-[var(--text-dim)] focus:outline-none focus:border-[var(--border)] text-xs font-mono"
          />
        </div>

        {/* Severity Filter */}
        <div className="md:col-span-3">
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="w-full px-3 py-2 bg-[var(--surface-subtle)] border border-[var(--border-subtle)] rounded text-[var(--text)] focus:outline-none focus:border-[var(--border)] text-xs font-mono cursor-pointer"
          >
            <option value="ALL">Severity: All</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>

        {/* Category Filter */}
        <div className="md:col-span-3">
          <select
            value={filterCategory}
            onChange={(e) => setFilterCategory(e.target.value)}
            className="w-full px-3 py-2 bg-[var(--surface-subtle)] border border-[var(--border-subtle)] rounded text-[var(--text)] focus:outline-none focus:border-[var(--border)] text-xs font-mono cursor-pointer truncate"
          >
            <option value="ALL">Category: All</option>
            {availableCategories.map((cat) => (
              <option key={cat} value={cat}>
                {cat}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Reports Table / List */}
      {cases.length === 0 ? (
        /* Zero Cases Stored Empty State */
        <div className="surface-card p-12 text-center border border-[var(--border-subtle)] rounded-lg space-y-4 max-w-md mx-auto my-8 font-sans">
          <div className="w-12 h-12 rounded bg-[var(--surface-elevated)] border border-[var(--border-subtle)] mx-auto flex items-center justify-center text-[var(--text-dim)]">
            <FileSpreadsheet className="w-6 h-6 text-[var(--text-muted)]" />
          </div>
          <div className="space-y-1 font-mono">
            <h2 className="text-sm font-bold text-[var(--text)] uppercase tracking-wider">
              No Forensic Reports Available Yet
            </h2>
            <p className="text-xs text-[var(--text-muted)] font-sans">
              Complete an email investigation to automatically generate a downloadable forensic dossier report.
            </p>
          </div>
          {onNavigateNewInvestigation && (
            <button
              type="button"
              onClick={onNavigateNewInvestigation}
              className="px-4 py-2 rounded bg-[var(--surface-elevated)] hover:bg-[var(--surface-hover)] border border-[var(--border)] text-xs font-mono text-[var(--text)] inline-flex items-center gap-1.5 transition-colors cursor-pointer font-semibold"
            >
              <PlusCircle className="w-3.5 h-3.5 text-[var(--identifier)]" />
              <span>START NEW INVESTIGATION</span>
            </button>
          )}
        </div>
      ) : filteredReports.length === 0 ? (
        /* No Search / Filter Matches State */
        <div className="surface-card p-8 text-center border border-[var(--border-subtle)] rounded-lg text-xs font-mono text-[var(--text-muted)] space-y-2">
          <p>No forensic reports match your filter criteria.</p>
          <button
            type="button"
            onClick={() => {
              setSearchQuery('');
              setFilterSeverity('ALL');
              setFilterCategory('ALL');
            }}
            className="text-[var(--identifier)] hover:underline cursor-pointer"
          >
            Clear Search & Filters
          </button>
        </div>
      ) : (
        /* Reports Table List */
        <div className="border border-[var(--border-subtle)] rounded-lg overflow-hidden bg-[var(--surface-subtle)] divide-y divide-[var(--border-subtle)]">
          {filteredReports.map((c) => {
            const isDownloading = downloadingId === c.id;
            const confidence = c.investigationData?.risk_assessment?.confidence?.level?.toUpperCase() || 'HIGH';

            return (
              <div
                key={c.id}
                className="p-4 hover:bg-[var(--surface-hover)] transition-colors flex flex-col md:flex-row md:items-center justify-between gap-4 font-sans"
              >
                {/* Left Meta Information */}
                <div className="space-y-1.5 min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
                    <span className="font-bold text-[var(--identifier)]">{c.id}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${getSeverityBadgeClass(c.severity)}`}>
                      {c.severity}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-[var(--surface-elevated)] border border-[var(--border-subtle)] text-[10px] text-[var(--text-dim)] font-mono">
                      SCORE: <strong className="text-[var(--text)]">{c.riskScore}/100</strong>
                    </span>
                    <span className="px-2 py-0.5 rounded bg-[var(--surface-elevated)] border border-[var(--border-subtle)] text-[10px] text-[var(--text-dim)] font-mono">
                      CONFIDENCE: <strong className="text-[var(--state-pass)]">{confidence}</strong>
                    </span>
                    {(c.id === 'CASE-2026-6142' || Boolean((c as any).isDemo)) && (
                      <span className="px-1.5 py-0.2 rounded bg-[var(--surface-elevated)] text-[var(--severity-medium)] border border-[var(--border-subtle)] text-[9px] font-mono font-bold uppercase">
                        DEMO
                      </span>
                    )}
                  </div>

                  <h3 className="text-sm font-semibold text-[var(--text)] truncate max-w-xl" title={c.subject}>
                    {c.subject || 'No Subject Line'}
                  </h3>

                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-[var(--text-muted)] font-mono">
                    <span className="truncate max-w-xs" title={c.sender}>
                      SENDER: <strong className="text-[var(--text)]">{c.sender || 'Unspecified'}</strong>
                    </span>
                    <span className="text-[var(--text-dim)]">•</span>
                    <span className="text-[var(--text)] font-medium">
                      {c.primaryCategory}
                    </span>
                    <span className="text-[var(--text-dim)]">•</span>
                    <span className="text-[var(--text-dim)]" title={c.createdAt}>
                      {formatISTTimestamp(c.createdAt, 'Unrecorded')}
                    </span>
                  </div>
                </div>

                {/* Right Action Buttons */}
                <div className="flex items-center gap-2 shrink-0 font-mono text-xs pt-2 md:pt-0 border-t md:border-t-0 border-[var(--border-subtle)]">
                  {onSelectCase && (
                    <button
                      type="button"
                      onClick={() => onSelectCase(c)}
                      className="px-3 py-1.5 rounded bg-[var(--surface)] hover:bg-[var(--surface-elevated)] border border-[var(--border-subtle)] hover:border-[var(--border)] text-[var(--text-muted)] hover:text-[var(--text)] inline-flex items-center gap-1.5 transition-colors cursor-pointer"
                    >
                      <ExternalLink className="w-3.5 h-3.5 text-[var(--text-dim)]" />
                      <span>VIEW CASE</span>
                    </button>
                  )}

                  <button
                    type="button"
                    onClick={() => handleDownloadReport(c)}
                    disabled={isDownloading}
                    className="px-3.5 py-1.5 rounded bg-[var(--surface-elevated)] hover:bg-[var(--surface-hover)] border border-[var(--border)] text-[var(--text)] inline-flex items-center gap-1.5 font-bold transition-colors cursor-pointer disabled:opacity-50"
                  >
                    {isDownloading ? (
                      <>
                        <Loader2 className="w-3.5 h-3.5 animate-spin text-[var(--identifier)]" />
                        <span>GENERATING...</span>
                      </>
                    ) : (
                      <>
                        <Download className="w-3.5 h-3.5 text-[var(--identifier)]" />
                        <span>DOWNLOAD REPORT</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
