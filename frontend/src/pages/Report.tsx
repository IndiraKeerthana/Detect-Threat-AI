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

  const enrichedCases = useMemo(() => {
    return cases.map((c) => {
      const cat = deriveEmailCategory(c.investigationData);
      return {
        ...c,
        primaryCategory: cat.primaryCategory,
      };
    });
  }, [cases]);

  const availableCategories = useMemo(() => {
    const set = new Set<string>();
    enrichedCases.forEach((c) => {
      if (c.primaryCategory) {
        set.add(c.primaryCategory);
      }
    });
    return Array.from(set).sort();
  }, [enrichedCases]);

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
      a.download = `Email_Safety_Report_${c.id}.pdf`;
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
      case 'high':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/20';
      case 'medium':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
      default:
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto py-2 font-sans">
      {/* Header Section */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-[var(--border-subtle)]">
        <div>
          <div className="flex items-center space-x-2 text-xs font-mono text-[var(--text-dim)] uppercase tracking-wider mb-1">
            <FileSpreadsheet className="w-4 h-4 text-[var(--identifier)]" />
            <span>Reports &amp; Downloads</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-[var(--text)]">
            Email Safety Reports
          </h1>
          <p className="text-xs text-[var(--text-muted)] mt-1">
            Completed investigation reports available for review and PDF download.
          </p>
        </div>

        {onNavigateNewInvestigation && (
          <button
            type="button"
            onClick={onNavigateNewInvestigation}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-[var(--surface-elevated)] hover:bg-[var(--surface-hover)] border border-[var(--border-subtle)] text-xs font-semibold text-[var(--text)] transition-colors cursor-pointer self-start md:self-auto shadow-sm"
          >
            <PlusCircle className="w-4 h-4 text-[var(--identifier)]" />
            <span>Check New Email</span>
          </button>
        )}
      </div>

      {/* Filter Controls & Search */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-3 text-xs font-sans">
        {/* Search Input */}
        <div className="md:col-span-6 relative">
          <Search className="w-4 h-4 absolute left-3.5 top-3 text-[var(--text-dim)] pointer-events-none" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search reports by Case ID, Subject, Sender, or Category..."
            className="w-full pl-9 pr-3 py-2 bg-[var(--surface-subtle)] border border-[var(--border-subtle)] rounded-xl text-[var(--text)] placeholder-[var(--text-dim)] focus:outline-none focus:border-[var(--border)] text-xs"
          />
        </div>

        {/* Severity Filter */}
        <div className="md:col-span-3">
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="w-full px-3 py-2 bg-[var(--surface-subtle)] border border-[var(--border-subtle)] rounded-xl text-[var(--text)] focus:outline-none focus:border-[var(--border)] text-xs cursor-pointer"
          >
            <option value="ALL">Risk Rating: All</option>
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
            className="w-full px-3 py-2 bg-[var(--surface-subtle)] border border-[var(--border-subtle)] rounded-xl text-[var(--text)] focus:outline-none focus:border-[var(--border)] text-xs cursor-pointer truncate"
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
        <div className="surface-card p-12 text-center border border-[var(--border-subtle)] rounded-2xl space-y-4 max-w-md mx-auto my-8 font-sans">
          <div className="w-12 h-12 rounded-full bg-[var(--surface-elevated)] border border-[var(--border-subtle)] mx-auto flex items-center justify-center text-[var(--text-dim)]">
            <FileSpreadsheet className="w-6 h-6 text-[var(--text-muted)]" />
          </div>
          <div className="space-y-1">
            <h2 className="text-sm font-bold text-[var(--text)] uppercase tracking-wider">
              No Safety Reports Available Yet
            </h2>
            <p className="text-xs text-[var(--text-muted)]">
              Complete an email check to automatically generate a downloadable safety report.
            </p>
          </div>
          {onNavigateNewInvestigation && (
            <button
              type="button"
              onClick={onNavigateNewInvestigation}
              className="px-4 py-2 rounded-xl bg-[var(--surface-elevated)] hover:bg-[var(--surface-hover)] border border-[var(--border-subtle)] text-xs font-semibold text-[var(--text)] inline-flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <PlusCircle className="w-4 h-4 text-[var(--identifier)]" />
              <span>Check New Email</span>
            </button>
          )}
        </div>
      ) : filteredReports.length === 0 ? (
        <div className="surface-card p-8 text-center border border-[var(--border-subtle)] rounded-2xl text-xs text-[var(--text-muted)] space-y-2">
          <p>No safety reports match your filter criteria.</p>
          <button
            type="button"
            onClick={() => {
              setSearchQuery('');
              setFilterSeverity('ALL');
              setFilterCategory('ALL');
            }}
            className="text-[var(--identifier)] hover:underline cursor-pointer font-semibold"
          >
            Clear Search &amp; Filters
          </button>
        </div>
      ) : (
        <div className="border border-[var(--border-subtle)] rounded-2xl overflow-hidden bg-[var(--surface-subtle)] divide-y divide-[var(--border-subtle)]">
          {filteredReports.map((c) => {
            const isDownloading = downloadingId === c.id;

            return (
              <div
                key={c.id}
                className="p-4 hover:bg-[var(--surface-hover)] transition-colors flex flex-col md:flex-row md:items-center justify-between gap-4 font-sans"
              >
                {/* Meta Information */}
                <div className="space-y-1.5 min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                    <span className="font-bold text-[var(--identifier)]">{c.id}</span>
                    <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-semibold uppercase border ${getSeverityBadgeClass(c.severity)}`}>
                      {c.severity}
                    </span>
                    <span className="px-2.5 py-0.5 rounded-full bg-[var(--surface-elevated)] border border-[var(--border-subtle)] text-[10px] text-[var(--text-muted)] font-mono">
                      Risk Score: <strong className="text-[var(--text)]">{c.riskScore}/100</strong>
                    </span>
                  </div>

                  <h3 className="text-sm font-semibold text-[var(--text)] truncate max-w-xl" title={c.subject}>
                    {c.subject || 'No Subject Line'}
                  </h3>

                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-[var(--text-muted)]">
                    <span className="truncate max-w-xs font-mono" title={c.sender}>
                      From: <strong className="text-[var(--text)]">{c.sender || 'Unspecified'}</strong>
                    </span>
                    <span>•</span>
                    <span className="text-[var(--text)] font-medium">
                      {c.primaryCategory}
                    </span>
                    <span>•</span>
                    <span className="text-[var(--text-dim)] font-mono" title={c.createdAt}>
                      {formatISTTimestamp(c.createdAt, 'Unrecorded')}
                    </span>
                  </div>
                </div>

                {/* Actions */}
                <div className="flex items-center gap-2 shrink-0 text-xs">
                  {onSelectCase && (
                    <button
                      type="button"
                      onClick={() => onSelectCase(c)}
                      className="px-3 py-1.5 rounded-lg bg-[var(--surface)] hover:bg-[var(--surface-elevated)] border border-[var(--border-subtle)] text-[var(--text-muted)] hover:text-[var(--text)] inline-flex items-center gap-1.5 transition-colors cursor-pointer font-medium"
                    >
                      <ExternalLink className="w-3.5 h-3.5 text-[var(--text-dim)]" />
                      <span>View Details</span>
                    </button>
                  )}

                  <button
                    type="button"
                    onClick={() => handleDownloadReport(c)}
                    disabled={isDownloading}
                    className="px-3.5 py-1.5 rounded-lg bg-[var(--surface-elevated)] hover:bg-[var(--surface-hover)] border border-[var(--border-subtle)] text-[var(--text)] inline-flex items-center gap-1.5 font-semibold transition-colors cursor-pointer disabled:opacity-50"
                  >
                    {isDownloading ? (
                      <>
                        <Loader2 className="w-3.5 h-3.5 animate-spin text-[var(--identifier)]" />
                        <span>Generating...</span>
                      </>
                    ) : (
                      <>
                        <Download className="w-3.5 h-3.5 text-[var(--identifier)]" />
                        <span>Download PDF</span>
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
