import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
  Search,
  ArrowUpRight,
  Plus,
  Filter,
  ArrowUpDown,
  RotateCcw,
  ShieldAlert,
  X,
  Download,
  Loader2,
  Layers,
  Network,
  Globe,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';
import {
  caseStore,
  getCampaignClusters,
  type CaseRecord,
  type CaseSeverity,
} from '../services/caseStore';
import { NewInvestigationModal } from '../components/cases/NewInvestigationModal';
import { formatISTTimestamp } from '../utils/dateFormatter';
import { downloadForensicReportPdf } from '../services/api';

interface CasesProps {
  onSelectCase: (caseRecord: CaseRecord) => void;
  onOpenNewInvestigation?: () => void;
}

type SortOption = 'activity_desc' | 'activity_asc' | 'score_desc' | 'score_asc';

export const Cases: React.FC<CasesProps> = ({ onSelectCase }) => {
  const [cases, setCases] = useState<CaseRecord[]>(caseStore.getCases());
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');
  const [filterStatus, setFilterStatus] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [sortBy, setSortBy] = useState<SortOption>('activity_desc');
  const [viewMode, setViewMode] = useState<'INDIVIDUAL' | 'CAMPAIGNS'>('INDIVIDUAL');
  const [expandedCampaigns, setExpandedCampaigns] = useState<Record<string, boolean>>({});
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [openDropdown, setOpenDropdown] = useState<'RISK' | 'STATUS' | null>(null);

  const riskDropdownRef = useRef<HTMLDivElement>(null);
  const statusDropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        openDropdown === 'RISK' &&
        riskDropdownRef.current &&
        !riskDropdownRef.current.contains(event.target as Node)
      ) {
        setOpenDropdown(null);
      }
      if (
        openDropdown === 'STATUS' &&
        statusDropdownRef.current &&
        !statusDropdownRef.current.contains(event.target as Node)
      ) {
        setOpenDropdown(null);
      }
    };

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setOpenDropdown(null);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [openDropdown]);

  const handleDownloadCaseReport = async (caseRecord: CaseRecord) => {
    setDownloadingId(caseRecord.id);
    try {
      const blob = await downloadForensicReportPdf(caseRecord.investigationData, caseRecord.id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `Email_Safety_Report_${caseRecord.id}.pdf`;
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

  useEffect(() => {
    const unsubscribe = caseStore.subscribe(() => {
      setCases(caseStore.getCases());
    });
    return unsubscribe;
  }, []);

  const campaignClusters = useMemo(() => {
    return getCampaignClusters(cases);
  }, [cases]);

  const filteredCases = useMemo(() => {
    return cases
      .filter((c) => {
        if (filterSeverity !== 'ALL' && c.severity.toUpperCase() !== filterSeverity.toUpperCase()) {
          return false;
        }
        if (filterStatus !== 'ALL' && c.status.toUpperCase() !== filterStatus.toUpperCase()) {
          return false;
        }
        if (searchQuery.trim()) {
          const q = searchQuery.toLowerCase().trim();
          const matchId = c.id.toLowerCase().includes(q);
          const matchSubject = c.subject.toLowerCase().includes(q);
          const matchSender = c.sender.toLowerCase().includes(q);
          const matchIp = c.sourceIp ? c.sourceIp.toLowerCase().includes(q) : false;
          return matchId || matchSubject || matchSender || matchIp;
        }
        return true;
      })
      .sort((a, b) => {
        switch (sortBy) {
          case 'score_desc':
            return b.riskScore - a.riskScore;
          case 'score_asc':
            return a.riskScore - b.riskScore;
          case 'activity_asc':
            return new Date(a.updatedAt).getTime() - new Date(b.updatedAt).getTime();
          case 'activity_desc':
          default:
            return new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime();
        }
      });
  }, [cases, filterSeverity, filterStatus, searchQuery, sortBy]);

  const statusCounts = useMemo(() => {
    return {
      open: cases.filter((c) => c.status === 'OPEN').length,
      inReview: cases.filter((c) => c.status === 'IN REVIEW').length,
      contained: cases.filter((c) => c.status === 'CONTAINED').length,
      closed: cases.filter((c) => c.status === 'CLOSED').length,
    };
  }, [cases]);

  const getSeverityBadgeClass = (sev: CaseSeverity) => {
    switch (sev.toUpperCase()) {
      case 'CRITICAL':
      case 'HIGH':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/20';
      case 'MEDIUM':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
      case 'LOW':
      default:
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
    }
  };

  const resetFilters = () => {
    setFilterSeverity('ALL');
    setFilterStatus('ALL');
    setSearchQuery('');
    setSortBy('activity_desc');
    setOpenDropdown(null);
  };

  const handleCaseCreated = (newCase: CaseRecord) => {
    onSelectCase(newCase);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto py-2 font-sans">
      {/* 1. Header Area */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[var(--border-subtle)]">
        <div>
          <div className="flex items-center space-x-2 text-xs font-mono text-[var(--text-dim)] uppercase">
            <span>Case Directory</span>
            <span>/</span>
            <span className="text-[var(--text-muted)]">Saved Checks</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-[var(--text)] mt-1">
            All Cases &amp; Investigations
          </h1>
          <p className="text-xs text-[var(--text-muted)] mt-1 font-sans">
            Search, filter, and review all email safety checks and saved cases.
          </p>
        </div>

        <div className="flex items-center space-x-3 self-start sm:self-auto">
          <button
            type="button"
            onClick={() => setIsModalOpen(true)}
            className="px-4 py-2 rounded-xl bg-[var(--surface-elevated)] hover:bg-[var(--surface-hover)] text-[var(--text)] text-xs font-semibold inline-flex items-center gap-2 border border-[var(--border-subtle)] shadow-sm transition-colors cursor-pointer"
          >
            <Plus className="w-4 h-4 text-[var(--identifier)]" />
            <span>Check New Email</span>
          </button>
        </div>
      </div>

      {/* 2. Control Bar */}
      <div className="surface-card p-4 border border-[var(--border-subtle)] rounded-2xl space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          {/* Search Box */}
          <div className="relative flex-1 max-w-lg">
            <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-[var(--text-dim)] pointer-events-none" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by Case ID, subject, sender, or IP address..."
              className="w-full bg-[var(--surface)] border border-[var(--border-subtle)] hover:border-[var(--border)] focus:border-[var(--border-active)] rounded-xl px-3 py-2 pl-9 pr-8 text-xs text-[var(--text)] placeholder-[var(--text-disabled)] outline-none transition-colors"
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => setSearchQuery('')}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[var(--text-dim)] hover:text-[var(--text)]"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* Quick Metrics */}
          <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-[var(--text-muted)]">
            <span className="px-3 py-1 rounded-full bg-[var(--surface-subtle)] border border-[var(--border-subtle)]">
              TOTAL: <strong className="text-[var(--text)]">{cases.length}</strong>
            </span>
            <span className="px-3 py-1 rounded-full bg-[var(--surface-subtle)] border border-[var(--border-subtle)]">
              OPEN: <strong className="text-[var(--identifier)]">{statusCounts.open}</strong>
            </span>
            <span className="px-3 py-1 rounded-full bg-[var(--surface-subtle)] border border-[var(--border-subtle)]">
              REVIEW: <strong className="text-amber-400">{statusCounts.inReview}</strong>
            </span>
            <span className="px-3 py-1 rounded-full bg-[var(--surface-subtle)] border border-[var(--border-subtle)]">
              RESOLVED: <strong className="text-emerald-400">{statusCounts.contained}</strong>
            </span>
          </div>

          {/* Sort Selector */}
          <div className="flex items-center space-x-2 text-xs self-end lg:self-auto">
            <ArrowUpDown className="w-3.5 h-3.5 text-[var(--text-dim)]" />
            <span className="text-[var(--text-dim)] font-mono hidden sm:inline">Sort:</span>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as SortOption)}
              className="bg-[var(--surface)] border border-[var(--border-subtle)] focus:border-[var(--border-active)] rounded-xl px-3 py-1.5 text-xs text-[var(--text)] font-sans outline-none cursor-pointer"
            >
              <option value="activity_desc">Newest First</option>
              <option value="activity_asc">Oldest First</option>
              <option value="score_desc">Highest Risk Score</option>
              <option value="score_asc">Lowest Risk Score</option>
            </select>
          </div>
        </div>

        {/* Filter Chips & View Switcher */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-[var(--border-subtle)] text-xs font-sans">
          {/* View Mode Toggle */}
          <div className="flex items-center space-x-1.5 bg-[var(--surface-subtle)] p-1 rounded-xl border border-[var(--border-subtle)]">
            <button
              type="button"
              onClick={() => setViewMode('INDIVIDUAL')}
              className={`px-3 py-1 rounded-lg text-xs font-semibold transition-colors cursor-pointer ${
                viewMode === 'INDIVIDUAL'
                  ? 'bg-[var(--surface-elevated)] text-[var(--text)] border border-[var(--border-subtle)] shadow-sm'
                  : 'text-[var(--text-dim)] hover:text-[var(--text)]'
              }`}
            >
              Individual Cases ({filteredCases.length})
            </button>
            <button
              type="button"
              onClick={() => setViewMode('CAMPAIGNS')}
              className={`px-3 py-1 rounded-lg text-xs font-semibold transition-colors cursor-pointer ${
                viewMode === 'CAMPAIGNS'
                  ? 'bg-[var(--surface-elevated)] text-[var(--text)] border border-[var(--border-subtle)] shadow-sm'
                  : 'text-[var(--text-dim)] hover:text-[var(--text)]'
              }`}
            >
              Grouped Campaigns ({campaignClusters.length})
            </button>
          </div>

          {/* Severity & Status Dropdown Filters */}
          <div className="flex flex-wrap items-center gap-2.5">
            {/* Risk Dropdown */}
            <div className="relative" ref={riskDropdownRef}>
              <button
                type="button"
                onClick={() => setOpenDropdown(openDropdown === 'RISK' ? null : 'RISK')}
                className={`px-3 py-1.5 rounded-xl text-xs font-medium transition-all inline-flex items-center gap-1.5 cursor-pointer ${
                  filterSeverity !== 'ALL'
                    ? 'bg-[var(--surface-elevated)] text-[var(--text)] border border-[var(--border-active)] shadow-xs font-semibold'
                    : 'bg-[var(--surface-subtle)] text-[var(--text-muted)] hover:text-[var(--text)] hover:bg-[var(--surface)] border border-[var(--border-subtle)]'
                }`}
              >
                <Filter className="w-3 h-3 text-[var(--text-dim)]" />
                <span>
                  {filterSeverity === 'ALL'
                    ? 'Risk ▾'
                    : `Risk: ${filterSeverity.charAt(0) + filterSeverity.slice(1).toLowerCase()} ▾`}
                </span>
              </button>

              {openDropdown === 'RISK' && (
                <div className="absolute left-0 mt-1.5 w-36 bg-[var(--surface)] border border-[var(--border)] rounded-xl shadow-lg py-1.5 z-30 space-y-0.5">
                  {[
                    { key: 'ALL', label: 'All' },
                    { key: 'CRITICAL', label: 'Critical' },
                    { key: 'HIGH', label: 'High' },
                    { key: 'MEDIUM', label: 'Medium' },
                    { key: 'LOW', label: 'Low' },
                  ].map((item) => (
                    <button
                      key={item.key}
                      type="button"
                      onClick={() => {
                        setFilterSeverity(item.key);
                        setOpenDropdown(null);
                      }}
                      className={`w-full text-left px-3.5 py-1.5 text-xs transition-colors flex items-center justify-between cursor-pointer ${
                        filterSeverity === item.key
                          ? 'bg-[var(--surface-elevated)] text-[var(--text)] font-semibold'
                          : 'text-[var(--text-muted)] hover:text-[var(--text)] hover:bg-[var(--surface-hover)]'
                      }`}
                    >
                      <span>{item.label}</span>
                      {filterSeverity === item.key && <span className="text-[var(--identifier)] font-bold">✓</span>}
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* Status Dropdown */}
            <div className="relative" ref={statusDropdownRef}>
              <button
                type="button"
                onClick={() => setOpenDropdown(openDropdown === 'STATUS' ? null : 'STATUS')}
                className={`px-3 py-1.5 rounded-xl text-xs font-medium transition-all inline-flex items-center gap-1.5 cursor-pointer ${
                  filterStatus !== 'ALL'
                    ? 'bg-[var(--surface-elevated)] text-[var(--text)] border border-[var(--border-active)] shadow-xs font-semibold'
                    : 'bg-[var(--surface-subtle)] text-[var(--text-muted)] hover:text-[var(--text)] hover:bg-[var(--surface)] border border-[var(--border-subtle)]'
                }`}
              >
                <span>
                  {filterStatus === 'ALL'
                    ? 'Status ▾'
                    : `Status: ${filterStatus.split(' ').map((w) => w.charAt(0) + w.slice(1).toLowerCase()).join(' ')} ▾`}
                </span>
              </button>

              {openDropdown === 'STATUS' && (
                <div className="absolute left-0 mt-1.5 w-36 bg-[var(--surface)] border border-[var(--border)] rounded-xl shadow-lg py-1.5 z-30 space-y-0.5">
                  {[
                    { key: 'ALL', label: 'All' },
                    { key: 'OPEN', label: 'Open' },
                    { key: 'IN REVIEW', label: 'In Review' },
                    { key: 'CONTAINED', label: 'Contained' },
                    { key: 'CLOSED', label: 'Closed' },
                  ].map((item) => (
                    <button
                      key={item.key}
                      type="button"
                      onClick={() => {
                        setFilterStatus(item.key);
                        setOpenDropdown(null);
                      }}
                      className={`w-full text-left px-3.5 py-1.5 text-xs transition-colors flex items-center justify-between cursor-pointer ${
                        filterStatus === item.key
                          ? 'bg-[var(--surface-elevated)] text-[var(--text)] font-semibold'
                          : 'text-[var(--text-muted)] hover:text-[var(--text)] hover:bg-[var(--surface-hover)]'
                      }`}
                    >
                      <span>{item.label}</span>
                      {filterStatus === item.key && <span className="text-[var(--identifier)] font-bold">✓</span>}
                    </button>
                  ))}
                </div>
              )}
            </div>

            {(filterSeverity !== 'ALL' || filterStatus !== 'ALL' || searchQuery) && (
              <button
                type="button"
                onClick={resetFilters}
                className="ml-1 text-[var(--identifier)] hover:underline text-xs flex items-center gap-1 transition-colors cursor-pointer font-medium"
              >
                <RotateCcw className="w-3 h-3" />
                Reset
              </button>
            )}
          </div>
        </div>
      </div>

      {/* 3. Main Queue Display */}
      {viewMode === 'CAMPAIGNS' ? (
        /* CAMPAIGN CLUSTERS VIEW */
        <div className="space-y-4">
          {campaignClusters.length > 0 ? (
            campaignClusters.map((cluster) => {
              const isExpanded = Boolean(expandedCampaigns[cluster.id]);
              const sharedIp = cluster.sharedIndicators.find((ind) => ind.type === 'ip')?.value || 'None';
              const sharedDomain = cluster.sharedIndicators.find((ind) => ind.type === 'domain')?.value || 'None';

              return (
                <div
                  key={cluster.id}
                  className="surface-card border border-[var(--border-subtle)] rounded-2xl overflow-hidden"
                >
                  <div className="p-4 bg-[var(--surface-subtle)] border-b border-[var(--border-subtle)] flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <div className="space-y-1.5">
                      <div className="flex items-center space-x-2.5">
                        <span className="text-xs text-[var(--identifier)] font-bold font-mono px-2.5 py-0.5 rounded-full bg-[var(--surface-elevated)] border border-[var(--border-subtle)]">
                          {cluster.id}
                        </span>
                        <h2 className="text-sm font-bold text-[var(--text)] truncate max-w-lg" title={cluster.title}>
                          {cluster.title}
                        </h2>
                      </div>
                      <div className="flex flex-wrap items-center gap-2 text-xs text-[var(--text-muted)]">
                        <span className="text-[var(--identifier)] font-semibold font-mono">
                          {cluster.caseCount} Linked Cases
                        </span>
                        <span>•</span>
                        <span>
                          Date range: <strong className="text-[var(--text)] font-mono">{cluster.dateRange.earliest} — {cluster.dateRange.latest}</strong>
                        </span>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-2 self-start md:self-auto">
                      <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold border uppercase ${getSeverityBadgeClass(cluster.highestSeverity)}`}>
                        {cluster.highestSeverity} Risk
                      </span>

                      <button
                        type="button"
                        onClick={() =>
                          setExpandedCampaigns((prev) => ({
                            ...prev,
                            [cluster.id]: !prev[cluster.id],
                          }))
                        }
                        className="px-3.5 py-1.5 rounded-xl bg-[var(--surface-elevated)] hover:bg-[var(--surface-hover)] text-[var(--text)] text-xs font-semibold border border-[var(--border-subtle)] transition-colors inline-flex items-center gap-1 cursor-pointer"
                      >
                        {isExpanded ? (
                          <>
                            <span>Hide Cases</span>
                            <ChevronDown className="w-3.5 h-3.5" />
                          </>
                        ) : (
                          <>
                            <span>View Linked Cases</span>
                            <ChevronRight className="w-3.5 h-3.5" />
                          </>
                        )}
                      </button>
                    </div>
                  </div>

                  {/* Shared Info */}
                  <div className="p-4 bg-[var(--surface)] grid grid-cols-1 md:grid-cols-2 gap-3 border-b border-[var(--border-subtle)] text-xs">
                    <div className="bg-[var(--surface-subtle)] p-3 rounded-xl border border-[var(--border-subtle)] space-y-1">
                      <div className="text-[11px] text-[var(--text-dim)] uppercase font-mono flex items-center gap-1">
                        <Network className="w-3.5 h-3.5 text-[var(--identifier)]" /> Shared Source IP
                      </div>
                      <div className="font-bold text-[var(--identifier)] font-mono">{sharedIp}</div>
                    </div>

                    <div className="bg-[var(--surface-subtle)] p-3 rounded-xl border border-[var(--border-subtle)] space-y-1">
                      <div className="text-[11px] text-[var(--text-dim)] uppercase font-mono flex items-center gap-1">
                        <Globe className="w-3.5 h-3.5 text-[var(--identifier)]" /> Shared Sender Domain
                      </div>
                      <div className="font-bold text-[var(--text)] font-mono">{sharedDomain}</div>
                    </div>
                  </div>

                  {/* Expandable Cases */}
                  {isExpanded && (
                    <div className="p-4 bg-[var(--surface)] space-y-3">
                      <div className="text-xs font-mono text-[var(--text-dim)] uppercase">
                        Linked Cases ({cluster.cases.length})
                      </div>
                      <div className="divide-y divide-[var(--border-subtle)]">
                        {cluster.cases.map((c: CaseRecord) => (
                          <div
                            key={c.id}
                            onClick={() => onSelectCase(c)}
                            className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-[var(--surface-hover)] p-2 rounded-xl transition-colors cursor-pointer"
                          >
                            <div className="space-y-1 min-w-0 flex-1">
                              <div className="flex items-center gap-2">
                                <span className="font-bold text-[var(--identifier)] font-mono text-xs">{c.id}</span>
                                <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase border ${getSeverityBadgeClass(c.severity)}`}>
                                  {c.severity}
                                </span>
                                <span className="text-xs font-mono text-[var(--text-muted)]">Risk Score: <strong className="text-[var(--text)]">{c.riskScore}/100</strong></span>
                              </div>
                              <div className="text-xs font-medium text-[var(--text)] truncate">{c.subject || '(No Subject)'}</div>
                              <div className="text-[11px] text-[var(--text-dim)] truncate">From: {c.sender}</div>
                            </div>

                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                onSelectCase(c);
                              }}
                              className="px-3 py-1.5 rounded-lg bg-[var(--surface-elevated)] hover:bg-[var(--surface-hover)] text-[var(--text)] text-xs font-medium inline-flex items-center gap-1 transition-colors cursor-pointer self-start sm:self-auto"
                            >
                              <span>View Details</span>
                              <ArrowUpRight className="w-3.5 h-3.5 text-[var(--identifier)]" />
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              );
            })
          ) : (
            <div className="surface-card p-12 border border-[var(--border-subtle)] rounded-2xl text-center space-y-3">
              <div className="w-12 h-12 rounded-full bg-[var(--surface)] border border-[var(--border-subtle)] mx-auto flex items-center justify-center text-[var(--text-dim)]">
                <Layers className="w-6 h-6 text-[var(--text-dim)]" />
              </div>
              <h3 className="text-sm font-bold text-[var(--text)]">No Linked Campaigns</h3>
              <p className="text-xs text-[var(--text-muted)] max-w-md mx-auto">
                Campaign grouping appears automatically when multiple cases share the same sending IP or domain.
              </p>
            </div>
          )}
        </div>
      ) : (
        /* INDIVIDUAL CASES VIEW */
        <div className="surface-card border border-[var(--border-subtle)] rounded-2xl overflow-hidden">
          {filteredCases.length > 0 ? (
            <>
              {/* Desktop Table View */}
              <div className="overflow-x-auto hidden md:block">
                <table className="w-full text-left text-xs font-sans">
                  <thead className="bg-[var(--surface-subtle)] border-b border-[var(--border-subtle)] text-[var(--text-dim)] text-[11px] font-mono uppercase">
                    <tr>
                      <th className="py-3 px-4">Case ID</th>
                      <th className="py-3 px-4">Subject / Sender</th>
                      <th className="py-3 px-4">Risk Level</th>
                      <th className="py-3 px-4">Email Type</th>
                      <th className="py-3 px-4">Risk Score</th>
                      <th className="py-3 px-4">Date</th>
                      <th className="py-3 px-4 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--border-subtle)]">
                    {filteredCases.map((c) => (
                      <tr
                        key={c.id}
                        onClick={() => onSelectCase(c)}
                        className="hover:bg-[var(--surface-hover)] cursor-pointer transition-colors"
                      >
                        <td className="py-3.5 px-4 whitespace-nowrap font-mono font-bold text-[var(--identifier)]">
                          {c.id}
                        </td>
                        <td className="py-3.5 px-4 max-w-xs">
                          <div className="font-semibold text-[var(--text)] truncate" title={c.subject}>
                            {c.subject || '(No Subject Provided)'}
                          </div>
                          <div className="text-[11px] text-[var(--text-dim)] font-mono truncate" title={c.sender}>
                            From: {c.sender}
                          </div>
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap">
                          <span className={`px-2.5 py-0.5 rounded-full text-[11px] font-semibold uppercase border ${getSeverityBadgeClass(c.severity)}`}>
                            {c.severity}
                          </span>
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap text-[var(--text-muted)] text-xs">
                          {c.classification}
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap font-mono">
                          <span className="font-bold text-[var(--text)]">{c.riskScore}</span>
                          <span className="text-[var(--text-dim)] text-[11px]"> / 100</span>
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap text-[var(--text-dim)] text-[11px] font-mono">
                          {formatISTTimestamp(c.updatedAt)}
                        </td>
                        <td className="py-3.5 px-4 text-right whitespace-nowrap">
                          <div className="flex items-center justify-end space-x-2">
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                handleDownloadCaseReport(c);
                              }}
                              disabled={downloadingId === c.id}
                              className="px-2.5 py-1 rounded-lg bg-[var(--surface-elevated)] hover:bg-[var(--surface-hover)] text-[var(--text-muted)] hover:text-[var(--text)] text-[11px] font-mono border border-[var(--border-subtle)] transition-colors inline-flex items-center gap-1 cursor-pointer"
                              title="Download PDF report"
                            >
                              {downloadingId === c.id ? (
                                <Loader2 className="w-3 h-3 animate-spin text-[var(--identifier)]" />
                              ) : (
                                <Download className="w-3 h-3" />
                              )}
                              <span>PDF</span>
                            </button>
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                onSelectCase(c);
                              }}
                              className="px-3 py-1 rounded-lg bg-[var(--surface-elevated)] hover:bg-[var(--surface-hover)] text-[var(--text)] text-xs font-semibold border border-[var(--border-subtle)] transition-colors inline-flex items-center gap-1 cursor-pointer"
                            >
                              <span>View Details</span>
                              <ArrowUpRight className="w-3.5 h-3.5 text-[var(--identifier)]" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Mobile Card List */}
              <div className="block md:hidden divide-y divide-[var(--border-subtle)]">
                {filteredCases.map((c) => (
                  <div
                    key={c.id}
                    onClick={() => onSelectCase(c)}
                    className="p-4 space-y-3 hover:bg-[var(--surface-hover)] cursor-pointer"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-[var(--identifier)] font-mono text-xs">{c.id}</span>
                      <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-semibold border uppercase ${getSeverityBadgeClass(c.severity)}`}>
                        {c.severity}
                      </span>
                    </div>

                    <div className="space-y-1">
                      <h4 className="text-sm font-semibold text-[var(--text)] leading-snug">
                        {c.subject || '(No Subject)'}
                      </h4>
                      <p className="text-xs text-[var(--text-dim)] truncate">From: {c.sender}</p>
                    </div>

                    <div className="flex items-center justify-between text-xs pt-2 border-t border-[var(--border-subtle)]">
                      <span className="text-[var(--text-muted)]">Risk Score: <strong className="text-[var(--text)]">{c.riskScore}/100</strong></span>
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectCase(c);
                        }}
                        className="px-3 py-1 rounded-lg bg-[var(--surface-elevated)] text-[var(--text)] text-xs font-semibold border border-[var(--border-subtle)]"
                      >
                        View Details →
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </>
          ) : (
            /* Empty State */
            <div className="p-12 text-center font-sans space-y-4">
              <div className="max-w-md mx-auto space-y-3">
                <div className="w-12 h-12 rounded-full bg-[var(--surface)] border border-[var(--border-subtle)] mx-auto flex items-center justify-center text-[var(--text-muted)]">
                  <ShieldAlert className="w-6 h-6 text-[var(--identifier)]" />
                </div>
                <div className="space-y-1">
                  <h3 className="text-sm font-bold text-[var(--text)]">
                    No Matching Cases Found
                  </h3>
                  <p className="text-xs text-[var(--text-muted)]">
                    No investigation records matched your search query or active filter settings.
                  </p>
                </div>
                <div className="pt-2">
                  <button
                    type="button"
                    onClick={resetFilters}
                    className="px-4 py-2 rounded-xl bg-[var(--surface-elevated)] hover:bg-[var(--surface-hover)] text-[var(--text)] border border-[var(--border-subtle)] text-xs font-semibold inline-flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    <RotateCcw className="w-3.5 h-3.5 text-[var(--identifier)]" />
                    Reset All Filters
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* 4. New Investigation Modal */}
      <NewInvestigationModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onInvestigationCreated={handleCaseCreated}
      />
    </div>
  );
};
