import React, { useState, useEffect, useMemo } from 'react';
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
  Link2,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
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

  const handleDownloadCaseReport = async (caseRecord: CaseRecord) => {
    setDownloadingId(caseRecord.id);
    try {
      const blob = await downloadForensicReportPdf(caseRecord.investigationData, caseRecord.id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `Forensic_Investigation_Report_${caseRecord.id}.pdf`;
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

  const getSeverityBadge = (sev: CaseSeverity) => {
    switch (sev.toUpperCase()) {
      case 'CRITICAL':
      case 'HIGH':
        return 'badge-critical';
      case 'MEDIUM':
        return 'badge-warning';
      case 'LOW':
      default:
        return 'badge-success';
    }
  };

  const resetFilters = () => {
    setFilterSeverity('ALL');
    setFilterStatus('ALL');
    setSearchQuery('');
    setSortBy('activity_desc');
  };

  const handleCaseCreated = (newCase: CaseRecord) => {
    onSelectCase(newCase);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto py-2">
      {/* 1. Header Area */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[var(--border-subtle)]">
        <div>
          <div className="flex items-center space-x-2 text-xs font-mono text-[var(--text-dim)] uppercase">
            <span>Case Management</span>
            <span>/</span>
            <span className="text-[var(--text-muted)]">Triage & Campaign Clusters</span>
          </div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-[var(--text)] mt-1 font-sans">
            Case registry & campaign clustering
          </h1>
          <p className="text-xs text-[var(--text-muted)] mt-0.5 font-sans">
            Persisted investigation records correlated across verified origin IPs, sender domains, and payload entities.
          </p>
        </div>

        <div className="flex items-center space-x-3 self-start sm:self-auto">
          <button
            type="button"
            onClick={() => setIsModalOpen(true)}
            className="px-4 py-2 rounded bg-[var(--surface-elevated)] hover:bg-[var(--surface-hover)] text-[var(--text)] text-xs font-mono font-medium inline-flex items-center gap-2 border border-[var(--border)] shadow-sm transition-colors cursor-pointer"
          >
            <Plus className="w-4 h-4 text-[var(--identifier)]" />
            <span>START NEW INVESTIGATION</span>
            <kbd className="text-[9px] text-[var(--text-dim)] bg-[var(--surface)] px-1 rounded border border-[var(--border-subtle)]">U</kbd>
          </button>
        </div>
      </div>

      {/* 2. Control Bar: Search + Filters + View Mode Switcher */}
      <div className="surface-card p-4 border border-[var(--border-subtle)] space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          {/* Search Box */}
          <div className="relative flex-1 max-w-lg">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-dim)]" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter by Case ID, subject, sender, domain, or IP address..."
              className="w-full bg-[var(--surface)] border border-[var(--border-subtle)] hover:border-[var(--border)] focus:border-[var(--border-active)] rounded px-3 py-1.5 pl-9 pr-8 text-xs text-[var(--text)] placeholder-[var(--text-disabled)] font-mono outline-none transition-colors"
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

          {/* Quick Metrics Pills */}
          <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-[var(--text-muted)]">
            <span className="px-2.5 py-1 rounded bg-[var(--surface-subtle)] border border-[var(--border-subtle)]">
              TOTAL: <strong className="text-[var(--text)]">{cases.length}</strong>
            </span>
            <span className="px-2.5 py-1 rounded bg-[var(--surface-subtle)] border border-[var(--border-subtle)]">
              OPEN: <strong className="text-[var(--identifier)]">{statusCounts.open}</strong>
            </span>
            <span className="px-2.5 py-1 rounded bg-[var(--surface-subtle)] border border-[var(--border-subtle)]">
              IN REVIEW: <strong className="text-[var(--severity-medium)]">{statusCounts.inReview}</strong>
            </span>
            <span className="px-2.5 py-1 rounded bg-[var(--surface-subtle)] border border-[var(--border-subtle)]">
              CONTAINED: <strong className="text-[var(--state-pass)]">{statusCounts.contained}</strong>
            </span>
          </div>

          {/* Sort Selector */}
          <div className="flex items-center space-x-2 text-xs font-mono self-end lg:self-auto">
            <ArrowUpDown className="w-3.5 h-3.5 text-[var(--text-dim)]" />
            <span className="text-[var(--text-dim)] hidden sm:inline">SORT:</span>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as SortOption)}
              className="bg-[var(--surface)] border border-[var(--border-subtle)] focus:border-[var(--border-active)] rounded px-2.5 py-1.5 text-xs text-[var(--text)] font-mono outline-none cursor-pointer"
            >
              <option value="activity_desc">LAST ACTIVITY (NEWEST)</option>
              <option value="activity_asc">LAST ACTIVITY (OLDEST)</option>
              <option value="score_desc">RISK SCORE (HIGH → LOW)</option>
              <option value="score_asc">RISK SCORE (LOW → HIGH)</option>
            </select>
          </div>
        </div>

        {/* Filter Chips & View Mode Switcher Row */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-[var(--border-subtle)] text-xs font-mono">
          {/* View Mode Toggle Switcher */}
          <div className="flex items-center space-x-1.5 bg-[var(--surface-subtle)] p-1 rounded border border-[var(--border-subtle)]">
            <button
              type="button"
              onClick={() => setViewMode('INDIVIDUAL')}
              className={`px-3 py-1 rounded text-xs font-bold transition-colors cursor-pointer ${
                viewMode === 'INDIVIDUAL'
                  ? 'bg-[var(--surface-elevated)] text-[var(--text)] border border-[var(--border)] shadow-sm'
                  : 'text-[var(--text-dim)] hover:text-[var(--text)]'
              }`}
            >
              INDIVIDUAL CASES ({filteredCases.length})
            </button>
            <button
              type="button"
              onClick={() => setViewMode('CAMPAIGNS')}
              className={`px-3 py-1 rounded text-xs font-bold transition-colors cursor-pointer ${
                viewMode === 'CAMPAIGNS'
                  ? 'bg-[var(--surface-elevated)] text-[var(--text)] border border-[var(--border)] shadow-sm'
                  : 'text-[var(--text-dim)] hover:text-[var(--text)]'
              }`}
            >
              CAMPAIGN CLUSTERS ({campaignClusters.length})
            </button>
          </div>

          {/* Severity & Status Filters */}
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[var(--text-dim)] text-[10px] uppercase tracking-wider mr-1 flex items-center gap-1">
                <Filter className="w-3 h-3" /> SEVERITY:
              </span>
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
                <button
                  key={sev}
                  type="button"
                  onClick={() => setFilterSeverity(sev)}
                  className={`px-2.5 py-0.5 rounded text-[11px] font-mono uppercase transition-colors cursor-pointer ${
                    filterSeverity === sev
                      ? 'bg-[var(--surface-elevated)] text-[var(--text)] border border-[var(--border)]'
                      : 'bg-[var(--surface)] text-[var(--text-dim)] hover:text-[var(--text)] border border-[var(--border-subtle)]'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>

            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[var(--text-dim)] text-[10px] uppercase tracking-wider mr-1">
                STATUS:
              </span>
              {['ALL', 'OPEN', 'IN REVIEW', 'CONTAINED', 'CLOSED'].map((st) => (
                <button
                  key={st}
                  type="button"
                  onClick={() => setFilterStatus(st)}
                  className={`px-2.5 py-0.5 rounded text-[11px] font-mono uppercase transition-colors cursor-pointer ${
                    filterStatus === st
                      ? 'bg-[var(--surface-elevated)] text-[var(--text)] border border-[var(--border)]'
                      : 'bg-[var(--surface)] text-[var(--text-dim)] hover:text-[var(--text)] border border-[var(--border-subtle)]'
                  }`}
                >
                  {st}
                </button>
              ))}

              {(filterSeverity !== 'ALL' || filterStatus !== 'ALL' || searchQuery) && (
                <button
                  type="button"
                  onClick={resetFilters}
                  className="ml-2 text-[var(--identifier)] hover:underline text-[11px] flex items-center gap-1 transition-colors cursor-pointer"
                  title="Reset all active filters"
                >
                  <RotateCcw className="w-3 h-3" />
                  Reset
                </button>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* 3. Main Queue & Campaign Cluster Display */}
      {viewMode === 'CAMPAIGNS' ? (
        /* CAMPAIGN CLUSTERS VIEW */
        <div className="space-y-4 font-mono">
          {campaignClusters.length > 0 ? (
            campaignClusters.map((cluster) => {
              const isExpanded = Boolean(expandedCampaigns[cluster.id]);
              const sharedIp = cluster.sharedIndicators.find((ind) => ind.type === 'ip')?.value || 'None';
              const sharedDomain = cluster.sharedIndicators.find((ind) => ind.type === 'domain')?.value || 'None';
              const sharedUrl = cluster.sharedIndicators.find((ind) => ind.type === 'url')?.value || 'None';

              return (
                <div
                  key={cluster.id}
                  className="surface-card border border-[var(--border-subtle)] hover:border-[var(--border)] transition-colors rounded-lg overflow-hidden"
                >
                  {/* Cluster Header Banner */}
                  <div className="p-4 bg-[var(--surface-subtle)] border-b border-[var(--border-subtle)] flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <div className="space-y-1.5">
                      <div className="flex items-center space-x-2.5">
                        <span className="text-xs text-[var(--identifier)] font-bold px-2 py-0.5 rounded bg-[var(--surface-elevated)] border border-[var(--border-subtle)]">
                          {cluster.id}
                        </span>
                        <h2 className="text-sm font-bold text-[var(--text)] font-sans truncate max-w-lg" title={cluster.title}>
                          {cluster.title}
                        </h2>
                      </div>
                      <div className="flex flex-wrap items-center gap-2 text-xs">
                        <span className="text-[var(--identifier)] font-bold">
                          {cluster.caseCount} LINKED CASES
                        </span>
                        <span className="text-[var(--text-dim)]">•</span>
                        <span className="text-[var(--text-dim)] font-sans">
                          Date range: <strong className="text-[var(--text)] font-mono">{cluster.dateRange.earliest} — {cluster.dateRange.latest}</strong>
                        </span>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-2 self-start md:self-auto">
                      <span
                        className={`px-2.5 py-1 rounded text-xs font-bold border uppercase ${getSeverityBadge(
                          cluster.highestSeverity
                        )}`}
                      >
                        {cluster.highestSeverity} SEVERITY
                      </span>

                      <span className="px-2.5 py-1 rounded text-xs font-bold bg-[var(--surface-elevated)] text-[var(--severity-critical)] border border-[var(--border-subtle)] uppercase">
                        RISK: {cluster.highestRiskScore}/100
                      </span>

                      <button
                        type="button"
                        onClick={() =>
                          setExpandedCampaigns((prev) => ({
                            ...prev,
                            [cluster.id]: !prev[cluster.id],
                          }))
                        }
                        className="px-3 py-1 rounded bg-[var(--surface-elevated)] hover:bg-[var(--surface-hover)] text-[var(--text)] text-xs font-bold border border-[var(--border-subtle)] transition-colors inline-flex items-center gap-1 cursor-pointer"
                      >
                        {isExpanded ? (
                          <>
                            <span>HIDE CASES</span>
                            <ChevronDown className="w-3.5 h-3.5" />
                          </>
                        ) : (
                          <>
                            <span>VIEW CASES</span>
                            <ChevronRight className="w-3.5 h-3.5" />
                          </>
                        )}
                      </button>
                    </div>
                  </div>

                  {/* Shared Infrastructure Highlights */}
                  <div className="p-4 bg-[var(--surface)] grid grid-cols-1 md:grid-cols-3 gap-3 border-b border-[var(--border-subtle)] text-xs">
                    {/* Shared IP */}
                    <div className="bg-[var(--surface-subtle)] p-3 rounded border border-[var(--border-subtle)] space-y-1">
                      <div className="text-[10px] text-[var(--text-dim)] uppercase tracking-wider flex items-center gap-1 font-sans">
                        <Network className="w-3 h-3 text-[var(--identifier)]" /> Shared Source IP
                      </div>
                      <div className="font-bold text-[var(--identifier)] truncate font-mono">
                        {sharedIp}
                      </div>
                    </div>

                    {/* Shared Sender Domain */}
                    <div className="bg-[var(--surface-subtle)] p-3 rounded border border-[var(--border-subtle)] space-y-1">
                      <div className="text-[10px] text-[var(--text-dim)] uppercase tracking-wider flex items-center gap-1 font-sans">
                        <Globe className="w-3 h-3 text-[var(--identifier)]" /> Shared Sender Domain
                      </div>
                      <div className="font-bold text-[var(--text)] truncate font-mono">
                        {sharedDomain}
                      </div>
                    </div>

                    {/* Shared URL Domain */}
                    <div className="bg-[var(--surface-subtle)] p-3 rounded border border-[var(--border-subtle)] space-y-1">
                      <div className="text-[10px] text-[var(--text-dim)] uppercase tracking-wider flex items-center gap-1 font-sans">
                        <Link2 className="w-3 h-3 text-[var(--severity-critical)]" /> Shared Payload Domain
                      </div>
                      <div className="font-bold text-[var(--severity-critical)] truncate font-mono">
                        {sharedUrl}
                      </div>
                    </div>
                  </div>

                  {/* Grouping Reasons List */}
                  <div className="p-4 bg-[var(--surface-subtle)] border-b border-[var(--border-subtle)] space-y-2 text-xs">
                    <div className="text-[10px] uppercase text-[var(--text-dim)] tracking-wider font-sans font-bold">
                      Forensic Grouping Rationale
                    </div>
                    <ul className="space-y-1 text-[var(--text-muted)] font-sans">
                      {cluster.reasons.map((reason: string, i: number) => (
                        <li key={i} className="flex items-start gap-2">
                          <span className="text-[var(--identifier)]">•</span>
                          <span>{reason}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Non-Attacker Attribution Safeguard Box */}
                  <div className="p-3 bg-[var(--surface-elevated)] text-xs flex items-center gap-2 text-[var(--text-muted)] font-sans border-b border-[var(--border-subtle)]">
                    <AlertTriangle className="w-4 h-4 text-[var(--severity-medium)] shrink-0" />
                    <span>
                      <strong>Forensic Safeguard:</strong> Cases linked by shared infrastructure or indicators. Shared infrastructure does not establish common actor attribution.
                    </span>
                  </div>

                  {/* Expandable Linked Cases Table */}
                  {isExpanded && (
                    <div className="p-4 bg-[var(--surface)] space-y-3">
                      <div className="text-xs font-mono text-[var(--text-dim)] uppercase">
                        Linked Investigation Cases ({cluster.cases.length})
                      </div>
                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-xs font-mono">
                          <thead className="bg-[var(--surface-subtle)] border-b border-[var(--border-subtle)] text-[var(--text-dim)] text-[10px] uppercase">
                            <tr>
                              <th className="py-2.5 px-3">Case ID</th>
                              <th className="py-2.5 px-3">Subject</th>
                              <th className="py-2.5 px-3">Sender</th>
                              <th className="py-2.5 px-3">Severity</th>
                              <th className="py-2.5 px-3">Score</th>
                              <th className="py-2.5 px-3">Created (IST)</th>
                              <th className="py-2.5 px-3 text-right">Action</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-[var(--border-subtle)]">
                            {cluster.cases.map((c: CaseRecord) => (
                              <tr
                                key={c.id}
                                onClick={() => onSelectCase(c)}
                                className="hover:bg-[var(--surface-hover)] cursor-pointer transition-colors"
                              >
                                <td className="py-2.5 px-3 font-bold text-[var(--identifier)]">{c.id}</td>
                                <td className="py-2.5 px-3 text-[var(--text)] font-sans max-w-xs truncate">{c.subject}</td>
                                <td className="py-2.5 px-3 text-[var(--text-muted)] max-w-xs truncate">{c.sender}</td>
                                <td className="py-2.5 px-3">
                                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${getSeverityBadge(c.severity)}`}>
                                    {c.severity}
                                  </span>
                                </td>
                                <td className="py-2.5 px-3 font-bold text-[var(--severity-critical)]">{c.riskScore}/100</td>
                                <td className="py-2.5 px-3 text-[var(--text-dim)] text-[11px]">{formatISTTimestamp(c.createdAt)}</td>
                                <td className="py-2.5 px-3 text-right whitespace-nowrap">
                                  <button
                                    type="button"
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      onSelectCase(c);
                                    }}
                                    className="px-2.5 py-1 rounded bg-[var(--surface-elevated)] hover:bg-[var(--surface-hover)] text-[var(--text)] text-[10px] font-bold border border-[var(--border-subtle)] transition-colors inline-flex items-center gap-1 cursor-pointer"
                                  >
                                    VIEW CASE
                                    <ArrowUpRight className="w-3 h-3 text-[var(--identifier)]" />
                                  </button>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}
                </div>
              );
            })
          ) : (
            /* Empty State when no campaigns exist */
            <div className="surface-card p-12 border border-[var(--border-subtle)] rounded-md text-center font-mono space-y-3">
              <div className="w-12 h-12 rounded-full bg-[var(--surface)] border border-[var(--border-subtle)] mx-auto flex items-center justify-center text-[var(--text-dim)]">
                <Layers className="w-6 h-6 text-[var(--text-dim)]" />
              </div>
              <div className="space-y-1">
                <h3 className="text-sm font-bold text-[var(--text)] uppercase tracking-wide font-sans">
                  No linked campaigns detected
                </h3>
                <p className="text-xs text-[var(--text-muted)] font-sans max-w-md mx-auto">
                  Campaign clustering requires multiple cases sharing meaningful forensic indicators (such as verified source IP, sender domain, or suspicious URL domain).
                </p>
              </div>
            </div>
          )}
        </div>
      ) : (
        /* INDIVIDUAL CASES VIEW */
        <div className="surface-card border border-[var(--border-subtle)] overflow-hidden rounded-md">
          {filteredCases.length > 0 ? (
            <>
              {/* Table View */}
              <div className="overflow-x-auto hidden md:block">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-[var(--surface-subtle)] border-b border-[var(--border-subtle)] text-[var(--text-dim)] text-[10px] uppercase">
                    <tr>
                      <th className="py-3 px-4">Case ID</th>
                      <th className="py-3 px-4">Subject / Incident</th>
                      <th className="py-3 px-4">Severity</th>
                      <th className="py-3 px-4">Classification</th>
                      <th className="py-3 px-4">Risk Score</th>
                      <th className="py-3 px-4">Confidence</th>
                      <th className="py-3 px-4">Origin IP</th>
                      <th className="py-3 px-4">Last Activity (IST)</th>
                      <th className="py-3 px-4 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--border-subtle)]">
                    {filteredCases.map((c) => (
                      <tr
                        key={c.id}
                        onClick={() => onSelectCase(c)}
                        className="hover:bg-[var(--surface-hover)] cursor-pointer transition-colors group"
                      >
                        <td className="py-3.5 px-4 whitespace-nowrap font-mono">
                          <span className="text-[var(--text-muted)] font-bold mr-2.5">{c.caseNumber || '#001'}</span>
                          <span className="font-bold text-[var(--identifier)]">{c.id}</span>
                        </td>
                        <td className="py-3.5 px-4 max-w-xs">
                          <div className="font-semibold text-[var(--text)] font-sans truncate" title={c.subject}>
                            {c.subject || '(No Subject Provided)'}
                          </div>
                          <div className="text-[11px] text-[var(--text-dim)] font-mono truncate" title={c.sender}>
                            From: {c.sender}
                          </div>
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap">
                          <span className={`px-2.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${getSeverityBadge(c.severity)}`}>
                            {c.severity}
                          </span>
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap font-sans text-[var(--text-muted)] text-[11px]">
                          {c.classification}
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap">
                          <span className="font-bold text-[var(--severity-critical)]">{c.riskScore}</span>
                          <span className="text-[var(--text-dim)] text-[10px]"> / 100</span>
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap">
                          <span className="text-[var(--text-muted)] uppercase text-[11px]">{c.confidence}</span>
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap font-mono text-[var(--identifier)] text-[11px]">
                          {c.sourceIp || 'Unavailable'}
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap text-[var(--text-dim)] text-[11px]">
                          {formatISTTimestamp(c.updatedAt)}
                        </td>
                        <td className="py-3.5 px-4 text-right whitespace-nowrap">
                          <div className="flex items-center justify-end space-x-1.5">
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                handleDownloadCaseReport(c);
                              }}
                              disabled={downloadingId === c.id}
                              className="px-2 py-1 rounded bg-[var(--surface-elevated)] hover:bg-[var(--surface-hover)] text-[var(--text-muted)] hover:text-[var(--text)] text-[10px] font-mono border border-[var(--border-subtle)] transition-colors inline-flex items-center gap-1 cursor-pointer"
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
                              className="px-2.5 py-1 rounded bg-[var(--surface-elevated)] hover:bg-[var(--surface-hover)] text-[var(--text)] text-[10px] font-bold border border-[var(--border-subtle)] transition-colors inline-flex items-center gap-1 cursor-pointer"
                            >
                              <span>INVESTIGATE</span>
                              <ArrowUpRight className="w-3 h-3 text-[var(--identifier)]" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Mobile Card List */}
              <div className="block md:hidden divide-y divide-[var(--border-subtle)] font-mono">
                {filteredCases.map((c) => (
                  <div
                    key={c.id}
                    onClick={() => onSelectCase(c)}
                    className="p-4 space-y-3 hover:bg-[var(--surface-hover)] cursor-pointer"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span className="text-xs text-[var(--text-muted)] font-bold">{c.caseNumber || '#001'}</span>
                        <span className="font-bold text-[var(--identifier)]">{c.id}</span>
                      </div>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${getSeverityBadge(c.severity)}`}>
                        {c.severity}
                      </span>
                    </div>

                    <div className="space-y-1">
                      <h4 className="text-sm font-semibold text-[var(--text)] font-sans leading-snug">
                        {c.subject || '(No Subject)'}
                      </h4>
                      <p className="text-xs text-[var(--text-dim)] truncate">From: {c.sender}</p>
                    </div>

                    <div className="flex items-center justify-between text-xs pt-1 border-t border-[var(--border-subtle)]">
                      <span className="text-[var(--text-muted)]">Score: <strong className="text-[var(--severity-critical)]">{c.riskScore}/100</strong></span>
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectCase(c);
                        }}
                        className="px-2.5 py-1 rounded bg-[var(--surface-elevated)] text-[var(--text)] text-[10px] font-bold border border-[var(--border-subtle)]"
                      >
                        INVESTIGATE →
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </>
          ) : (
            /* Filter / Search Returned No Cases */
            <div className="p-12 text-center font-mono space-y-4">
              <div className="max-w-md mx-auto space-y-3">
                <div className="w-12 h-12 rounded bg-[var(--surface)] border border-[var(--border-subtle)] mx-auto flex items-center justify-center text-[var(--text-muted)]">
                  <ShieldAlert className="w-6 h-6 text-[var(--identifier)]" />
                </div>
                <div className="space-y-1">
                  <h3 className="text-sm font-bold font-sans text-[var(--text)] uppercase">
                    NO MATCHING CASES
                  </h3>
                  <p className="text-xs text-[var(--text-muted)] font-sans">
                    No investigation records matched your query or filter parameters.
                  </p>
                </div>
                <div className="pt-2">
                  <button
                    type="button"
                    onClick={resetFilters}
                    className="px-3.5 py-1.5 rounded bg-[var(--surface-elevated)] hover:bg-[var(--surface-hover)] text-[var(--text)] border border-[var(--border-subtle)] text-xs font-mono inline-flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    <RotateCcw className="w-3.5 h-3.5 text-[var(--identifier)]" />
                    RESET ALL FILTERS
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
