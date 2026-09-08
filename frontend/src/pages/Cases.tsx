import React, { useState, useEffect, useMemo } from 'react';
import {
  FolderLock,
  Search,
  ArrowUpRight,
  Plus,
  Filter,
  ArrowUpDown,
  RotateCcw,
  ShieldAlert,
  Inbox,
  X,
} from 'lucide-react';
import { caseStore, type CaseRecord, type CaseStatus, type CaseSeverity } from '../services/caseStore';
import { NewInvestigationModal } from '../components/cases/NewInvestigationModal';
import { formatISTTimestamp } from '../utils/dateFormatter';

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
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);

  // Subscribe to caseStore changes
  useEffect(() => {
    const unsubscribe = caseStore.subscribe(() => {
      setCases(caseStore.getCases());
    });
    return unsubscribe;
  }, []);

  // Filter and sort computation
  const filteredCases = useMemo(() => {
    return cases
      .filter((c) => {
        // Severity filter
        if (filterSeverity !== 'ALL' && c.severity.toUpperCase() !== filterSeverity.toUpperCase()) {
          return false;
        }
        // Status filter
        if (filterStatus !== 'ALL' && c.status.toUpperCase() !== filterStatus.toUpperCase()) {
          return false;
        }
        // Search query
        if (searchQuery.trim()) {
          const q = searchQuery.toLowerCase().trim();
          return (
            c.id.toLowerCase().includes(q) ||
            c.subject.toLowerCase().includes(q) ||
            c.sender.toLowerCase().includes(q) ||
            c.classification.toLowerCase().includes(q) ||
            c.sourceIp.toLowerCase().includes(q) ||
            (c.analystNotes && c.analystNotes.toLowerCase().includes(q))
          );
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

  // Status metrics
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
        return 'text-[#fca5a5] bg-[#261114] border-[#5c1d24]';
      case 'HIGH':
        return 'text-[#fdba74] bg-[#26170e] border-[#5c2a16]';
      case 'MEDIUM':
        return 'text-[#fcd34d] bg-[#261b0c] border-[#5c3c12]';
      case 'LOW':
      default:
        return 'text-[#6ee7b7] bg-[#0e241b] border-[#164e3b]';
    }
  };

  const getStatusBadge = (status: CaseStatus) => {
    switch (status) {
      case 'OPEN':
        return 'text-[#38bdf8] bg-[#0c202d] border-[#164e63]';
      case 'IN REVIEW':
        return 'text-[#fcd34d] bg-[#261b0c] border-[#5c3c12]';
      case 'CONTAINED':
        return 'text-[#6ee7b7] bg-[#0e241b] border-[#164e3b]';
      case 'CLOSED':
      default:
        return 'text-[#94a3b8] bg-[#171b23] border-[#2a3242]';
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
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#1e2430]">
        <div>
          <div className="flex items-center space-x-2 text-xs font-mono text-[#64748b] mb-1">
            <span>SOC INCIDENT RESPONSE</span>
            <span>•</span>
            <span>PS SIH26106 QUEUE</span>
          </div>
          <h1 className="text-xl font-bold tracking-tight text-[#f1f5f9] flex items-center gap-2.5">
            <FolderLock className="w-5 h-5 text-[#8b5cf6]" />
            CASE MANAGEMENT
          </h1>
          <p className="text-xs text-[#94a3b8] font-sans mt-0.5">
            Active investigations and forensic case records.
          </p>
        </div>

        {/* Action Controls & Record Count */}
        <div className="flex items-center gap-3">
          <div className="hidden lg:flex items-center space-x-2 text-xs font-mono bg-[#12151b] border border-[#1e2430] px-3 py-1.5 rounded">
            <span className="text-[#64748b]">QUEUE:</span>
            <span className="text-[#38bdf8] font-semibold">{statusCounts.open} OPEN</span>
            <span className="text-[#3e485e]">/</span>
            <span className="text-[#fcd34d] font-semibold">{statusCounts.inReview} REVIEW</span>
            <span className="text-[#3e485e]">/</span>
            <span className="text-[#6ee7b7] font-semibold">{statusCounts.contained} CONTAINED</span>
          </div>

          <button
            type="button"
            onClick={() => setIsModalOpen(true)}
            className="px-3.5 py-1.5 rounded bg-[#8b5cf6] hover:bg-[#7c3aed] text-white text-xs font-mono font-medium flex items-center gap-1.5 shadow-sm transition-colors"
          >
            <Plus className="w-4 h-4" />
            NEW INVESTIGATION
          </button>
        </div>
      </div>

      {/* 2. Compact Control Filter & Sort Bar */}
      <div className="surface-card p-3.5 border border-[#1e2430] space-y-3">
        <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3">
          {/* Search Box */}
          <div className="relative flex-1 max-w-lg">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-[#64748b]" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search case ID, subject, sender, IP, classification..."
              className="w-full bg-[#12151b] border border-[#1e2430] focus:border-[#3e485e] rounded px-3 py-1.5 pl-9 pr-8 text-xs text-[#f1f5f9] placeholder-[#475569] font-mono outline-none transition-colors"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[#64748b] hover:text-[#f1f5f9]"
                title="Clear search"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* Sort Selector */}
          <div className="flex items-center space-x-2 text-xs font-mono self-end lg:self-auto">
            <ArrowUpDown className="w-3.5 h-3.5 text-[#64748b]" />
            <span className="text-[#64748b] hidden sm:inline">SORT:</span>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as SortOption)}
              className="bg-[#12151b] border border-[#1e2430] focus:border-[#3e485e] rounded px-2.5 py-1.5 text-xs text-[#f1f5f9] font-mono outline-none cursor-pointer"
            >
              <option value="activity_desc">LAST ACTIVITY (NEWEST)</option>
              <option value="activity_asc">LAST ACTIVITY (OLDEST)</option>
              <option value="score_desc">RISK SCORE (HIGH → LOW)</option>
              <option value="score_asc">RISK SCORE (LOW → HIGH)</option>
            </select>
          </div>
        </div>

        {/* Filter Chips Row */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-[#1e2430] text-xs font-mono">
          {/* Severity Filters */}
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[#64748b] text-[10px] uppercase tracking-wider mr-1 flex items-center gap-1">
              <Filter className="w-3 h-3" /> SEVERITY:
            </span>
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
              <button
                key={sev}
                onClick={() => setFilterSeverity(sev)}
                className={`px-2.5 py-0.5 rounded text-[11px] font-mono uppercase transition-colors ${
                  filterSeverity === sev
                    ? 'bg-[#1e232e] text-[#f1f5f9] border border-[#3e485e]'
                    : 'bg-[#12151b] text-[#64748b] hover:text-[#94a3b8] border border-[#1e2430]'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Status Filters */}
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[#64748b] text-[10px] uppercase tracking-wider mr-1">
              STATUS:
            </span>
            {['ALL', 'OPEN', 'IN REVIEW', 'CONTAINED', 'CLOSED'].map((st) => (
              <button
                key={st}
                onClick={() => setFilterStatus(st)}
                className={`px-2.5 py-0.5 rounded text-[11px] font-mono uppercase transition-colors ${
                  filterStatus === st
                    ? 'bg-[#1e232e] text-[#f1f5f9] border border-[#3e485e]'
                    : 'bg-[#12151b] text-[#64748b] hover:text-[#94a3b8] border border-[#1e2430]'
                }`}
              >
                {st}
              </button>
            ))}

            {(filterSeverity !== 'ALL' || filterStatus !== 'ALL' || searchQuery) && (
              <button
                onClick={resetFilters}
                className="ml-2 text-[#8b5cf6] hover:text-[#a78bfa] text-[11px] flex items-center gap-1 underline underline-offset-2 transition-colors"
                title="Reset all active filters"
              >
                <RotateCcw className="w-3 h-3" />
                Reset
              </button>
            )}
          </div>
        </div>
      </div>

      {/* 3. Forensic Cases Queue (Desktop / Tablet Table) */}
      <div className="surface-card border border-[#1e2430] overflow-hidden rounded-md">
        {filteredCases.length > 0 ? (
          <>
            {/* Table View (Desktop / Tablet) */}
            <div className="overflow-x-auto hidden md:block">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#0f1217] border-b border-[#1e2430] text-[#64748b] text-[10px] uppercase tracking-wider">
                  <tr>
                    <th className="py-3 px-4">Case ID</th>
                    <th className="py-3 px-4">Subject / Incident</th>
                    <th className="py-3 px-4">Severity</th>
                    <th className="py-3 px-4">Classification</th>
                    <th className="py-3 px-4">Risk Score</th>
                    <th className="py-3 px-4">Confidence</th>
                    <th className="py-3 px-4">Source / Origin</th>
                    <th className="py-3 px-4">Last Activity</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2430]">
                  {filteredCases.map((c) => (
                    <tr
                      key={c.id}
                      onClick={() => onSelectCase(c)}
                      className="hover:bg-[#171b23] transition-colors cursor-pointer group"
                    >
                      {/* Case ID */}
                      <td className="py-3 px-4 whitespace-nowrap">
                        <span className="text-[#06b6d4] font-semibold hover:underline">
                          {c.id}
                        </span>
                      </td>

                      {/* Subject / Title */}
                      <td className="py-3 px-4 max-w-xs xl:max-w-md">
                        <div className="font-sans font-medium text-[#f1f5f9] truncate" title={c.subject}>
                          {c.subject}
                        </div>
                        <div className="text-[10px] text-[#64748b] truncate font-mono mt-0.5">
                          From: {c.sender}
                        </div>
                      </td>

                      {/* Severity */}
                      <td className="py-3 px-4 whitespace-nowrap">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${getSeverityBadge(
                            c.severity
                          )}`}
                        >
                          {c.severity}
                        </span>
                      </td>

                      {/* Classification */}
                      <td className="py-3 px-4 uppercase text-[#c4b5fd] whitespace-nowrap font-medium text-[11px]">
                        {c.classification}
                      </td>

                      {/* Risk Score */}
                      <td className="py-3 px-4 whitespace-nowrap">
                        <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-[#12151b] border border-[#1e2430]">
                          <span
                            className={`font-bold ${
                              c.riskScore >= 80
                                ? 'text-[#ef4444]'
                                : c.riskScore >= 50
                                ? 'text-[#f59e0b]'
                                : 'text-[#10b981]'
                            }`}
                          >
                            {c.riskScore}
                          </span>
                          <span className="text-[#64748b] text-[10px]">/100</span>
                        </div>
                      </td>

                      {/* Confidence */}
                      <td className="py-3 px-4 whitespace-nowrap">
                        <span className="uppercase text-[#94a3b8] text-[11px]">
                          {c.confidence}
                        </span>
                      </td>

                      {/* Source IP / Origin */}
                      <td className="py-3 px-4 whitespace-nowrap text-[#94a3b8] text-[11px]">
                        {c.sourceIp}
                      </td>

                      {/* Last Activity */}
                      <td className="py-3 px-4 whitespace-nowrap text-[#64748b] text-[11px]">
                        {formatISTTimestamp(c.updatedAt || c.createdAt, 'Unrecorded')}
                      </td>

                      {/* Status */}
                      <td className="py-3 px-4 whitespace-nowrap">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase border ${getStatusBadge(
                            c.status
                          )}`}
                        >
                          {c.status}
                        </span>
                      </td>

                      {/* Action */}
                      <td className="py-3 px-4 text-right whitespace-nowrap">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectCase(c);
                          }}
                          className="px-2.5 py-1 rounded bg-[#171b23] group-hover:bg-[#8b5cf6] text-[#94a3b8] group-hover:text-white border border-[#2a3242] group-hover:border-[#8b5cf6] text-[11px] font-mono transition-colors inline-flex items-center gap-1"
                        >
                          Examine
                          <ArrowUpRight className="w-3 h-3" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Mobile Stacked Card View (Narrow Viewports <768px) */}
            <div className="md:hidden divide-y divide-[#1e2430]">
              {filteredCases.map((c) => (
                <div
                  key={c.id}
                  onClick={() => onSelectCase(c)}
                  className="p-4 space-y-2.5 hover:bg-[#171b23] transition-colors cursor-pointer"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-semibold text-[#06b6d4]">
                      {c.id}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase border ${getStatusBadge(
                        c.status
                      )}`}
                    >
                      {c.status}
                    </span>
                  </div>

                  <div className="font-sans text-xs font-medium text-[#f1f5f9] line-clamp-2">
                    {c.subject}
                  </div>

                  <div className="text-[11px] font-mono text-[#64748b] truncate">
                    From: {c.sender}
                  </div>

                  <div className="flex items-center justify-between pt-1 text-xs font-mono">
                    <div className="flex items-center space-x-2">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${getSeverityBadge(
                          c.severity
                        )}`}
                      >
                        {c.severity}
                      </span>
                      <span className="text-[#94a3b8] uppercase text-[11px]">
                        {c.classification}
                      </span>
                    </div>

                    <div className="flex items-center gap-1 text-[#ef4444] font-bold">
                      <span>{c.riskScore}</span>
                      <span className="text-[#64748b] text-[10px]">/100</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Table Footer Telemetry */}
            <div className="px-4 py-2.5 bg-[#0f1217] border-t border-[#1e2430] flex items-center justify-between text-[11px] font-mono text-[#64748b]">
              <div>
                SHOWING <span className="text-[#f1f5f9]">{filteredCases.length}</span> OF{' '}
                <span className="text-[#f1f5f9]">{cases.length}</span> CASE RECORDS
              </div>
              <div className="hidden sm:block">
                CLICK ROW TO OPEN ACTIVE INVESTIGATION WORKSTATION
              </div>
            </div>
          </>
        ) : (
          /* Operational Empty States */
          <div className="p-12 text-center space-y-4">
            {cases.length === 0 ? (
              /* State A: Case Repository Empty */
              <div className="max-w-md mx-auto space-y-3">
                <div className="w-12 h-12 rounded bg-[#171b23] border border-[#2a3242] mx-auto flex items-center justify-center text-[#94a3b8]">
                  <Inbox className="w-6 h-6 text-[#64748b]" />
                </div>
                <div className="space-y-1">
                  <h3 className="text-sm font-bold font-mono tracking-wide text-[#f1f5f9] uppercase">
                    CASE REPOSITORY EMPTY
                  </h3>
                  <p className="text-xs text-[#94a3b8] font-sans">
                    No active or archived forensic cases exist in the workstation database.
                  </p>
                </div>
                <div className="pt-2">
                  <button
                    type="button"
                    onClick={() => setIsModalOpen(true)}
                    className="px-4 py-2 rounded bg-[#8b5cf6] hover:bg-[#7c3aed] text-white text-xs font-mono font-medium inline-flex items-center gap-2 shadow-sm transition-colors"
                  >
                    <Plus className="w-4 h-4" />
                    START NEW INVESTIGATION
                  </button>
                </div>
              </div>
            ) : (
              /* State B: Filter / Search Returned No Cases */
              <div className="max-w-md mx-auto space-y-3">
                <div className="w-12 h-12 rounded bg-[#171b23] border border-[#2a3242] mx-auto flex items-center justify-center text-[#94a3b8]">
                  <ShieldAlert className="w-6 h-6 text-[#8b5cf6]" />
                </div>
                <div className="space-y-1">
                  <h3 className="text-sm font-bold font-mono tracking-wide text-[#f1f5f9] uppercase">
                    NO MATCHING CASES
                  </h3>
                  <p className="text-xs text-[#94a3b8] font-sans">
                    No investigation records matched your query or filter parameters.
                  </p>
                </div>
                <div className="pt-2">
                  <button
                    type="button"
                    onClick={resetFilters}
                    className="px-3.5 py-1.5 rounded bg-[#171b23] hover:bg-[#1e232e] text-[#f1f5f9] border border-[#2a3242] text-xs font-mono inline-flex items-center gap-1.5 transition-colors"
                  >
                    <RotateCcw className="w-3.5 h-3.5 text-[#8b5cf6]" />
                    RESET ALL FILTERS
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* 4. New Investigation Modal */}
      <NewInvestigationModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onInvestigationCreated={handleCaseCreated}
      />
    </div>
  );
};
