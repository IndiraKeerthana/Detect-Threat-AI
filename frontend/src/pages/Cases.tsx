import React, { useState } from 'react';
import { MOCK_CASES, MOCK_INVESTIGATION_DATA } from '../data/mockInvestigation';
import type { EmailAnalysisResponse } from '../types/investigation';
import { FolderLock, Search, ArrowUpRight } from 'lucide-react';

interface CasesProps {
  onSelectCase: (data: EmailAnalysisResponse) => void;
}

export const Cases: React.FC<CasesProps> = ({ onSelectCase }) => {
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const filteredCases = MOCK_CASES.filter((c) => {
    if (filterSeverity !== 'all' && c.severity !== filterSeverity) {
      return false;
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        c.id.toLowerCase().includes(q) ||
        c.subject.toLowerCase().includes(q) ||
        c.sender.toLowerCase().includes(q) ||
        c.classification.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const getSeverityBadge = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
        return 'text-[#fca5a5] bg-[#261114] border-[#5c1d24]';
      case 'high':
        return 'text-[#fca5a5] bg-[#261114] border-[#5c1d24]';
      case 'medium':
        return 'text-[#fcd34d] bg-[#261b0c] border-[#5c3c12]';
      default:
        return 'text-[#6ee7b7] bg-[#0e241b] border-[#164e3b]';
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'active':
        return 'text-[#c4b5fd] bg-[#1e1533] border-[#432474]';
      case 'in_review':
        return 'text-[#fcd34d] bg-[#261b0c] border-[#5c3c12]';
      case 'remediated':
      case 'closed':
        return 'text-[#6ee7b7] bg-[#0e241b] border-[#164e3b]';
      default:
        return 'text-[#94a3b8] bg-[#171b23] border-[#2a3242]';
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#1e2430]">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[#f1f5f9] flex items-center gap-2">
            <FolderLock className="w-5 h-5 text-[#8b5cf6]" />
            Case Management & Investigation Queue
          </h1>
          <p className="text-xs text-[#64748b] font-mono mt-0.5">
            Active SOC forensic intake and triage records • PS SIH26106
          </p>
        </div>

        <div className="text-xs font-mono text-[#64748b]">
          RECORDS COUNT: <span className="text-[#f1f5f9]">{filteredCases.length}</span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="flex items-center space-x-1.5 w-full sm:w-auto">
          {['all', 'critical', 'high', 'medium', 'benign'].map((sev) => (
            <button
              key={sev}
              onClick={() => setFilterSeverity(sev)}
              className={`px-3 py-1 text-xs font-mono rounded transition-colors uppercase ${
                filterSeverity === sev
                  ? 'bg-[#1e232e] text-[#f1f5f9] border border-[#3e485e]'
                  : 'bg-[#12151b] text-[#64748b] hover:text-[#94a3b8] border border-[#1e2430]'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-[#64748b]" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter cases..."
            className="w-full bg-[#12151b] border border-[#1e2430] focus:border-[#3e485e] rounded px-3 py-1.5 pl-9 text-xs text-[#f1f5f9] font-mono outline-none"
          />
        </div>
      </div>

      {/* Cases Table */}
      <div className="surface-card border border-[#1e2430] overflow-hidden rounded-md">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-[#0f1217] border-b border-[#1e2430] text-[#64748b] text-[10px] uppercase tracking-wider">
              <tr>
                <th className="py-3 px-4">Case ID</th>
                <th className="py-3 px-4">Subject</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Classification</th>
                <th className="py-3 px-4">Created Timestamp</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2430]">
              {filteredCases.map((c) => (
                <tr
                  key={c.id}
                  className="hover:bg-[#171b23] transition-colors cursor-pointer group"
                  onClick={() => onSelectCase(MOCK_INVESTIGATION_DATA)}
                >
                  <td className="py-3 px-4 text-[#06b6d4] font-semibold whitespace-nowrap">
                    {c.id}
                  </td>
                  <td className="py-3 px-4 max-w-xs truncate text-[#f1f5f9] font-sans font-medium" title={c.subject}>
                    {c.subject}
                    <span className="block text-[10px] text-[#64748b] font-mono truncate">
                      From: {c.sender}
                    </span>
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${getSeverityBadge(c.severity)}`}>
                      {c.severity}
                    </span>
                  </td>
                  <td className="py-3 px-4 uppercase text-[#94a3b8] whitespace-nowrap">
                    {c.classification}
                  </td>
                  <td className="py-3 px-4 text-[#64748b] whitespace-nowrap">
                    {c.created}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-semibold border ${getStatusBadge(c.status)}`}>
                      {c.status.replace('_', ' ')}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right whitespace-nowrap">
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectCase(MOCK_INVESTIGATION_DATA);
                      }}
                      className="px-2.5 py-1 rounded bg-[#171b23] hover:bg-[#8b5cf6] text-[#94a3b8] hover:text-white border border-[#2a3242] group-hover:border-[#8b5cf6] text-[11px] font-mono transition-colors inline-flex items-center gap-1"
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
      </div>
    </div>
  );
};
