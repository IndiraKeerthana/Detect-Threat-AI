import { Search, UserCheck, RefreshCw } from 'lucide-react';

interface TopbarProps {
  currentContext: string;
  onRefresh?: () => void;
  isAnalyzing?: boolean;
}

export const Topbar: React.FC<TopbarProps> = ({
  currentContext,
  onRefresh,
  isAnalyzing = false,
}) => {
  return (
    <header className="h-14 bg-[#0f1217] border-b border-[#1e2430] px-6 flex items-center justify-between shrink-0 select-none">
      {/* Context Breadcrumb */}
      <div className="flex items-center space-x-2 text-xs">
        <span className="font-mono text-[#64748b]">WORKSTATION</span>
        <span className="text-[#3e485e]">/</span>
        <span className="font-medium text-[#f1f5f9] tracking-wide">{currentContext}</span>
        {isAnalyzing && (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono bg-[#1e1533] border border-[#432474] text-[#c4b5fd]">
            <RefreshCw className="w-3 h-3 animate-spin text-[#8b5cf6]" />
            RUNNING INVESTIGATION...
          </span>
        )}
      </div>

      {/* Global Quick Search (Mock/Filter) */}
      <div className="flex-1 max-w-md mx-8 hidden md:block">
        <div className="relative">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-[#64748b]" />
          <input
            type="text"
            placeholder="Search indicators, domains, IPs, message-IDs (Ctrl+K)..."
            className="w-full bg-[#12151b] border border-[#1e2430] hover:border-[#2a3242] focus:border-[#3e485e] rounded px-3 py-1.5 pl-9 text-xs text-[#f1f5f9] placeholder-[#475569] font-mono outline-none transition-colors"
          />
          <kbd className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[9px] font-mono text-[#475569] bg-[#171b23] border border-[#2a3242] px-1.5 py-0.5 rounded">
            /
          </kbd>
        </div>
      </div>

      {/* System Status & Analyst Profile */}
      <div className="flex items-center space-x-4">
        {onRefresh && (
          <button
            onClick={onRefresh}
            title="Refresh state"
            className="text-[#64748b] hover:text-[#f1f5f9] p-1.5 rounded hover:bg-[#171b23] transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        )}

        <div className="h-4 w-[1px] bg-[#1e2430]" />

        {/* Threat Level Global Indicator */}
        <div className="flex items-center space-x-2 text-[11px] font-mono">
          <span className="w-2 h-2 rounded-full bg-[#10b981]" />
          <span className="text-[#94a3b8] hidden lg:inline">ENGINE:</span>
          <span className="text-[#f1f5f9]">ARMED</span>
        </div>

        <div className="h-4 w-[1px] bg-[#1e2430]" />

        {/* Analyst Identity */}
        <div className="flex items-center space-x-2 bg-[#12151b] border border-[#1e2430] px-2.5 py-1 rounded">
          <UserCheck className="w-3.5 h-3.5 text-[#06b6d4]" />
          <div className="text-[11px] font-mono text-[#94a3b8]">
            <span className="text-[#f1f5f9] font-medium">ANALYST</span>-01
          </div>
          <span className="text-[9px] font-mono px-1 py-0.2 bg-[#0c232c] text-[#67e8f9] rounded border border-[#154c5e]">
            TIER-3
          </span>
        </div>
      </div>
    </header>
  );
};
