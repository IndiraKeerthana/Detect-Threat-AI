import React from 'react';
import { MousePointer, FileX, MessageSquareX, ShieldAlert, Trash2 } from 'lucide-react';
import { SectionHeader } from './SectionHeader';

interface RecommendationsCardProps {
  recommendedActions?: string[];
  riskScore?: number;
}

export const RecommendationsCard: React.FC<RecommendationsCardProps> = ({
  recommendedActions = [],
  riskScore = 0,
}) => {
  const isHighRisk = riskScore >= 70;

  const defaultCards = [
    {
      icon: MousePointer,
      title: 'Do Not Click',
      description: 'Avoid clicking any links or buttons inside this email.',
      colorClass: 'text-rose-400 bg-rose-500/10 border-rose-500/20',
    },
    {
      icon: FileX,
      title: 'Do Not Download',
      description: 'Do not open or download any unexpected attachments.',
      colorClass: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
    },
    {
      icon: MessageSquareX,
      title: 'Do Not Reply',
      description: 'Do not respond to the sender or share personal information.',
      colorClass: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
    },
    {
      icon: ShieldAlert,
      title: 'Report Email',
      description: 'Forward or report this message to your IT/Security team.',
      colorClass: 'text-sky-400 bg-sky-500/10 border-sky-500/20',
    },
    {
      icon: Trash2,
      title: 'Delete Email',
      description: isHighRisk ? 'Permanently delete this email from your inbox.' : 'Move to junk or delete if unneeded.',
      colorClass: isHighRisk ? 'text-rose-400 bg-rose-500/10 border-rose-500/20' : 'text-[var(--text-muted)] bg-[var(--surface-elevated)] border-[var(--border-subtle)]',
    },
  ];

  return (
    <div className="surface-card p-5 border border-[var(--border-subtle)] rounded-2xl space-y-5 font-sans">
      {/* Section Header */}
      <SectionHeader
        index={6}
        title="Recommendations"
        subtitle="Actionable steps to take to stay safe."
      />

      {/* Clear Action Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
        {defaultCards.map((card) => {
          const Icon = card.icon;
          return (
            <div
              key={card.title}
              className={`p-4 rounded-xl border space-y-2 flex flex-col justify-between ${card.colorClass}`}
            >
              <div className="space-y-1.5">
                <div className="w-8 h-8 rounded-lg bg-[var(--surface)] border border-[var(--border-subtle)] flex items-center justify-center shrink-0">
                  <Icon className="w-4 h-4" />
                </div>
                <div className="font-bold text-sm tracking-tight text-[var(--text)]">
                  {card.title}
                </div>
                <p className="text-xs text-[var(--text-muted)] leading-relaxed font-normal">
                  {card.description}
                </p>
              </div>
            </div>
          );
        })}
      </div>

      {/* Specific Real Backend Recommendations (if present) */}
      {recommendedActions.length > 0 && (
        <div className="border border-[var(--border-subtle)] rounded-xl p-4 bg-[var(--surface-subtle)] space-y-3">
          <div className="text-xs font-semibold text-[var(--text)] font-mono uppercase tracking-wider">
            Detailed Incident Response Actions ({recommendedActions.length})
          </div>
          <div className="space-y-2">
            {recommendedActions.map((action, idx) => (
              <div key={idx} className="p-3 rounded-lg bg-[var(--surface)] border border-[var(--border-subtle)] flex items-start gap-3 text-xs">
                <span className="w-5 h-5 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 font-mono text-[10px] font-bold flex items-center justify-center shrink-0 mt-0.5">
                  {idx + 1}
                </span>
                <p className="text-[var(--text-muted)] leading-relaxed flex-1">
                  {action}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
