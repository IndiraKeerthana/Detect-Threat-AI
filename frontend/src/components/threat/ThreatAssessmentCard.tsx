import { ShieldAlert, Activity, CheckCircle2, Layers } from 'lucide-react';
import type { RiskAssessment } from '../../types/investigation';
import { SectionHeader } from '../investigation/SectionHeader';

interface ThreatAssessmentCardProps {
  assessment?: RiskAssessment | null;
  correlationCount?: number;
}

export const ThreatAssessmentCard: React.FC<ThreatAssessmentCardProps> = ({
  assessment,
  correlationCount = 0,
}) => {
  if (!assessment) {
    return (
      <div className="surface-card p-6 border border-[#1e2430] text-center text-xs text-[#64748b] font-mono">
        NO DETERMINISTIC THREAT ASSESSMENT AVAILABLE
      </div>
    );
  }

  const score = assessment.score;
  const level = assessment.level.toUpperCase();
  const classification = assessment.classification.toUpperCase();
  const confidence = assessment.confidence?.level?.toUpperCase() || 'UNKNOWN';
  const evidenceCount = assessment.confidence?.evidence_count ?? (assessment.factors?.length ?? 0);

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

  // Generate 24 tick segments for analytical arc visualization
  const totalTicks = 24;
  const activeTicks = Math.round((score / 100) * totalTicks);

  return (
    <div className="surface-card p-6 border border-[#1e2430] space-y-6">
      {/* Section Header */}
      <SectionHeader
        index="01"
        tag="THREAT POSTURE"
        title="Threat Assessment & Quantitative Scoring"
        subtitle="Deterministic multi-factor risk score computed from RFC authentication, telemetry feeds, and correlated evidence"
        action={
          <div className="flex items-center space-x-2 text-xs font-mono">
            <span className="px-2 py-0.5 rounded bg-[#171b23] border border-[#2a3242] text-[#94a3b8]">
              ENGINE: DETERMINISTIC SCORER v2
            </span>
          </div>
        }
      />

      {/* Visual Hero Composition: Analytical Meter + Telemetry Matrix */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center bg-[#0a0c10] border border-[#1e2430] p-6 rounded-lg">
        {/* Left 5 Cols: Calibrated Analytical Arc Instrument */}
        <div className="lg:col-span-5 flex flex-col items-center justify-center p-2 text-center border-b lg:border-b-0 lg:border-r border-[#1e2430] pb-6 lg:pb-0 lg:pr-6">
          <div className="relative w-52 h-44 flex items-center justify-center">
            {/* SVG Analytical Precision Arc */}
            <svg className="w-48 h-48 -rotate-90 transform" viewBox="0 0 160 160">
              {/* Background Arc Ticks */}
              {Array.from({ length: totalTicks }).map((_, i) => {
                const angle = (i / (totalTicks - 1)) * 240 - 210; // 240 degree span
                const rad = (angle * Math.PI) / 180;
                const r1 = 62;
                const r2 = 72;
                const x1 = 80 + r1 * Math.cos(rad);
                const y1 = 80 + r1 * Math.sin(rad);
                const x2 = 80 + r2 * Math.cos(rad);
                const y2 = 80 + r2 * Math.sin(rad);
                const isActive = i < activeTicks;

                let strokeColor = '#1e2430';
                if (isActive) {
                  if (i < 8) strokeColor = '#10b981'; // Green
                  else if (i < 16) strokeColor = '#f59e0b'; // Amber
                  else strokeColor = '#ef4444'; // Red
                }

                return (
                  <line
                    key={i}
                    x1={x1}
                    y1={y1}
                    x2={x2}
                    y2={y2}
                    stroke={strokeColor}
                    strokeWidth={isActive ? 2.5 : 1.5}
                    strokeLinecap="round"
                    className="transition-all duration-300"
                  />
                );
              })}

              {/* Inner Reference Ring */}
              <circle
                cx="80"
                cy="80"
                r="50"
                fill="none"
                stroke="#171b23"
                strokeWidth="1"
                strokeDasharray="2 3"
              />
            </svg>

            {/* Central Score Readout */}
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none select-none">
              <span className="text-[10px] font-mono uppercase tracking-widest text-[#64748b]">
                RISK INDEX
              </span>
              <div className="text-4xl font-mono font-extrabold text-[#ef4444] tracking-tight leading-none mt-1">
                {score}
              </div>
              <span className="text-xs font-mono text-[#64748b] mt-0.5">
                / 100
              </span>
            </div>
          </div>

          {/* Analytical Calibration Bar */}
          <div className="w-full max-w-xs flex items-center justify-between text-[10px] font-mono text-[#64748b] pt-1">
            <span>0 BENIGN</span>
            <span>50 SUSPICIOUS</span>
            <span className="text-[#ef4444] font-semibold">100 CRITICAL</span>
          </div>
        </div>

        {/* Right 7 Cols: Analytical Telemetry Breakdown */}
        <div className="lg:col-span-7 space-y-4">
          <div className="grid grid-cols-2 gap-3 text-xs font-mono">
            {/* Severity Level */}
            <div className="bg-[#12151b] border border-[#1e2430] p-3 rounded space-y-1">
              <span className="text-[10px] text-[#64748b] uppercase tracking-wider block">
                SEVERITY BAND
              </span>
              <div className="text-base font-bold text-[#ef4444] flex items-center gap-2">
                <ShieldAlert className="w-4 h-4" />
                {level}
              </div>
              <span className="text-[10px] text-[#94a3b8] block">Calibrated risk score: {score}/100</span>
            </div>

            {/* Classification */}
            <div className="bg-[#12151b] border border-[#1e2430] p-3 rounded space-y-1">
              <span className="text-[10px] text-[#64748b] uppercase tracking-wider block">
                PRIMARY CLASSIFICATION
              </span>
              <div className="text-base font-bold text-[#c4b5fd] flex items-center gap-2">
                <Layers className="w-4 h-4 text-[#8b5cf6]" />
                {classification}
              </div>
              <span className="text-[10px] text-[#94a3b8] block">Detected threat taxonomy</span>
            </div>

            {/* Confidence Level */}
            <div className="bg-[#12151b] border border-[#1e2430] p-3 rounded space-y-1">
              <span className="text-[10px] text-[#64748b] uppercase tracking-wider block">
                ANALYTICAL CONFIDENCE
              </span>
              <div className="text-base font-bold text-[#6ee7b7] flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-[#10b981]" />
                {confidence}
              </div>
              <span className="text-[10px] text-[#94a3b8] block">Evidence consistency rating</span>
            </div>

            {/* Evidence Coverage */}
            <div className="bg-[#12151b] border border-[#1e2430] p-3 rounded space-y-1">
              <span className="text-[10px] text-[#64748b] uppercase tracking-wider block">
                EVIDENCE COVERAGE
              </span>
              <div className="text-base font-bold text-[#67e8f9] flex items-center gap-2">
                <Activity className="w-4 h-4 text-[#06b6d4]" />
                {evidenceCount} OBSERVABLES
              </div>
              <span className="text-[10px] text-[#94a3b8] block">{correlationCount} cross-correlations active</span>
            </div>
          </div>

          {/* Rationale Statement */}
          <div className="bg-[#0f1217] border border-[#1e2430] p-3 rounded text-xs text-[#94a3b8] leading-relaxed">
            <span className="font-mono text-[#64748b] uppercase text-[10px] tracking-wider block mb-1">
              FORENSIC SCORING RATIONALE
            </span>
            {assessment.rationale}
          </div>
        </div>
      </div>

      {/* Contributing Risk Factors Breakdown */}
      <div className="space-y-3 pt-2">
        <div className="flex items-center justify-between text-xs font-mono text-[#64748b] px-1">
          <span className="uppercase tracking-wider">
            CONTRIBUTING RISK FACTORS ({assessment.factors.length})
          </span>
          <span className="text-[11px]">SORTED BY QUANTITATIVE IMPACT</span>
        </div>

        <div className="space-y-2">
          {assessment.factors.map((factor) => (
            <div
              key={factor.code}
              className="bg-[#12151b] border border-[#1e2430] hover:border-[#2a3242] p-3.5 rounded-md text-xs space-y-2 transition-colors"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center space-x-2.5">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${getSeverityBadge(
                      factor.severity
                    )}`}
                  >
                    {factor.severity}
                  </span>
                  <span className="font-semibold text-[#f1f5f9] text-sm tracking-tight">
                    {factor.title}
                  </span>
                  <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-[#171b23] border border-[#2a3242] text-[#64748b]">
                    {factor.category || factor.code}
                  </span>
                </div>

                <div className="font-mono font-bold text-xs text-[#ef4444] bg-[#261114] border border-[#5c1d24] px-2 py-0.5 rounded shrink-0 self-start sm:self-auto">
                  +{factor.contribution} pts
                </div>
              </div>

              <p className="text-[11px] text-[#94a3b8] leading-relaxed font-sans">
                {factor.explanation}
              </p>

              {factor.evidence && factor.evidence.length > 0 && (
                <div className="flex flex-wrap items-center gap-1.5 pt-1">
                  <span className="text-[10px] font-mono text-[#64748b] mr-1">EVIDENCE:</span>
                  {factor.evidence.map((ev, i) => (
                    <span
                      key={i}
                      className="font-mono text-[10px] px-2 py-0.5 bg-[#0a0c10] border border-[#1e2430] rounded text-[#67e8f9]"
                    >
                      {ev}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
