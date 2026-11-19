import React from 'react';

interface RiskScoreGaugeProps {
  score: number;
  showBar?: boolean;
}

export const RiskScoreGauge: React.FC<RiskScoreGaugeProps> = ({
  score,
  showBar = true,
}) => {
  const clamped = Math.max(0, Math.min(100, score));

  // Determine color based on centralized policy thresholds
  // 0-29: Low (emerald), 30-49: Medium (amber), 50-79: High (orange), 80-100: Critical (red)
  const getColors = () => {
    if (clamped >= 80) {
      return {
        text: 'text-red-400',
        bg: 'bg-red-500',
        track: 'bg-red-950/40',
        border: 'border-red-900/40',
      };
    }
    if (clamped >= 50) {
      return {
        text: 'text-orange-400',
        bg: 'bg-orange-500',
        track: 'bg-orange-950/40',
        border: 'border-orange-900/40',
      };
    }
    if (clamped >= 30) {
      return {
        text: 'text-amber-400',
        bg: 'bg-amber-500',
        track: 'bg-amber-950/40',
        border: 'border-amber-900/40',
      };
    }
    return {
      text: 'text-emerald-400',
      bg: 'bg-emerald-500',
      track: 'bg-emerald-950/40',
      border: 'border-emerald-900/40',
    };
  };

  const colors = getColors();

  return (
    <div className="flex items-center gap-2">
      <span className={`font-mono font-semibold text-xs min-w-[28px] text-right ${colors.text}`}>
        {clamped}
      </span>
      {showBar && (
        <div className={`w-16 h-1.5 rounded-full overflow-hidden ${colors.track} border ${colors.border}`}>
          <div
            className={`h-full rounded-full transition-all duration-300 ${colors.bg}`}
            style={{ width: `${clamped}%` }}
          />
        </div>
      )}
    </div>
  );
};
