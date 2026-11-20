import React from 'react';

interface RiskScoreGaugeProps {
  score: number;
  showBar?: boolean;
}

const riskTone = (score: number) => {
  if (score >= 80) return 'is-critical';
  if (score >= 50) return 'is-high';
  if (score >= 30) return 'is-medium';
  return 'is-low';
};

export const RiskScoreGauge: React.FC<RiskScoreGaugeProps> = ({ score, showBar = true }) => {
  const value = Math.max(0, Math.min(100, score));
  const tone = riskTone(value);
  return (
    <span className="inline-flex items-center gap-2" aria-label={`Risk score ${value} out of 100`}>
      <span className={`table-mono risk-value ${tone}`}>{value}</span>
      {showBar && (
        <span className="risk-bar" aria-hidden="true">
          <span className={`risk-bar-fill ${tone}`} style={{ width: `${value}%` }} />
        </span>
      )}
    </span>
  );
};
