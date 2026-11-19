import React from 'react';
import { ShieldCheck, AlertTriangle, AlertOctagon, Ban } from 'lucide-react';
import { Decision, Severity, RiskLevel } from '../api/types';

interface DecisionBadgeProps {
  decision: Decision | string;
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
}

export const DecisionBadge: React.FC<DecisionBadgeProps> = ({
  decision,
  size = 'md',
  showIcon = true,
}) => {
  const norm = decision.toLowerCase();

  const config = {
    allow: {
      label: 'ALLOW',
      color: 'text-emerald-400 bg-emerald-950/60 border-emerald-500/30',
      icon: ShieldCheck,
      iconColor: 'text-emerald-400',
    },
    flag: {
      label: 'FLAG',
      color: 'text-amber-400 bg-amber-950/60 border-amber-500/30',
      icon: AlertTriangle,
      iconColor: 'text-amber-400',
    },
    quarantine: {
      label: 'QUARANTINE',
      color: 'text-orange-400 bg-orange-950/60 border-orange-500/30',
      icon: AlertOctagon,
      iconColor: 'text-orange-400',
    },
    block: {
      label: 'BLOCK',
      color: 'text-red-400 bg-red-950/60 border-red-500/30',
      icon: Ban,
      iconColor: 'text-red-400',
    },
  }[norm] || {
    label: decision.toUpperCase(),
    color: 'text-slate-400 bg-slate-900 border-slate-700',
    icon: ShieldCheck,
    iconColor: 'text-slate-400',
  };

  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5 gap-1',
    md: 'text-xs px-2.5 py-1 gap-1.5 font-medium',
    lg: 'text-sm px-3.5 py-1.5 gap-2 font-semibold',
  }[size];

  const IconComponent = config.icon;

  return (
    <span
      className={`inline-flex items-center rounded-md border font-mono tracking-wider ${config.color} ${sizeClasses}`}
    >
      {showIcon && <IconComponent className={`${size === 'sm' ? 'w-3 h-3' : 'w-3.5 h-3.5'} ${config.iconColor}`} />}
      {config.label}
    </span>
  );
};

interface SeverityBadgeProps {
  severity: Severity | RiskLevel | string;
  size?: 'sm' | 'md';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  size = 'sm',
}) => {
  const norm = (severity || '').toLowerCase();

  const styles = {
    low: 'text-emerald-400 bg-emerald-950/40 border-emerald-800/40',
    medium: 'text-amber-400 bg-amber-950/40 border-amber-800/40',
    high: 'text-orange-400 bg-orange-950/40 border-orange-800/40',
    critical: 'text-red-400 bg-red-950/50 border-red-800/50',
  }[norm] || 'text-slate-400 bg-slate-800 border-slate-700';

  const sizeClass = size === 'sm' ? 'text-[11px] px-2 py-0.5' : 'text-xs px-2.5 py-1';

  return (
    <span
      className={`inline-block font-mono uppercase tracking-wider rounded border font-medium ${styles} ${sizeClass}`}
    >
      {severity}
    </span>
  );
};
