import React from 'react';
import { AlertTriangle, Ban, ShieldAlert, ShieldCheck } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { Decision, RiskLevel, Severity } from '../api/types';

interface DecisionBadgeProps {
  decision: Decision | string;
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
}

const decisionConfig: Record<string, { label: string; tone: string; icon: LucideIcon }> = {
  allow: { label: 'Allowed', tone: 'allow', icon: ShieldCheck },
  flag: { label: 'Flagged', tone: 'flag', icon: AlertTriangle },
  quarantine: { label: 'Quarantined', tone: 'quarantine', icon: ShieldAlert },
  block: { label: 'Blocked', tone: 'block', icon: Ban },
};

export const DecisionBadge: React.FC<DecisionBadgeProps> = ({ decision, size = 'md', showIcon = true }) => {
  const config = decisionConfig[decision.toLowerCase()];
  const Icon = config?.icon ?? ShieldCheck;
  return <span className={`status-badge status-${config?.tone ?? 'unknown'} decision-${size}`}>{showIcon && <Icon size={13} aria-hidden />}{config?.label ?? decision}</span>;
};

interface SeverityBadgeProps {
  severity: Severity | RiskLevel | string;
  size?: 'sm' | 'md';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = 'sm' }) => {
  const key = (severity || '').toLowerCase();
  const label = key ? `${key[0].toUpperCase()}${key.slice(1)}` : 'Unknown';
  return <span className={`status-badge status-${['low', 'medium', 'high', 'critical'].includes(key) ? key : 'unknown'} severity-${size}`}>{label}</span>;
};
