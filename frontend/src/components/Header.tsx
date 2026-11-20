import React from 'react';
import { Database, Menu, RefreshCw, Shield, X } from 'lucide-react';
import { HealthResponse } from '../api/types';

interface HeaderProps {
  health: HealthResponse | null;
  loading: boolean;
  navigationOpen: boolean;
  onToggleNavigation: () => void;
  onRefresh: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  health,
  loading,
  navigationOpen,
  onToggleNavigation,
  onRefresh,
}) => {
  const healthy = health?.status === 'healthy';
  const databaseConnected = health?.database === 'connected';
  const firewallTone = !health?.status ? '' : healthy ? 'is-healthy' : health.status === 'degraded' ? 'is-warning' : 'is-error';
  const databaseTone = !health?.database ? '' : databaseConnected ? 'is-healthy' : 'is-error';

  return (
    <header className="topbar">
      <div className="topbar-start">
        <button
          className="menu-toggle"
          type="button"
          aria-label={navigationOpen ? 'Close navigation' : 'Open navigation'}
          aria-expanded={navigationOpen}
          aria-controls="primary-navigation"
          onClick={onToggleNavigation}
        >
          {navigationOpen ? <X size={18} /> : <Menu size={18} />}
        </button>
        <div className="brand-lockup">
          <span className="brand-mark" aria-hidden="true"><Shield size={19} strokeWidth={1.8} /></span>
          <div>
            <div className="flex items-center gap-1.5">
              <p className="brand-name">SmritiRakshak</p>
              {health?.version && <span className="version-tag">v{health.version}</span>}
            </div>
            <p className="brand-subtitle">AI memory security</p>
          </div>
        </div>
      </div>

      <div className="topbar-end">
        <div className="health-list" aria-label="Service health">
          <div className="health-item" role="status" aria-label={`Firewall: ${health?.status || 'unknown'}`} title={`Firewall: ${health?.status || 'unknown'}`}>
            <span className={`health-dot ${firewallTone}`} aria-hidden="true" />
            <span>Firewall</span>
            <span className="health-value">{health?.status || 'Checking'}</span>
          </div>
          <div className="health-item" role="status" aria-label={`PostgreSQL: ${health?.database || 'unknown'}`} title={`PostgreSQL: ${health?.database || 'unknown'}`}>
            <Database size={14} aria-hidden="true" />
            <span>PostgreSQL</span>
            <span className={`health-dot ${databaseTone}`} aria-hidden="true" />
            <span className="health-value">{health?.database || 'Checking'}</span>
          </div>
        </div>
        <button
          className="icon-button"
          type="button"
          onClick={onRefresh}
          disabled={loading}
          aria-label={loading ? 'Refreshing service status' : 'Refresh service status'}
          title="Refresh service status and telemetry"
        >
          <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
        </button>
      </div>
    </header>
  );
};
