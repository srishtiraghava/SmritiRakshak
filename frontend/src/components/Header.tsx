import React from 'react';
import { Shield, RefreshCw, Database } from 'lucide-react';
import { HealthResponse } from '../api/types';

interface HeaderProps {
  health: HealthResponse | null;
  loading: boolean;
  onRefresh: () => void;
}

export const Header: React.FC<HeaderProps> = ({ health, loading, onRefresh }) => {
  const isHealthy = health?.status === 'healthy';
  const isDbConnected = health?.database === 'connected';

  return (
    <header className="h-16 border-b border-cyber-border bg-cyber-surface/90 backdrop-blur px-6 flex items-center justify-between sticky top-0 z-30">
      <div className="flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-cyber-card border border-cyber-borderLight flex items-center justify-center text-cyber-accent shadow-sm">
          <Shield className="w-5 h-5 text-cyber-accent" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="font-semibold text-slate-100 text-sm tracking-wide font-mono uppercase">
              SmritiRakshak
            </h1>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyber-card text-cyber-accent border border-cyber-border">
              v{health?.version || '0.1.0'}
            </span>
          </div>
          <p className="text-[11px] text-cyber-muted font-sans hidden sm:block">
            AI Agent Memory Security Firewall • OWASP ASI-06
          </p>
        </div>
      </div>

      <div className="flex items-center gap-4">
        {/* Status Indicators */}
        <div className="hidden md:flex items-center gap-2">
          {/* Engine Status */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-cyber-card border border-cyber-border text-xs font-mono">
            <span className={`w-2 h-2 rounded-full ${isHealthy ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'}`} />
            <span className="text-slate-300 text-[11px]">FIREWALL:</span>
            <span className={`text-[11px] font-semibold ${isHealthy ? 'text-emerald-400' : 'text-red-400'}`}>
              {health?.status ? health.status.toUpperCase() : 'CONNECTING...'}
            </span>
          </div>

          {/* Database Status */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-cyber-card border border-cyber-border text-xs font-mono">
            <Database className="w-3 h-3 text-cyber-muted" />
            <span className="text-slate-300 text-[11px]">POSTGRES:</span>
            <span className={`text-[11px] font-semibold ${isDbConnected ? 'text-emerald-400' : 'text-amber-400'}`}>
              {health?.database ? health.database.toUpperCase() : 'UNKNOWN'}
            </span>
          </div>
        </div>

        {/* Sync / Refresh Button */}
        <button
          onClick={onRefresh}
          disabled={loading}
          title="Refresh telemetry and records"
          className="p-2 rounded bg-cyber-card hover:bg-cyber-surfaceHover border border-cyber-border text-cyber-muted hover:text-slate-200 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-cyber-accent' : ''}`} />
        </button>
      </div>
    </header>
  );
};
