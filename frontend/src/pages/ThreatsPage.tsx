import React, { useState, useEffect } from 'react';
import { ShieldAlert, ShieldCheck, RefreshCw, Filter, Key, Terminal } from 'lucide-react';
import { api } from '../api/client';
import { ThreatItemResponse } from '../api/types';
import { SeverityBadge, DecisionBadge } from '../components/StatusBadge';
import { PageHeader } from '../components/PageHeader';

export const ThreatsPage: React.FC = () => {
  const [threats, setThreats] = useState<ThreatItemResponse[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');

  const loadThreats = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.listThreats(200);
      setThreats(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load threat detection events');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadThreats();
  }, []);

  const filteredThreats = threats.filter((t) => {
    if (categoryFilter !== 'all' && t.category !== categoryFilter) return false;
    if (severityFilter !== 'all' && t.severity.toLowerCase() !== severityFilter) return false;
    return true;
  });

  return (
    <section className="page-view" aria-labelledby="threats-title">
      <PageHeader
        titleId="threats-title"
        title="Threat detection"
        description="Review rule-based findings, their severity, and the policy decision applied to each memory."
        actions={<button
          type="button"
          onClick={loadThreats}
          disabled={loading}
          className="btn"
        >
          <RefreshCw size={15} className={loading ? 'animate-spin' : ''} /> Refresh findings
        </button>}
      />

      {/* Filter Controls */}
      <div className="filter-bar panel" aria-label="Threat filters">
        <div className="flex items-center gap-1.5 text-cyber-muted">
          <Filter className="w-3.5 h-3.5" />
          <span>CATEGORY:</span>
        </div>
        <div className="flex items-center gap-1">
          {['all', 'prompt_injection', 'sensitive_data'].map((cat) => (
            <button
              key={cat}
              type="button"
              aria-pressed={categoryFilter === cat}
              onClick={() => setCategoryFilter(cat)}
              className={`filter-tab ${categoryFilter === cat ? 'is-active' : ''}`}
            >
              {cat === 'all' ? 'ALL' : cat.replace('_', ' ').toUpperCase()}
            </button>
          ))}
        </div>

        <div className="h-4 w-px bg-cyber-border mx-2 hidden sm:block" />

        <div className="flex items-center gap-1.5 text-cyber-muted">
          <span>SEVERITY:</span>
        </div>
        <div className="flex items-center gap-1">
          {['all', 'critical', 'high', 'medium', 'low'].map((sev) => (
            <button
              key={sev}
              type="button"
              aria-pressed={severityFilter === sev}
              onClick={() => setSeverityFilter(sev)}
              className={`filter-tab ${severityFilter === sev ? 'is-active' : ''}`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="notice notice-error" role="alert">
          <ShieldAlert aria-hidden="true" />
          {error}
        </div>
      )}

      {/* Threat Incident Feed / Cards */}
      <div className="space-y-3">
        {loading ? (
          <div className="loading-state" role="status">
            <RefreshCw />
            <p>Loading detected findings…</p>
          </div>
        ) : filteredThreats.length === 0 ? (
          <div className="empty-state panel">
            <ShieldCheck size={22} aria-hidden="true" />
            <strong>No matching findings</strong>
            <p>{threats.length === 0 ? 'No threat findings are available.' : 'Try changing the category or severity filters.'}</p>
          </div>
        ) : (
          filteredThreats.map((threat) => {
            const isInjection = threat.category === 'prompt_injection';
            return (
              <div
                key={threat.id}
                className="panel threat-incident"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-cyber-border/40 pb-2.5">
                  <div className="flex items-center gap-3 min-w-0">
                    <div
                      className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 ${
                        isInjection
                          ? 'bg-red-950/50 text-red-400 border border-red-900/40'
                          : 'bg-amber-950/50 text-amber-400 border border-amber-900/40'
                      }`}
                    >
                      {isInjection ? (
                        <Terminal className="w-4 h-4" />
                      ) : (
                        <Key className="w-4 h-4" />
                      )}
                    </div>
                    <div>
                      <span className="font-semibold text-sm text-slate-100 block break-all">
                        {threat.detector_name}
                      </span>
                      <span className="font-mono text-[10px] text-cyber-muted uppercase">
                        Category: {threat.category.replace('_', ' ')}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={threat.severity} />
                    <DecisionBadge decision={threat.decision} size="sm" />
                    <span className="table-mono text-xs font-semibold px-2.5 py-1 rounded-md bg-cyber-bg border border-cyber-border text-slate-200">
                      +{threat.risk_points} pts
                    </span>
                  </div>
                </div>

                {/* Description & Redacted Evidence */}
                <div className="space-y-2 text-xs">
                  <p className="text-slate-300 font-sans text-xs">{threat.description}</p>

                  <div className="p-3 rounded-lg bg-cyber-bg border border-cyber-border/80 font-mono text-xs space-y-1">
                    <span className="text-[10px] uppercase tracking-wider text-cyber-muted block font-semibold">
                      Redacted Detection Evidence
                    </span>
                    <div className="text-amber-200 whitespace-pre-wrap break-all evidence-block">
                      {threat.evidence}
                    </div>
                  </div>
                </div>

                {/* Metadata Footer */}
                <div className="incident-meta">
                  <span>User <strong>{threat.user_id}</strong></span>
                  {threat.memory_id && <span>Memory <strong>{threat.memory_id}</strong></span>}
                  <time dateTime={threat.timestamp}>{new Date(threat.timestamp).toLocaleString()}</time>
                </div>
              </div>
            );
          })
        )}
      </div>
    </section>
  );
};
