import React, { useState, useEffect } from 'react';
import { ShieldAlert, RefreshCw, Filter, Key, Terminal } from 'lucide-react';
import { api } from '../api/client';
import { ThreatItemResponse } from '../api/types';
import { SeverityBadge, DecisionBadge } from '../components/StatusBadge';

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
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-cyber-border">
        <div>
          <h2 className="text-xl font-semibold text-slate-100 font-mono tracking-wide flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-red-400" />
            THREAT DETECTION INTELLIGENCE
          </h2>
          <p className="text-xs text-cyber-muted mt-0.5">
            Log of detected prompt injections, role-hijacks, and credential exfiltrations
          </p>
        </div>

        <button
          onClick={loadThreats}
          disabled={loading}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyber-card border border-cyber-border text-xs font-mono text-slate-300 hover:text-white transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Threats</span>
        </button>
      </div>

      {/* Filter Controls */}
      <div className="flex flex-wrap items-center gap-3 bg-cyber-card p-3 rounded-xl border border-cyber-border text-xs font-mono">
        <div className="flex items-center gap-1.5 text-cyber-muted">
          <Filter className="w-3.5 h-3.5" />
          <span>CATEGORY:</span>
        </div>
        <div className="flex items-center gap-1">
          {['all', 'prompt_injection', 'sensitive_data'].map((cat) => (
            <button
              key={cat}
              onClick={() => setCategoryFilter(cat)}
              className={`px-2.5 py-1 rounded text-xs transition-colors ${
                categoryFilter === cat
                  ? 'bg-cyber-surfaceHover text-cyber-accent font-semibold border border-cyber-borderLight'
                  : 'text-cyber-muted hover:text-slate-200'
              }`}
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
              onClick={() => setSeverityFilter(sev)}
              className={`px-2.5 py-1 rounded text-xs uppercase transition-colors ${
                severityFilter === sev
                  ? 'bg-cyber-surfaceHover text-cyber-accent font-semibold border border-cyber-borderLight'
                  : 'text-cyber-muted hover:text-slate-200'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="p-3.5 rounded-lg bg-red-950/30 border border-red-900/50 text-red-300 text-xs font-mono">
          {error}
        </div>
      )}

      {/* Threat Incident Feed / Cards */}
      <div className="space-y-3">
        {loading ? (
          <div className="py-16 text-center text-xs font-mono text-cyber-muted">
            <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-cyber-accent" />
            Scanning security findings across storage tiers...
          </div>
        ) : filteredThreats.length === 0 ? (
          <div className="py-16 text-center text-xs font-mono text-cyber-muted rounded-xl border border-cyber-border bg-cyber-card">
            No threat detections matching the active criteria.
          </div>
        ) : (
          filteredThreats.map((threat) => {
            const isInjection = threat.category === 'prompt_injection';
            return (
              <div
                key={threat.id}
                className="p-4 rounded-xl bg-cyber-card border border-cyber-border hover:border-cyber-borderLight transition-all space-y-3 shadow-sm"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-cyber-border/40 pb-2.5">
                  <div className="flex items-center gap-2.5">
                    <div
                      className={`w-7 h-7 rounded flex items-center justify-center shrink-0 ${
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
                      <span className="font-mono font-semibold text-xs text-slate-100 block">
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
                    <span className="font-mono text-xs font-semibold px-2 py-0.5 rounded bg-cyber-bg border border-cyber-border text-slate-200">
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
                    <div className="text-amber-300 whitespace-pre-wrap break-all selection:bg-amber-950">
                      {threat.evidence}
                    </div>
                  </div>
                </div>

                {/* Metadata Footer */}
                <div className="flex items-center justify-between pt-1 text-[11px] font-mono text-cyber-muted">
                  <span>USER: {threat.user_id}</span>
                  {threat.memory_id && <span>MEMORY REF: {threat.memory_id}</span>}
                  <span>{new Date(threat.timestamp).toLocaleString()}</span>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
