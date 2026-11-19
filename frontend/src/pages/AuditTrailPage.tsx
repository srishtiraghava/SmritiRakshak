import React, { useState, useEffect, useMemo } from 'react';
import { FileText, RefreshCw, Copy, Check, Fingerprint, Search, Filter } from 'lucide-react';
import { api } from '../api/client';
import { AuditEventItemResponse } from '../api/types';
import { RiskScoreGauge } from '../components/RiskScoreGauge';

export const AuditTrailPage: React.FC = () => {
  const [events, setEvents] = useState<AuditEventItemResponse[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [eventTypeFilter, setEventTypeFilter] = useState<string>('ALL');

  const loadEvents = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.listAuditEvents();
      setEvents(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load security audit events');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadEvents();
  }, []);

  const handleCopySha = (sha: string) => {
    navigator.clipboard.writeText(sha);
    setCopiedId(sha);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filteredEvents = useMemo(() => {
    return events.filter((evt) => {
      const matchesType =
        eventTypeFilter === 'ALL' ||
        evt.event_type.toUpperCase() === eventTypeFilter.toUpperCase();

      const q = searchQuery.toLowerCase().trim();
      const matchesSearch =
        !q ||
        evt.id.toLowerCase().includes(q) ||
        evt.reason.toLowerCase().includes(q) ||
        evt.user_id.toLowerCase().includes(q) ||
        (evt.session_id && evt.session_id.toLowerCase().includes(q)) ||
        evt.content_sha256.toLowerCase().includes(q);

      return matchesType && matchesSearch;
    });
  }, [events, eventTypeFilter, searchQuery]);

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-cyber-border">
        <div>
          <h2 className="text-xl font-semibold text-slate-100 font-mono tracking-wide flex items-center gap-2">
            <FileText className="w-5 h-5 text-red-400" />
            SECURITY AUDIT TRAIL
          </h2>
          <p className="text-xs text-cyber-muted mt-0.5">
            Tamper-evident forensics log of blocked memory injection attempts and security rejections
          </p>
        </div>

        <button
          onClick={loadEvents}
          disabled={loading}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyber-card border border-cyber-border text-xs font-mono text-slate-300 hover:text-white transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Security Guarantee Note */}
      <div className="p-4 rounded-xl bg-red-950/10 border border-red-900/30 text-xs space-y-1.5">
        <div className="flex items-center gap-2 text-red-400 font-semibold font-mono">
          <Fingerprint className="w-4 h-4" />
          <span>NON-RETENTION GUARANTEE</span>
        </div>
        <p className="text-slate-300 text-[11px] leading-relaxed">
          SmritiRakshak enforces a strict zero-retention policy for blocked memory content: malicious payloads are{' '}
          <strong className="text-red-300">never stored as plaintext</strong> in any database table. Instead, a
          cryptographic SHA-256 fingerprint is recorded to enable forensics, incident correlation, and deduplication
          without memory contamination.
        </p>
      </div>

      {/* Filter and Search Controls */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-cyber-card p-3 rounded-xl border border-cyber-border text-xs font-mono">
        <div className="flex items-center gap-2 w-full sm:w-auto flex-1 max-w-md">
          <Search className="w-4 h-4 text-cyber-muted flex-shrink-0" />
          <input
            type="text"
            placeholder="Search by event ID, reason, user, or SHA-256..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-cyber-bg border border-cyber-border rounded px-2.5 py-1.5 text-slate-200 placeholder-cyber-muted focus:outline-none focus:border-red-500/50 text-xs"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter className="w-3.5 h-3.5 text-cyber-muted" />
          <span className="text-cyber-muted text-[11px]">Type:</span>
          <select
            value={eventTypeFilter}
            onChange={(e) => setEventTypeFilter(e.target.value)}
            className="bg-cyber-bg border border-cyber-border rounded px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-red-500/50"
          >
            <option value="ALL">All Event Types</option>
            <option value="MEMORY_BLOCKED">MEMORY_BLOCKED</option>
            <option value="QUARANTINE_REJECTED">QUARANTINE_REJECTED</option>
          </select>
          <span className="text-cyber-muted text-[11px] ml-2">
            Showing {filteredEvents.length} of {events.length}
          </span>
        </div>
      </div>

      {error && (
        <div className="p-3.5 rounded-lg bg-red-950/30 border border-red-900/50 text-red-300 text-xs font-mono">
          {error}
        </div>
      )}

      {/* Audit Log Table */}
      <div className="rounded-xl border border-cyber-border bg-cyber-card overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-cyber-bg/80 border-b border-cyber-border text-cyber-muted uppercase tracking-wider text-[11px]">
              <tr>
                <th className="px-4 py-3 font-semibold">Event Type</th>
                <th className="px-4 py-3 font-semibold">Event ID / Ref</th>
                <th className="px-4 py-3 font-semibold">Policy Violation Reason</th>
                <th className="px-4 py-3 font-semibold">User / Session</th>
                <th className="px-4 py-3 font-semibold">Risk Score</th>
                <th className="px-4 py-3 font-semibold">Content SHA-256 Fingerprint</th>
                <th className="px-4 py-3 font-semibold">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border/40 text-slate-200">
              {loading ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-cyber-muted font-mono">
                    <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-red-400" />
                    Querying security_audit_events table...
                  </td>
                </tr>
              ) : filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-cyber-muted font-mono">
                    {events.length === 0
                      ? 'No security audit events recorded. No memory blocks triggered yet.'
                      : 'No audit events match the active search or filter criteria.'}
                  </td>
                </tr>
              ) : (
                filteredEvents.map((evt) => (
                  <tr key={evt.id} className="hover:bg-cyber-surfaceHover/70 transition-colors">
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded font-mono text-[10px] uppercase font-semibold bg-red-950/50 text-red-400 border border-red-900/40">
                        {evt.event_type}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-medium text-slate-200 whitespace-nowrap">
                      {evt.id}
                    </td>
                    <td className="px-4 py-3 max-w-xs text-slate-300 truncate" title={evt.reason}>
                      {evt.reason}
                    </td>
                    <td className="px-4 py-3 text-slate-300 whitespace-nowrap">
                      <div>{evt.user_id}</div>
                      {evt.session_id && (
                        <div className="text-[10px] text-cyber-muted">{evt.session_id}</div>
                      )}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <RiskScoreGauge score={evt.risk_score} showBar={false} />
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <span className="font-mono text-[11px] text-cyber-muted bg-cyber-bg px-2 py-0.5 rounded border border-cyber-border">
                          {evt.content_sha256.slice(0, 16)}...
                        </span>
                        <button
                          onClick={() => handleCopySha(evt.content_sha256)}
                          title="Copy full SHA-256 fingerprint"
                          className="p-1 rounded hover:bg-cyber-border text-cyber-muted hover:text-white transition-colors"
                        >
                          {copiedId === evt.content_sha256 ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-cyber-muted whitespace-nowrap text-[11px]">
                      {new Date(evt.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
