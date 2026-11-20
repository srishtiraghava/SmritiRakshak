import React, { useState, useEffect, useMemo } from 'react';
import { RefreshCw, Copy, Check, Fingerprint, Search, Filter } from 'lucide-react';
import { api } from '../api/client';
import { AuditEventItemResponse } from '../api/types';
import { RiskScoreGauge } from '../components/RiskScoreGauge';
import { PageHeader } from '../components/PageHeader';

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
    <section className="page-view" aria-labelledby="audit-title">
      <PageHeader
        titleId="audit-title"
        title="Audit trail"
        description="Review blocked memories and quarantine rejections. Search event details and copy a full content fingerprint for correlation."
        actions={<button
          type="button"
          onClick={loadEvents}
          disabled={loading}
          className="btn"
        >
          <RefreshCw size={15} className={loading ? 'animate-spin' : ''} /> Refresh events
        </button>}
      />

      {/* Security Guarantee Note */}
      <div className="notice notice-info">
        <Fingerprint aria-hidden="true" />
        <div>
          <h2>Blocked content is represented by a fingerprint</h2>
          <p>
            Blocked memory payloads are not retained as plaintext. The audit record stores a SHA-256 fingerprint for forensic correlation and deduplication.
          </p>
        </div>
      </div>

      {/* Filter and Search Controls */}
      <div className="filter-bar panel">
        <label className="search-field">
          <Search aria-hidden="true" />
          <input
            type="text"
            aria-label="Search audit events"
            placeholder="Search by event ID, reason, user, or SHA-256..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="field"
          />
        </label>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter className="w-3.5 h-3.5 text-cyber-muted" />
          <label className="text-cyber-muted text-xs" htmlFor="audit-type-filter">Event type</label>
          <select
            id="audit-type-filter"
            value={eventTypeFilter}
            onChange={(e) => setEventTypeFilter(e.target.value)}
            className="field-select"
          >
            <option value="ALL">All Event Types</option>
            <option value="MEMORY_BLOCKED">MEMORY_BLOCKED</option>
            <option value="QUARANTINE_REJECTED">QUARANTINE_REJECTED</option>
          </select>
          <span className="inline-message" aria-live="polite">
            Showing {filteredEvents.length} of {events.length}
          </span>
        </div>
      </div>

      {error && (
        <div className="notice notice-error" role="alert">
          <Fingerprint aria-hidden="true" />
          {error}
        </div>
      )}

      {/* Audit Log Table */}
      <div className="table-frame">
        <div className="table-scroll">
          <table aria-label="Security audit events">
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
                      <span className="status-badge status-block table-mono">
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
                          type="button"
                          onClick={() => handleCopySha(evt.content_sha256)}
                          title="Copy full SHA-256 fingerprint"
                          className="icon-button"
                          aria-label={copiedId === evt.content_sha256 ? 'Fingerprint copied' : 'Copy full SHA-256 fingerprint'}
                        >
                          {copiedId === evt.content_sha256 ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    </td>
                    <td className="table-subtle whitespace-nowrap">
                      <time dateTime={evt.created_at}>{new Date(evt.created_at).toLocaleString()}</time>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
};
