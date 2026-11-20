import React, { useState, useEffect } from 'react';
import { Search, RefreshCw, ChevronLeft, ChevronRight, Eye } from 'lucide-react';
import { api } from '../api/client';
import { MemoryItemResponse } from '../api/types';
import { DecisionBadge } from '../components/StatusBadge';
import { RiskScoreGauge } from '../components/RiskScoreGauge';
import { PageHeader } from '../components/PageHeader';

interface ExplorerPageProps {
  onSelectMemory: (memory: MemoryItemResponse) => void;
}

export const ExplorerPage: React.FC<ExplorerPageProps> = ({ onSelectMemory }) => {
  const [memories, setMemories] = useState<MemoryItemResponse[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [decisionFilter, setDecisionFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [page, setPage] = useState<number>(1);
  const pageSize = 20;

  const loadMemories = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.listMemories({
        decision: decisionFilter === 'all' ? undefined : decisionFilter,
        page,
        page_size: pageSize,
      });
      setMemories(res.items);
      setTotal(res.total);
    } catch (err: any) {
      setError(err.message || 'Failed to load memories from PostgreSQL database');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadMemories();
  }, [decisionFilter, page]);

  // Client-side search query filtering
  const filteredMemories = memories.filter((m) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      m.id.toLowerCase().includes(q) ||
      (m.content && m.content.toLowerCase().includes(q)) ||
      m.user_id.toLowerCase().includes(q) ||
      m.source.toLowerCase().includes(q) ||
      (m.content_sha256 && m.content_sha256.toLowerCase().includes(q))
    );
  });

  return (
    <section className="page-view" aria-labelledby="memory-explorer-title">
      <PageHeader
        titleId="memory-explorer-title"
        title="Memory explorer"
        description="Search records across trusted, review, quarantine, and audit tiers. Select a record to inspect its decision evidence."
        actions={<button
          onClick={loadMemories}
          disabled={loading}
          className="btn"
        >
          <RefreshCw size={15} className={loading ? 'animate-spin' : ''} /> Refresh records
        </button>}
      />

      {/* Filter & Search Bar */}
      <div className="flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between">
        {/* Tier Decision Selector Tabs */}
        <div className="filter-tabs" role="group" aria-label="Filter memories by decision">
          {[
            { id: 'all', label: 'ALL TIERS' },
            { id: 'allow', label: 'ALLOW (TRUSTED)' },
            { id: 'flag', label: 'FLAG (REVIEW)' },
            { id: 'quarantine', label: 'QUARANTINE' },
            { id: 'block', label: 'BLOCK (AUDIT)' },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => {
                setDecisionFilter(tab.id);
                setPage(1);
              }}
              type="button"
              aria-pressed={decisionFilter === tab.id}
              className={`filter-tab ${decisionFilter === tab.id ? 'is-active' : ''}`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Search input */}
        <label className="search-field">
          <Search aria-hidden="true" />
          <input
            type="text"
            aria-label="Search memory records"
            placeholder="Search by ID, user, content..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="field"
          />
        </label>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="p-3.5 rounded-lg bg-red-950/30 border border-red-900/50 text-red-300 text-xs font-mono">
          {error}
        </div>
      )}

      {/* Main Table */}
      <div className="table-frame">
        <div className="table-scroll">
          <table aria-label="Memory records">
            <thead className="bg-cyber-bg/80 border-b border-cyber-border text-cyber-muted uppercase tracking-wider text-[11px]">
              <tr>
                <th className="px-4 py-3 font-semibold">Decision</th>
                <th className="px-4 py-3 font-semibold">Memory ID</th>
                <th className="px-4 py-3 font-semibold">Content Snippet</th>
                <th className="px-4 py-3 font-semibold">Source</th>
                <th className="px-4 py-3 font-semibold">User</th>
                <th className="px-4 py-3 font-semibold">Risk</th>
                <th className="px-4 py-3 font-semibold">Created</th>
                <th className="px-4 py-3 font-semibold text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border/40 text-slate-200">
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-cyber-muted font-mono">
                    <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-cyber-accent" />
                    Querying PostgreSQL storage tiers...
                  </td>
                </tr>
              ) : filteredMemories.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-cyber-muted font-mono">
                    No memories found in selected tier or matching search query.
                  </td>
                </tr>
              ) : (
                filteredMemories.map((m) => (
                  <tr
                    key={m.id}
                    onClick={() => onSelectMemory(m)}
                    tabIndex={0}
                    aria-label={`Inspect memory ${m.id}`}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault();
                        onSelectMemory(m);
                      }
                    }}
                    className="cursor-pointer"
                  >
                    <td className="px-4 py-3 whitespace-nowrap">
                      <DecisionBadge decision={m.decision} size="sm" />
                    </td>
                    <td className="table-link whitespace-nowrap">
                      {m.id}
                    </td>
                    <td>
                      <span className="table-clip" title={m.content || undefined}>
                      {m.content ? (
                        m.content
                      ) : (
                        <span className="text-red-400 italic">
                          [Untrusted Content Blocked - SHA256: {m.content_sha256?.slice(0, 12)}...]
                        </span>
                      )}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-cyber-muted whitespace-nowrap uppercase">
                      {m.source}
                    </td>
                    <td className="px-4 py-3 text-slate-300 whitespace-nowrap">
                      {m.user_id}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <RiskScoreGauge score={m.risk_score} showBar={false} />
                    </td>
                    <td className="px-4 py-3 text-cyber-muted whitespace-nowrap text-[11px]">
                      {new Date(m.created_at).toLocaleDateString()} {new Date(m.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </td>
                    <td className="px-4 py-3 text-right whitespace-nowrap">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectMemory(m);
                        }}
                        className="icon-button"
                        aria-label={`Inspect memory ${m.id}`}
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div className="pagination-bar">
          <span>
            Showing {filteredMemories.length} of {total} records
          </span>
          <div className="pagination-controls">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1 || loading}
              className="p-1 rounded bg-cyber-card border border-cyber-border text-slate-300 disabled:opacity-40 hover:bg-cyber-surfaceHover"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span>Page {page}</span>
            <button
              onClick={() => setPage((p) => p + 1)}
              disabled={page * pageSize >= total || loading}
              className="p-1 rounded bg-cyber-card border border-cyber-border text-slate-300 disabled:opacity-40 hover:bg-cyber-surfaceHover"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </section>
  );
};
