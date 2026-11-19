import React, { useState, useEffect } from 'react';
import {
  Lock,
  RefreshCw,
  CheckCircle2,
  XCircle,
  AlertOctagon,
  Eye,
} from 'lucide-react';
import { api } from '../api/client';
import { MemoryItemResponse } from '../api/types';
import { RiskScoreGauge } from '../components/RiskScoreGauge';

interface QuarantinePageProps {
  onSelectMemory: (memory: MemoryItemResponse) => void;
  onRefreshStats: () => void;
}

export const QuarantinePage: React.FC<QuarantinePageProps> = ({
  onSelectMemory,
  onRefreshStats,
}) => {
  const [quarantined, setQuarantined] = useState<MemoryItemResponse[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Review Modal state
  const [selectedItem, setSelectedItem] = useState<MemoryItemResponse | null>(null);
  const [reviewAction, setReviewAction] = useState<'approve' | 'reject' | null>(null);
  const [reviewerNotes, setReviewerNotes] = useState<string>('');
  const [actionLoading, setActionLoading] = useState<boolean>(false);
  const [actionMessage, setActionMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const loadQuarantine = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.listMemories({ decision: 'quarantine', page_size: 100 });
      setQuarantined(res.items);
    } catch (err: any) {
      setError(err.message || 'Failed to query quarantined records');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadQuarantine();
  }, []);

  const handleExecuteReview = async () => {
    if (!selectedItem || !reviewAction) return;

    setActionLoading(true);
    setActionMessage(null);
    try {
      const res = await api.reviewQuarantine(selectedItem.id, {
        action: reviewAction,
        reviewer_notes: reviewerNotes.trim() || undefined,
      });

      setActionMessage({ type: 'success', text: res.message });
      setSelectedItem(null);
      setReviewAction(null);
      setReviewerNotes('');
      // Refresh list & global stats
      await loadQuarantine();
      onRefreshStats();
    } catch (err: any) {
      setActionMessage({ type: 'error', text: err.message || 'Review action failed.' });
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-cyber-border">
        <div>
          <h2 className="text-xl font-semibold text-slate-100 font-mono tracking-wide flex items-center gap-2">
            <Lock className="w-5 h-5 text-orange-400" />
            QUARANTINE ISOLATION CENTER
          </h2>
          <p className="text-xs text-cyber-muted mt-0.5">
            High-risk memories physically isolated from agent execution awaiting security review
          </p>
        </div>

        <button
          onClick={loadQuarantine}
          disabled={loading}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyber-card border border-cyber-border text-xs font-mono text-slate-300 hover:text-white transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Action Notification Banner */}
      {actionMessage && (
        <div
          className={`p-3.5 rounded-lg border text-xs font-mono flex items-center justify-between ${
            actionMessage.type === 'success'
              ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
              : 'bg-red-950/40 border-red-800 text-red-300'
          }`}
        >
          <span>{actionMessage.text}</span>
          <button
            onClick={() => setActionMessage(null)}
            className="text-cyber-muted hover:text-white text-xs"
          >
            ✕
          </button>
        </div>
      )}

      {error && (
        <div className="p-3.5 rounded-lg bg-red-950/30 border border-red-900/50 text-red-300 text-xs font-mono">
          {error}
        </div>
      )}

      {/* Security Architecture Notice */}
      <div className="p-4 rounded-xl bg-orange-950/10 border border-orange-900/30 text-xs space-y-1.5">
        <div className="flex items-center gap-2 text-orange-400 font-semibold font-mono">
          <AlertOctagon className="w-4 h-4" />
          <span>ISOLATION PROTOCOL ACTIVE</span>
        </div>
        <p className="text-slate-300 text-[11px] leading-relaxed">
          Entries in this quarantine tier are stored in the segregated{' '}
          <code className="text-orange-300 bg-orange-950/40 px-1 py-0.5 rounded font-mono">quarantined_memories</code>{' '}
          table. They are strictly inaccessible to AI agent context windows. Releasing an item initiates a live database transaction
          moving it into trusted memory. Rejecting permanently purges the payload and logs an immutable audit event.
        </p>
      </div>

      {/* Quarantined Records Table */}
      <div className="rounded-xl border border-cyber-border bg-cyber-card overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-cyber-bg/80 border-b border-cyber-border text-cyber-muted uppercase tracking-wider text-[11px]">
              <tr>
                <th className="px-4 py-3 font-semibold">Memory ID</th>
                <th className="px-4 py-3 font-semibold">Quarantine Reason</th>
                <th className="px-4 py-3 font-semibold">User</th>
                <th className="px-4 py-3 font-semibold">Risk Score</th>
                <th className="px-4 py-3 font-semibold">Detected Findings</th>
                <th className="px-4 py-3 font-semibold">Timestamp</th>
                <th className="px-4 py-3 font-semibold text-right">Review Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border/40 text-slate-200">
              {loading ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-cyber-muted font-mono">
                    <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-orange-400" />
                    Checking quarantined_memories table...
                  </td>
                </tr>
              ) : quarantined.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-cyber-muted font-mono">
                    No quarantined records found. Quarantine pool is clean.
                  </td>
                </tr>
              ) : (
                quarantined.map((item) => (
                  <tr
                    key={item.id}
                    className="hover:bg-cyber-surfaceHover/70 transition-colors"
                  >
                    <td className="px-4 py-3 font-medium text-orange-400 whitespace-nowrap">
                      {item.id}
                    </td>
                    <td className="px-4 py-3 max-w-sm text-slate-300 truncate">
                      {item.quarantine_reason || 'Exceeded risk threshold'}
                    </td>
                    <td className="px-4 py-3 text-slate-300 whitespace-nowrap">
                      {item.user_id}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <RiskScoreGauge score={item.risk_score} showBar={false} />
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded bg-cyber-bg border border-cyber-border text-[11px]">
                        {item.findings_json.length} findings
                      </span>
                    </td>
                    <td className="px-4 py-3 text-cyber-muted whitespace-nowrap text-[11px]">
                      {new Date(item.created_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-right whitespace-nowrap space-x-1.5">
                      <button
                        onClick={() => onSelectMemory(item)}
                        title="Inspect full memory"
                        className="p-1.5 rounded hover:bg-cyber-surfaceHover text-cyber-muted hover:text-white transition-colors"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => {
                          setSelectedItem(item);
                          setReviewAction('approve');
                        }}
                        className="px-2.5 py-1 rounded bg-emerald-950/40 hover:bg-emerald-900/60 text-emerald-400 border border-emerald-800/40 text-[11px] font-semibold transition-colors"
                      >
                        Release
                      </button>
                      <button
                        onClick={() => {
                          setSelectedItem(item);
                          setReviewAction('reject');
                        }}
                        className="px-2.5 py-1 rounded bg-red-950/40 hover:bg-red-900/60 text-red-400 border border-red-800/40 text-[11px] font-semibold transition-colors"
                      >
                        Reject
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Review Confirmation Modal */}
      {selectedItem && reviewAction && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
          <div className="bg-cyber-surface border border-cyber-border rounded-xl max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center gap-2 text-sm font-mono font-semibold">
              {reviewAction === 'approve' ? (
                <>
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                  <span className="text-emerald-400">AUTHORIZE RELEASE TO TRUSTED MEMORY</span>
                </>
              ) : (
                <>
                  <XCircle className="w-5 h-5 text-red-400" />
                  <span className="text-red-400">PERMANENTLY REJECT & LOG TO AUDIT TRAIL</span>
                </>
              )}
            </div>

            <div className="p-3 bg-cyber-bg rounded-lg border border-cyber-border text-xs font-mono space-y-1">
              <div>
                <span className="text-cyber-muted">Memory ID: </span>
                <span className="text-slate-200">{selectedItem.id}</span>
              </div>
              <div>
                <span className="text-cyber-muted">Owner: </span>
                <span className="text-slate-200">{selectedItem.user_id}</span>
              </div>
              <div>
                <span className="text-cyber-muted">Risk Score: </span>
                <span className="text-slate-200">{selectedItem.risk_score} / 100</span>
              </div>
            </div>

            <div className="space-y-1">
              <label className="text-xs font-mono uppercase text-cyber-muted block">
                Reviewer Justification Notes
              </label>
              <textarea
                rows={3}
                placeholder={
                  reviewAction === 'approve'
                    ? 'State reasons why this memory is verified safe to store in trusted memory...'
                    : 'State reasons for permanent rejection and security blocking...'
                }
                value={reviewerNotes}
                onChange={(e) => setReviewerNotes(e.target.value)}
                className="w-full bg-cyber-card border border-cyber-border rounded-lg p-3 text-xs text-slate-200 placeholder-cyber-dim focus:outline-none focus:border-cyber-accent/50 font-mono resize-none"
              />
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-cyber-border">
              <button
                onClick={() => {
                  setSelectedItem(null);
                  setReviewAction(null);
                  setReviewerNotes('');
                }}
                disabled={actionLoading}
                className="px-3.5 py-1.5 rounded bg-cyber-card hover:bg-cyber-surfaceHover text-xs font-mono text-slate-300 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleExecuteReview}
                disabled={actionLoading}
                className={`px-4 py-1.5 rounded text-xs font-mono font-semibold transition-colors flex items-center gap-2 ${
                  reviewAction === 'approve'
                    ? 'bg-emerald-600 hover:bg-emerald-500 text-white'
                    : 'bg-red-600 hover:bg-red-500 text-white'
                }`}
              >
                {actionLoading && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                {reviewAction === 'approve' ? 'Confirm Release' : 'Confirm Rejection'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
