import React, { useState, useEffect, useRef } from 'react';
import {
  Lock,
  RefreshCw,
  CheckCircle2,
  XCircle,
  AlertOctagon,
  Eye,
  X,
} from 'lucide-react';
import { api } from '../api/client';
import { MemoryItemResponse } from '../api/types';
import { RiskScoreGauge } from '../components/RiskScoreGauge';
import { PageHeader } from '../components/PageHeader';

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
  const reviewDialogRef = useRef<HTMLDivElement>(null);
  const reviewTriggerRef = useRef<HTMLElement | null>(null);
  const actionLoadingRef = useRef(actionLoading);
  actionLoadingRef.current = actionLoading;

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

  useEffect(() => {
    if (!selectedItem || !reviewAction) return;
    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !actionLoadingRef.current) {
        setSelectedItem(null);
        setReviewAction(null);
        setReviewerNotes('');
      }
      if (event.key === 'Tab' && reviewDialogRef.current) {
        const focusable = Array.from(reviewDialogRef.current.querySelectorAll<HTMLElement>(
          'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])',
        ));
        if (focusable.length === 0) return;
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
      }
    };
    document.addEventListener('keydown', handleEscape);
    return () => {
      document.removeEventListener('keydown', handleEscape);
      reviewTriggerRef.current?.focus();
    };
  }, [selectedItem, reviewAction]);

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
    <section className="page-view" aria-labelledby="quarantine-title">
      <PageHeader
        titleId="quarantine-title"
        title="Quarantine review"
        description="Inspect isolated memories and record a reviewer decision before releasing or rejecting them."
        actions={<button
          type="button"
          onClick={loadQuarantine}
          disabled={loading}
          className="btn"
        >
          <RefreshCw size={15} className={loading ? 'animate-spin' : ''} /> Refresh queue
        </button>}
      />

      {/* Action Notification Banner */}
      {actionMessage && (!selectedItem || actionMessage.type === 'success') && (
        <div
          role={actionMessage.type === 'success' ? 'status' : 'alert'}
          className={`notice ${actionMessage.type === 'success' ? 'notice-success' : 'notice-error'}`}
        >
          <span>{actionMessage.text}</span>
          <button
            onClick={() => setActionMessage(null)}
            type="button"
            aria-label="Dismiss message"
            className="btn-quiet"
          >
            <X size={15} />
          </button>
        </div>
      )}

      {error && (
        <div className="notice notice-error" role="alert">
          <AlertOctagon aria-hidden="true" />
          {error}
        </div>
      )}

      {/* Security Architecture Notice */}
      <div className="notice notice-warning">
        <Lock aria-hidden="true" />
        <div>
          <h2>Isolated from trusted memory</h2>
          <p>
            Quarantined entries remain separate from trusted memory until reviewed. Releasing an item moves it to trusted memory; rejecting it purges the payload and records an audit event.
          </p>
        </div>
      </div>

      {/* Quarantined Records Table */}
      <div className="table-frame">
        <div className="table-scroll">
          <table aria-label="Quarantined memory records">
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
                    <td className="table-link whitespace-nowrap">
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
                        type="button"
                        onClick={() => onSelectMemory(item)}
                        title="Inspect full memory"
                        className="icon-button"
                        aria-label={`Inspect memory ${item.id}`}
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          reviewTriggerRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
                          setSelectedItem(item);
                          setReviewAction('approve');
                        }}
                        className="btn-primary review-action"
                      >
                        Release
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          reviewTriggerRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
                          setSelectedItem(item);
                          setReviewAction('reject');
                        }}
                        className="btn-danger review-action"
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
        <div className="modal-overlay">
          <div ref={reviewDialogRef} className="dialog-panel review-dialog" role="dialog" aria-modal="true" aria-labelledby="review-dialog-title" tabIndex={-1}>
            <div className="dialog-header">
              {reviewAction === 'approve' ? (
                <>
                  <CheckCircle2 className="text-emerald-400" aria-hidden="true" />
                  <h2 id="review-dialog-title" className="dialog-title">Release to trusted memory?</h2>
                </>
              ) : (
                <>
                  <XCircle className="text-red-400" aria-hidden="true" />
                  <h2 id="review-dialog-title" className="dialog-title">Reject and purge this memory?</h2>
                </>
              )}
            </div>

            <div className="dialog-body review-dialog-body">
            {actionMessage?.type === 'error' && <div className="notice notice-error" role="alert">{actionMessage.text}</div>}
            <dl className="metadata-grid review-meta">
              <div>
                <dt>Memory ID</dt>
                <dd className="table-mono">{selectedItem.id}</dd>
              </div>
              <div>
                <dt>Owner</dt>
                <dd>{selectedItem.user_id}</dd>
              </div>
              <div>
                <dt>Risk score</dt>
                <dd className="table-mono">{selectedItem.risk_score} / 100</dd>
              </div>
            </dl>

            <div className="review-notes">
              <label className="field-label" htmlFor="reviewer-notes">
                Reviewer notes <span className="font-normal text-cyber-muted">(optional)</span>
              </label>
              <textarea
                id="reviewer-notes"
                rows={3}
                placeholder={
                  reviewAction === 'approve'
                    ? 'Add context for releasing this memory…'
                    : 'Add context for rejecting this memory…'
                }
                value={reviewerNotes}
                onChange={(e) => setReviewerNotes(e.target.value)}
                className="field-textarea"
                autoFocus
              />
            </div>

            </div>
            <div className="dialog-footer">
              <button
                type="button"
                onClick={() => {
                  setSelectedItem(null);
                  setReviewAction(null);
                  setReviewerNotes('');
                }}
                disabled={actionLoading}
                className="btn"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleExecuteReview}
                disabled={actionLoading}
                className={reviewAction === 'approve' ? 'btn-primary' : 'btn-danger'}
              >
                {actionLoading && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                {reviewAction === 'approve' ? 'Confirm Release' : 'Confirm Rejection'}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
};
