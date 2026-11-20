import React, { useEffect, useRef } from 'react';
import { AlertTriangle, X } from 'lucide-react';
import { MemoryItemResponse } from '../api/types';
import { DecisionBadge, SeverityBadge } from './StatusBadge';
import { RiskScoreGauge } from './RiskScoreGauge';

interface MemoryDetailModalProps {
  memory: MemoryItemResponse | null;
  onClose: () => void;
}

export const MemoryDetailModal: React.FC<MemoryDetailModalProps> = ({ memory, onClose }) => {
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const dialogRef = useRef<HTMLElement>(null);
  const returnFocusRef = useRef<HTMLElement | null>(null);
  const onCloseRef = useRef(onClose);

  useEffect(() => { onCloseRef.current = onClose; }, [onClose]);
  useEffect(() => {
    if (!memory) return;
    returnFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    closeButtonRef.current?.focus();
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onCloseRef.current();
      if (event.key === 'Tab' && dialogRef.current) {
        const focusable = Array.from(dialogRef.current.querySelectorAll<HTMLElement>(
          'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])',
        ));
        if (focusable.length === 0) return;
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
      }
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      returnFocusRef.current?.focus();
    };
  }, [memory?.id]);

  if (!memory) return null;

  return (
    <div className="modal-overlay" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <section ref={dialogRef} className="dialog-panel" role="dialog" aria-modal="true" aria-labelledby="memory-dialog-title" tabIndex={-1}>
        <header className="dialog-header">
          <div className="dialog-identity">
            <h2 id="memory-dialog-title" className="dialog-title">Memory record</h2>
            <span className="table-mono dialog-id">{memory.id}</span>
          </div>
          <div className="dialog-header-actions">
            <DecisionBadge decision={memory.decision} size="sm" />
            <button ref={closeButtonRef} type="button" className="icon-button" onClick={onClose} aria-label="Close memory details"><X size={17} /></button>
          </div>
        </header>

        <div className="dialog-body detail-body">
          <div className="decision-spine detail-spine" aria-label={`Risk score ${memory.risk_score}, risk level ${memory.risk_level}, decision ${memory.decision}`}>
            <div><span className="result-label">Risk score</span><strong><RiskScoreGauge score={memory.risk_score} /></strong></div>
            <span className="decision-spine-separator" aria-hidden="true">›</span>
            <div><span className="result-label">Severity</span><SeverityBadge severity={memory.risk_level} /></div>
            <span className="decision-spine-separator" aria-hidden="true">›</span>
            <div><span className="result-label">Current tier</span><DecisionBadge decision={memory.decision} size="sm" /></div>
          </div>

          <dl className="metadata-grid">
            <div><dt>Source</dt><dd>{memory.source}</dd></div>
            <div><dt>User ID</dt><dd>{memory.user_id}</dd></div>
            <div><dt>Created</dt><dd><time dateTime={memory.created_at}>{new Date(memory.created_at).toLocaleString()}</time></dd></div>
            <div><dt>Session</dt><dd>{memory.session_id || 'Not provided'}</dd></div>
          </dl>

          <section className="detail-section" aria-labelledby="memory-content-title">
            <h3 id="memory-content-title" className="panel-title">Memory content</h3>
            {memory.content ? (
              <pre className="evidence-block detail-content">{memory.content}</pre>
            ) : (
              <div className="notice notice-error" role="note">
                <AlertTriangle aria-hidden="true" />
                <div>
                  <h3>Content withheld by policy</h3>
                  <p>This blocked payload is not retained as plaintext. Its SHA-256 fingerprint is available for correlation.</p>
                  {memory.content_sha256 && <code className="fingerprint-value">{memory.content_sha256}</code>}
                </div>
              </div>
            )}
          </section>

          {memory.quarantine_reason && (
            <section className="notice notice-warning" aria-labelledby="quarantine-reason-title">
              <AlertTriangle aria-hidden="true" />
              <div><h3 id="quarantine-reason-title">Quarantine reason</h3><p>{memory.quarantine_reason}</p></div>
            </section>
          )}

          <section className="detail-section" aria-labelledby="memory-findings-title">
            <div className="panel-heading">
              <div><h3 id="memory-findings-title" className="panel-title">Detector findings</h3><p className="panel-description">{memory.findings_json.length} finding{memory.findings_json.length === 1 ? '' : 's'} recorded</p></div>
            </div>
            {memory.findings_json.length === 0 ? (
              <div className="notice notice-success" role="status"><p>No detector findings were recorded for this memory.</p></div>
            ) : (
              <div className="finding-list">
                {memory.findings_json.map((finding, index) => (
                  <article key={`${finding.detector_name}-${index}`} className="finding-row">
                    <div className="finding-heading"><strong>{finding.detector_name}</strong><span className="finding-points table-mono">+{finding.risk_points} pts</span><SeverityBadge severity={finding.severity} /></div>
                    <p>{finding.description}</p>
                    <div className="evidence-block"><span className="text-cyber-muted">Evidence</span> · {finding.evidence}</div>
                  </article>
                ))}
              </div>
            )}
          </section>

          {memory.content_sha256 && memory.content && (
            <section className="detail-section">
              <h3 className="panel-title">Content fingerprint</h3>
              <code className="fingerprint-value">{memory.content_sha256}</code>
            </section>
          )}
        </div>

        <footer className="dialog-footer">
          <button type="button" onClick={onClose} className="btn">Close details</button>
        </footer>
      </section>
    </div>
  );
};
