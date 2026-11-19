import React from 'react';
import { X, AlertTriangle } from 'lucide-react';
import { MemoryItemResponse } from '../api/types';
import { DecisionBadge, SeverityBadge } from './StatusBadge';
import { RiskScoreGauge } from './RiskScoreGauge';

interface MemoryDetailModalProps {
  memory: MemoryItemResponse | null;
  onClose: () => void;
}

export const MemoryDetailModal: React.FC<MemoryDetailModalProps> = ({
  memory,
  onClose,
}) => {
  if (!memory) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div className="bg-cyber-surface border border-cyber-border rounded-xl max-w-2xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-cyber-border flex items-center justify-between bg-cyber-card">
          <div className="flex items-center gap-3">
            <DecisionBadge decision={memory.decision} size="md" />
            <div className="font-mono text-xs text-cyber-muted truncate max-w-md">
              {memory.id}
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-cyber-surface text-cyber-muted hover:text-slate-200 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-5 text-sm">
          {/* Metadata Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-3 rounded-lg bg-cyber-bg border border-cyber-border/60 text-xs font-mono">
            <div>
              <span className="text-cyber-muted block text-[10px] uppercase">Source</span>
              <span className="text-slate-200 font-medium">{memory.source}</span>
            </div>
            <div>
              <span className="text-cyber-muted block text-[10px] uppercase">User ID</span>
              <span className="text-slate-200 font-medium truncate block">{memory.user_id}</span>
            </div>
            <div>
              <span className="text-cyber-muted block text-[10px] uppercase">Risk Score</span>
              <RiskScoreGauge score={memory.risk_score} />
            </div>
            <div>
              <span className="text-cyber-muted block text-[10px] uppercase">Risk Level</span>
              <SeverityBadge severity={memory.risk_level} />
            </div>
          </div>

          {/* Content Section */}
          <div className="space-y-1.5">
            <span className="text-xs font-mono uppercase tracking-wider text-cyber-muted font-semibold">
              Memory Content Payload
            </span>
            {memory.content ? (
              <div className="p-3.5 rounded-lg bg-cyber-card border border-cyber-border font-mono text-xs text-slate-200 whitespace-pre-wrap leading-relaxed max-h-48 overflow-y-auto">
                {memory.content}
              </div>
            ) : (
              <div className="p-3.5 rounded-lg bg-red-950/20 border border-red-900/40 text-xs text-red-300 flex items-start gap-2.5">
                <AlertTriangle className="w-4 h-4 shrink-0 text-red-400 mt-0.5" />
                <div>
                  <p className="font-semibold text-red-200">Untrusted Content Withheld Under Policy</p>
                  <p className="text-[11px] text-red-300/80 mt-1">
                    SmritiRakshak guarantees that malicious or blocked memory content is never retained
                    in trusted memory. A cryptographic SHA-256 fingerprint is recorded instead:
                  </p>
                  {memory.content_sha256 && (
                    <div className="mt-2 font-mono text-[11px] bg-red-950/60 p-2 rounded border border-red-800/40 select-all">
                      {memory.content_sha256}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Quarantine Reason (if applicable) */}
          {memory.quarantine_reason && (
            <div className="p-3 rounded-lg bg-orange-950/20 border border-orange-900/40 text-xs">
              <span className="font-mono text-[10px] uppercase text-orange-400 block font-semibold mb-1">
                Quarantine Isolation Reason
              </span>
              <p className="text-orange-200 text-xs">{memory.quarantine_reason}</p>
            </div>
          )}

          {/* Detector Findings */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono uppercase tracking-wider text-cyber-muted font-semibold">
                Security Detector Findings ({memory.findings_json.length})
              </span>
            </div>

            {memory.findings_json.length === 0 ? (
              <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-900/30 text-xs text-emerald-400 font-mono">
                ✓ No threat findings detected. Content passed rule-based inspection.
              </div>
            ) : (
              <div className="space-y-2">
                {memory.findings_json.map((finding, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-lg bg-cyber-card border border-cyber-border/80 space-y-1.5 text-xs"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-semibold text-slate-200">
                          {finding.detector_name}
                        </span>
                        <SeverityBadge severity={finding.severity} size="sm" />
                      </div>
                      <span className="font-mono text-[11px] text-cyber-muted">
                        +{finding.risk_points} pts
                      </span>
                    </div>

                    <p className="text-slate-300 text-[11px]">{finding.description}</p>

                    <div className="font-mono text-[11px] bg-cyber-bg/80 p-2 rounded border border-cyber-border text-amber-300">
                      <span className="text-cyber-muted">Evidence: </span>
                      {finding.evidence}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Timestamps & Extra Metadata */}
          <div className="flex items-center justify-between pt-2 border-t border-cyber-border/60 text-[11px] font-mono text-cyber-muted">
            <span>CREATED: {new Date(memory.created_at).toLocaleString()}</span>
            {memory.session_id && <span>SESSION: {memory.session_id}</span>}
          </div>
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3 border-t border-cyber-border bg-cyber-card flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded bg-cyber-border hover:bg-cyber-surfaceHover text-slate-200 text-xs font-medium transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
