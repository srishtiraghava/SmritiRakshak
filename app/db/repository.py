"""
SmritiRakshak — Database Repository Layer
==========================================

Encapsulates all database operations, query execution, transactions,
and repository queries across the segregated memory tables.
"""

from __future__ import annotations

import hashlib
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import (
    PendingReviewMemory,
    QuarantinedMemory,
    SecurityAuditEvent,
    TrustedMemory,
)
from app.schemas.memory import DetectorFinding


def _hash_content(content: str) -> str:
    """Compute SHA-256 hex digest for tamper-evident audit logging."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


class MemoryRepository:
    """Manages transactional persistence into segregated PostgreSQL tables."""

    @staticmethod
    def save_trusted_memory(
        session: Session,
        memory_id: str,
        content: str,
        source: str,
        user_id: str,
        session_id: str | None,
        risk_score: int,
        risk_level: str,
        metadata_json: dict[str, Any] | None,
        findings: list[DetectorFinding],
    ) -> TrustedMemory:
        """Persist an approved memory entry into trusted_memories."""
        record = TrustedMemory(
            id=memory_id,
            content=content,
            source=source,
            user_id=user_id,
            session_id=session_id,
            decision="allow",
            risk_score=risk_score,
            risk_level=risk_level,
            metadata_json=metadata_json,
            findings_json=[f.model_dump() for f in findings],
        )
        session.add(record)
        return record

    @staticmethod
    def save_pending_review_memory(
        session: Session,
        memory_id: str,
        content: str,
        source: str,
        user_id: str,
        session_id: str | None,
        risk_score: int,
        risk_level: str,
        metadata_json: dict[str, Any] | None,
        findings: list[DetectorFinding],
    ) -> PendingReviewMemory:
        """Persist a borderline memory entry into pending_review_memories."""
        record = PendingReviewMemory(
            id=memory_id,
            content=content,
            source=source,
            user_id=user_id,
            session_id=session_id,
            decision="flag",
            risk_score=risk_score,
            risk_level=risk_level,
            flagged=True,
            review_status="pending",
            metadata_json=metadata_json,
            findings_json=[f.model_dump() for f in findings],
        )
        session.add(record)
        return record

    @staticmethod
    def save_quarantined_memory(
        session: Session,
        memory_id: str,
        content: str,
        source: str,
        user_id: str,
        session_id: str | None,
        risk_score: int,
        risk_level: str,
        quarantine_reason: str,
        metadata_json: dict[str, Any] | None,
        findings: list[DetectorFinding],
    ) -> QuarantinedMemory:
        """Persist a suspicious memory entry into quarantined_memories."""
        record = QuarantinedMemory(
            id=memory_id,
            content=content,
            source=source,
            user_id=user_id,
            session_id=session_id,
            decision="quarantine",
            risk_score=risk_score,
            risk_level=risk_level,
            quarantine_reason=quarantine_reason,
            metadata_json=metadata_json,
            findings_json=[f.model_dump() for f in findings],
        )
        session.add(record)
        return record

    @staticmethod
    def save_security_audit_event(
        session: Session,
        event_id: str,
        reason: str,
        risk_score: int,
        risk_level: str,
        user_id: str,
        session_id: str | None,
        source: str,
        findings: list[DetectorFinding],
        content: str,
    ) -> SecurityAuditEvent:
        """Record a security audit event for a BLOCKED memory entry.

        Security Note: The original malicious content is NOT stored as trusted
        memory. Its cryptographic SHA-256 hash is recorded instead.
        """
        evidence_summary = "; ".join(f.evidence for f in findings if f.evidence)
        record = SecurityAuditEvent(
            id=event_id,
            event_type="MEMORY_BLOCKED",
            decision="block",
            reason=reason,
            risk_score=risk_score,
            risk_level=risk_level,
            user_id=user_id,
            session_id=session_id,
            source=source,
            findings_json=[f.model_dump() for f in findings],
            sanitized_evidence=evidence_summary if evidence_summary else None,
            content_sha256=_hash_content(content),
        )
        session.add(record)
        return record

    # ─────────────────────────────────────────────────────────────────
    # Queries with strict repository isolation
    # ─────────────────────────────────────────────────────────────────

    @staticmethod
    def get_trusted_memories(
        session: Session,
        user_id: str | None = None,
        session_id: str | None = None,
    ) -> list[TrustedMemory]:
        """Fetch records exclusively from trusted_memories (ALLOW)."""
        stmt = select(TrustedMemory).order_by(TrustedMemory.created_at.desc())
        if user_id is not None:
            stmt = stmt.where(TrustedMemory.user_id == user_id)
        if session_id is not None:
            stmt = stmt.where(TrustedMemory.session_id == session_id)
        return list(session.scalars(stmt).all())

    @staticmethod
    def get_trusted_memory_by_id(
        session: Session, memory_id: str
    ) -> TrustedMemory | None:
        """Fetch a specific trusted memory by ID."""
        stmt = select(TrustedMemory).where(TrustedMemory.id == memory_id)
        return session.scalar(stmt)

    @staticmethod
    def get_pending_memories(
        session: Session,
        user_id: str | None = None,
        session_id: str | None = None,
    ) -> list[PendingReviewMemory]:
        """Fetch records from pending_review_memories (FLAG)."""
        stmt = select(PendingReviewMemory).order_by(PendingReviewMemory.created_at.desc())
        if user_id is not None:
            stmt = stmt.where(PendingReviewMemory.user_id == user_id)
        if session_id is not None:
            stmt = stmt.where(PendingReviewMemory.session_id == session_id)
        return list(session.scalars(stmt).all())

    @staticmethod
    def get_quarantined_memories(
        session: Session,
        user_id: str | None = None,
        session_id: str | None = None,
    ) -> list[QuarantinedMemory]:
        """Fetch records from quarantined_memories (QUARANTINE)."""
        stmt = select(QuarantinedMemory).order_by(QuarantinedMemory.created_at.desc())
        if user_id is not None:
            stmt = stmt.where(QuarantinedMemory.user_id == user_id)
        if session_id is not None:
            stmt = stmt.where(QuarantinedMemory.session_id == session_id)
        return list(session.scalars(stmt).all())

    @staticmethod
    def get_security_audit_events(
        session: Session,
        user_id: str | None = None,
        session_id: str | None = None,
    ) -> list[SecurityAuditEvent]:
        """Fetch records from security_audit_events (BLOCK)."""
        stmt = select(SecurityAuditEvent).order_by(SecurityAuditEvent.created_at.desc())
        if user_id is not None:
            stmt = stmt.where(SecurityAuditEvent.user_id == user_id)
        if session_id is not None:
            stmt = stmt.where(SecurityAuditEvent.session_id == session_id)
        return list(session.scalars(stmt).all())

    @staticmethod
    def get_pending_memory_by_id(
        session: Session, memory_id: str
    ) -> PendingReviewMemory | None:
        """Fetch a specific pending review memory by ID."""
        stmt = select(PendingReviewMemory).where(PendingReviewMemory.id == memory_id)
        return session.scalar(stmt)

    @staticmethod
    def get_quarantined_memory_by_id(
        session: Session, memory_id: str
    ) -> QuarantinedMemory | None:
        """Fetch a specific quarantined memory by ID."""
        stmt = select(QuarantinedMemory).where(QuarantinedMemory.id == memory_id)
        return session.scalar(stmt)

    @staticmethod
    def get_security_audit_event_by_id(
        session: Session, event_id: str
    ) -> SecurityAuditEvent | None:
        """Fetch a specific security audit event by ID."""
        stmt = select(SecurityAuditEvent).where(SecurityAuditEvent.id == event_id)
        return session.scalar(stmt)

    @staticmethod
    def review_quarantined_memory(
        session: Session,
        memory_id: str,
        action: str,
        reviewer_notes: str | None = None,
    ) -> tuple[bool, str]:
        """Execute a secure, transactional quarantine resolution workflow.

        - 'approve': Moves the item from quarantined_memories to trusted_memories
                     with review annotations, preserving audit history.
        - 'reject': Permanently deletes from quarantine and registers a permanent
                    BLOCK entry in security_audit_events with content SHA-256.
        """
        item = session.scalar(
            select(QuarantinedMemory).where(QuarantinedMemory.id == memory_id)
        )
        if not item:
            return False, f"Quarantined memory '{memory_id}' not found."

        if action == "approve":
            meta = dict(item.metadata_json or {})
            meta["reviewed_by"] = "security_officer"
            meta["review_action"] = "approved_from_quarantine"
            if reviewer_notes:
                meta["reviewer_notes"] = reviewer_notes

            trusted_record = TrustedMemory(
                id=item.id,
                content=item.content,
                source=item.source,
                user_id=item.user_id,
                session_id=item.session_id,
                decision="allow",
                risk_score=item.risk_score,
                risk_level=item.risk_level,
                metadata_json=meta,
                findings_json=item.findings_json,
            )
            session.add(trusted_record)
            session.delete(item)
            session.commit()
            return True, f"Memory '{memory_id}' released to trusted memory repository."

        elif action == "reject":
            reason = f"Quarantined memory permanently rejected by reviewer: {reviewer_notes or 'No notes provided'}"
            audit_record = SecurityAuditEvent(
                id=item.id,
                event_type="QUARANTINE_REJECTED",
                decision="block",
                reason=reason,
                risk_score=item.risk_score,
                risk_level=item.risk_level,
                user_id=item.user_id,
                session_id=item.session_id,
                source=item.source,
                findings_json=item.findings_json,
                sanitized_evidence=item.quarantine_reason,
                content_sha256=_hash_content(item.content),
            )
            session.add(audit_record)
            session.delete(item)
            session.commit()
            return True, f"Memory '{memory_id}' permanently rejected and logged to audit trail."

        return False, f"Unknown action: '{action}'"

    @staticmethod
    def get_dashboard_stats(session: Session) -> dict[str, Any]:
        """Aggregate actual PostgreSQL metrics for the Security Dashboard.

        Traceability of metrics:
        - trusted_count: SELECT COUNT(*) FROM trusted_memories
        - flagged_count: SELECT COUNT(*) FROM pending_review_memories
        - quarantined_count: SELECT COUNT(*) FROM quarantined_memories
        - blocked_count: SELECT COUNT(*) FROM security_audit_events
        - total_processed: Sum of the 4 physical tiers (excludes Attack Simulator)
        """
        trusted_count = session.scalar(select(func.count(TrustedMemory.id))) or 0
        flagged_count = session.scalar(select(func.count(PendingReviewMemory.id))) or 0
        quarantined_count = session.scalar(select(func.count(QuarantinedMemory.id))) or 0
        blocked_count = session.scalar(select(func.count(SecurityAuditEvent.id))) or 0

        total = trusted_count + flagged_count + quarantined_count + blocked_count

        # Risk score distribution across all tables
        dist = {"0-29 (Low)": 0, "30-49 (Medium)": 0, "50-79 (High)": 0, "80-100 (Critical)": 0}
        all_scores: list[int] = []
        all_scores.extend(session.scalars(select(TrustedMemory.risk_score)).all())
        all_scores.extend(session.scalars(select(PendingReviewMemory.risk_score)).all())
        all_scores.extend(session.scalars(select(QuarantinedMemory.risk_score)).all())
        all_scores.extend(session.scalars(select(SecurityAuditEvent.risk_score)).all())

        for score in all_scores:
            if score < 30:
                dist["0-29 (Low)"] += 1
            elif score < 50:
                dist["30-49 (Medium)"] += 1
            elif score < 80:
                dist["50-79 (High)"] += 1
            else:
                dist["80-100 (Critical)"] += 1

        # Threat category breakdown from non-allow tables
        categories: dict[str, int] = {}
        for findings in session.scalars(select(PendingReviewMemory.findings_json)).all():
            for finding in (findings or []):
                cat = finding.get("category", "unknown")
                categories[cat] = categories.get(cat, 0) + 1

        for findings in session.scalars(select(QuarantinedMemory.findings_json)).all():
            for finding in (findings or []):
                cat = finding.get("category", "unknown")
                categories[cat] = categories.get(cat, 0) + 1

        for findings in session.scalars(select(SecurityAuditEvent.findings_json)).all():
            for finding in (findings or []):
                cat = finding.get("category", "unknown")
                categories[cat] = categories.get(cat, 0) + 1

        # Recent events summary (most recent 5 from each tier, ordered and capped to 10)
        recent_trusted = session.scalars(
            select(TrustedMemory).order_by(TrustedMemory.created_at.desc()).limit(5)
        ).all()
        recent_pending = session.scalars(
            select(PendingReviewMemory).order_by(PendingReviewMemory.created_at.desc()).limit(5)
        ).all()
        recent_quarantined = session.scalars(
            select(QuarantinedMemory).order_by(QuarantinedMemory.created_at.desc()).limit(5)
        ).all()
        recent_audits = session.scalars(
            select(SecurityAuditEvent).order_by(SecurityAuditEvent.created_at.desc()).limit(5)
        ).all()

        all_events: list[dict[str, Any]] = []
        for t in recent_trusted:
            all_events.append({
                "id": t.id,
                "decision": "allow",
                "risk_score": t.risk_score,
                "user_id": t.user_id,
                "source": t.source,
                "timestamp": t.created_at.isoformat(),
                "summary": "Memory allowed and stored in trusted repository",
            })
        for p in recent_pending:
            all_events.append({
                "id": p.id,
                "decision": "flag",
                "risk_score": p.risk_score,
                "user_id": p.user_id,
                "source": p.source,
                "timestamp": p.created_at.isoformat(),
                "summary": "Borderline memory flagged for review",
            })
        for q in recent_quarantined:
            all_events.append({
                "id": q.id,
                "decision": "quarantine",
                "risk_score": q.risk_score,
                "user_id": q.user_id,
                "source": q.source,
                "timestamp": q.created_at.isoformat(),
                "summary": q.quarantine_reason,
            })
        for a in recent_audits:
            all_events.append({
                "id": a.id,
                "decision": "block",
                "risk_score": a.risk_score,
                "user_id": a.user_id,
                "source": a.source,
                "timestamp": a.created_at.isoformat(),
                "summary": a.reason,
            })

        all_events.sort(key=lambda x: x["timestamp"], reverse=True)

        return {
            "total_processed": total,
            "trusted_count": trusted_count,
            "flagged_count": flagged_count,
            "quarantined_count": quarantined_count,
            "blocked_count": blocked_count,
            "threat_category_distribution": categories,
            "risk_score_distribution": dist,
            "recent_events": all_events[:10],
            "system_status": "operational",
            "database_status": "connected",
        }

