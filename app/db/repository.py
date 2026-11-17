"""
SmritiRakshak — Database Repository Layer
==========================================

Encapsulates all database operations, query execution, transactions,
and repository queries across the segregated memory tables.
"""

from __future__ import annotations

import hashlib
from typing import Any

from sqlalchemy import select
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
        session: Session, user_id: str | None = None
    ) -> list[TrustedMemory]:
        """Fetch records exclusively from trusted_memories (ALLOW)."""
        stmt = select(TrustedMemory).order_by(TrustedMemory.created_at.desc())
        if user_id is not None:
            stmt = stmt.where(TrustedMemory.user_id == user_id)
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
        session: Session, user_id: str | None = None
    ) -> list[PendingReviewMemory]:
        """Fetch records from pending_review_memories (FLAG)."""
        stmt = select(PendingReviewMemory).order_by(PendingReviewMemory.created_at.desc())
        if user_id is not None:
            stmt = stmt.where(PendingReviewMemory.user_id == user_id)
        return list(session.scalars(stmt).all())

    @staticmethod
    def get_quarantined_memories(
        session: Session, user_id: str | None = None
    ) -> list[QuarantinedMemory]:
        """Fetch records from quarantined_memories (QUARANTINE)."""
        stmt = select(QuarantinedMemory).order_by(QuarantinedMemory.created_at.desc())
        if user_id is not None:
            stmt = stmt.where(QuarantinedMemory.user_id == user_id)
        return list(session.scalars(stmt).all())

    @staticmethod
    def get_security_audit_events(
        session: Session, user_id: str | None = None
    ) -> list[SecurityAuditEvent]:
        """Fetch records from security_audit_events (BLOCK)."""
        stmt = select(SecurityAuditEvent).order_by(SecurityAuditEvent.created_at.desc())
        if user_id is not None:
            stmt = stmt.where(SecurityAuditEvent.user_id == user_id)
        return list(session.scalars(stmt).all())
