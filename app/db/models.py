"""
SmritiRakshak — SQLAlchemy 2.0 ORM Models
==========================================

Defines physically segregated PostgreSQL tables for different memory security tiers:
  1. trusted_memories        → ONLY approved (ALLOW) memories
  2. pending_review_memories → Borderline (FLAG) memories awaiting human/security review
  3. quarantined_memories    → Suspicious/high-risk (QUARANTINE) memories isolated from agent context
  4. security_audit_events   → Audited (BLOCK) events with SHA-256 fingerprint, without retaining untrusted text

Security Architecture Note:
───────────────────────────
By maintaining distinct physical tables, we enforce at the database level
that quarantined, flagged, and blocked items are impossible to accidentally
query through trusted memory retrieval channels.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class TrustedMemory(Base):
    """Stores purely trusted, policy-approved memories (ALLOW)."""

    __tablename__ = "trusted_memories"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(50), nullable=False)
    user_id: Mapped[str] = mapped_column(String(256), nullable=False)
    session_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    decision: Mapped[str] = mapped_column(String(20), nullable=False, default="allow")
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)
    metadata_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    findings_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="check_trusted_risk_score_bounds"),
        CheckConstraint("decision = 'allow'", name="check_trusted_decision_allow"),
        Index("idx_trusted_user_created", "user_id", "created_at"),
        Index("idx_trusted_session", "session_id"),
    )


class PendingReviewMemory(Base):
    """Stores borderline memories (FLAG) in a dedicated review queue."""

    __tablename__ = "pending_review_memories"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(50), nullable=False)
    user_id: Mapped[str] = mapped_column(String(256), nullable=False)
    session_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    decision: Mapped[str] = mapped_column(String(20), nullable=False, default="flag")
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)
    flagged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    review_status: Mapped[str] = mapped_column(
        String(30), nullable=False, default="pending"
    )
    metadata_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    findings_json: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="check_pending_risk_score_bounds"),
        CheckConstraint("decision = 'flag'", name="check_pending_decision_flag"),
        Index("idx_pending_user_created", "user_id", "created_at"),
        Index("idx_pending_review_status", "review_status"),
    )


class QuarantinedMemory(Base):
    """Stores high-risk memories (QUARANTINE) in isolation away from agent execution."""

    __tablename__ = "quarantined_memories"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(50), nullable=False)
    user_id: Mapped[str] = mapped_column(String(256), nullable=False)
    session_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    decision: Mapped[str] = mapped_column(String(20), nullable=False, default="quarantine")
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)
    quarantine_reason: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    findings_json: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="check_quarantine_risk_score_bounds"),
        CheckConstraint("decision = 'quarantine'", name="check_quarantine_decision"),
        Index("idx_quarantine_user_created", "user_id", "created_at"),
        Index("idx_quarantine_risk", "risk_score"),
    )


class SecurityAuditEvent(Base):
    """Audit log for BLOCKED memory attempts and security events.

    Security Guarantee:
    Does NOT store the malicious memory content in any trusted memory table.
    Stores a cryptographic SHA-256 hash of the content for forensics and deduplication.
    """

    __tablename__ = "security_audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False, default="MEMORY_BLOCKED")
    decision: Mapped[str] = mapped_column(String(20), nullable=False, default="block")
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)
    user_id: Mapped[str] = mapped_column(String(256), nullable=False)
    session_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    source: Mapped[str] = mapped_column(String(50), nullable=False)
    findings_json: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    sanitized_evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="check_audit_risk_score_bounds"),
        CheckConstraint("decision = 'block'", name="check_audit_decision_block"),
        Index("idx_audit_user_created", "user_id", "created_at"),
        Index("idx_audit_sha256", "content_sha256"),
        Index("idx_audit_event_type", "event_type"),
    )
