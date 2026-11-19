"""
SmritiRakshak — Pydantic v2 Schemas for the Memory Security Pipeline

This module defines every data shape that flows through SmritiRakshak:

  MemoryInput          → what an AI agent sends us for inspection
  DetectorFinding      → one security observation produced by a detector
  RiskAssessment       → aggregated numeric score + risk level
  PolicyDecision       → ALLOW / FLAG / QUARANTINE / BLOCK + reason
  MemoryProcessingResponse → the complete API response

Design rules
────────────
• Actual secrets or credentials must NEVER appear in findings or
  responses.  The ``evidence`` field in DetectorFinding stores only
  safely-redacted snippets.
• Content length limits come from ``app.core.config`` so there is
  exactly one place to change them.
• All validation happens via Pydantic v2 field constraints and
  model validators — no manual checks scattered across the codebase.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.core.config import MAX_CONTENT_LENGTH, MIN_CONTENT_LENGTH


# ───────────────────────────────────────────────────────────────────
# Enumerations
# ───────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    """How dangerous a single finding is."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskLevel(str, Enum):
    """Human-readable risk band derived from the numeric score."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Decision(str, Enum):
    """Policy engine verdict for a memory entry."""
    ALLOW = "allow"
    FLAG = "flag"
    QUARANTINE = "quarantine"
    BLOCK = "block"


class MemorySource(str, Enum):
    """
    Known origins of a memory entry.

    Using an enum prevents garbage values while still being easy to
    extend later.  If an agent introduces a new source type, add it
    here.
    """
    CONVERSATION = "conversation"
    DOCUMENT = "document"
    TOOL = "tool"
    SYSTEM = "system"
    UNKNOWN = "unknown"


# ───────────────────────────────────────────────────────────────────
# REQUEST — what an AI agent sends for inspection
# ───────────────────────────────────────────────────────────────────

class MemoryInput(BaseModel):
    """
    Incoming memory entry submitted by an AI agent for security
    inspection.

    Fields
    ------
    content : str
        The text that the agent wants to store.  Must be between
        MIN_CONTENT_LENGTH and MAX_CONTENT_LENGTH characters.
    source : MemorySource
        Where the memory came from (conversation, document, tool …).
    user_id : str
        Identifier of the user or agent session that owns this memory.
    session_id : str | None
        Optional session context.
    metadata : dict | None
        Arbitrary key/value pairs the caller wants to attach.
    """

    content: str = Field(
        ...,
        min_length=MIN_CONTENT_LENGTH,
        max_length=MAX_CONTENT_LENGTH,
        description="Memory text to be inspected.",
    )
    source: MemorySource = Field(
        ...,
        description="Origin of this memory entry.",
    )
    user_id: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Owner identifier.",
    )
    session_id: str | None = Field(
        default=None,
        max_length=256,
        description="Optional session identifier.",
    )
    metadata: dict[str, Any] | None = Field(
        default=None,
        description="Optional extra key-value context.",
    )

    # -- Extra validation ----------------------------------------------------

    @field_validator("content")
    @classmethod
    def content_must_not_be_blank(cls, value: str) -> str:
        """Reject strings that are technically non-empty but only whitespace."""
        if not value.strip():
            raise ValueError(
                "Content must contain at least one non-whitespace character."
            )
        return value

    model_config = {"str_strip_whitespace": False}


# ───────────────────────────────────────────────────────────────────
# DETECTOR OUTPUT — one security observation
# ───────────────────────────────────────────────────────────────────

class DetectorFinding(BaseModel):
    """
    A single security observation produced by a detection rule.

    The ``evidence`` field must contain only a safely redacted snippet
    — never the full secret or credential.

    Attributes
    ----------
    detector_name : str
        Which detector rule produced this finding
        (e.g. "prompt_injection_override").
    category : str
        Broad threat family: "prompt_injection" or "sensitive_data".
    severity : Severity
        LOW / MEDIUM / HIGH / CRITICAL.
    description : str
        Human-readable explanation of what was found.
    evidence : str
        A safely redacted excerpt from the content that triggered the
        finding.  Must NOT expose actual secrets.
    risk_points : int
        How many points this finding contributes to the overall risk
        score (before clamping to 0-100).
    """

    detector_name: str = Field(..., min_length=1)
    category: str = Field(..., min_length=1)
    severity: Severity
    description: str = Field(..., min_length=1)
    evidence: str = Field(
        ...,
        description="Redacted excerpt — must never expose real secrets.",
    )
    risk_points: int = Field(..., ge=0, le=100)


# ───────────────────────────────────────────────────────────────────
# RISK SCORING OUTPUT
# ───────────────────────────────────────────────────────────────────

class RiskAssessment(BaseModel):
    """
    The aggregated risk picture after all detectors have run.

    Attributes
    ----------
    risk_score : int
        Bounded 0-100.  Sum of all finding risk_points, clamped.
    risk_level : RiskLevel
        Human-readable band (low / medium / high / critical).
    contributing_findings : list[DetectorFinding]
        The findings that fed into the score.
    score_explanation : str
        Plain-English explanation of how the score was calculated.
    """

    risk_score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    contributing_findings: list[DetectorFinding] = Field(default_factory=list)
    score_explanation: str = Field(
        ...,
        description="How the final score was calculated.",
    )


# ───────────────────────────────────────────────────────────────────
# POLICY ENGINE OUTPUT
# ───────────────────────────────────────────────────────────────────

class PolicyDecision(BaseModel):
    """
    Final security verdict returned by the policy engine.

    Attributes
    ----------
    decision : Decision
        ALLOW / FLAG / QUARANTINE / BLOCK.
    reason : str
        Why this decision was made.
    risk_score : int
        The numeric score that (partly) drove the decision.
    findings : list[DetectorFinding]
        All security findings for transparency.
    """

    decision: Decision
    reason: str
    risk_score: int = Field(..., ge=0, le=100)
    findings: list[DetectorFinding] = Field(default_factory=list)


# ───────────────────────────────────────────────────────────────────
# FULL API RESPONSE
# ───────────────────────────────────────────────────────────────────

class MemoryProcessingResponse(BaseModel):
    """
    The complete response returned by ``POST /api/memories``.

    It wraps the policy decision together with the risk assessment
    and a timestamp, giving callers full visibility into why a memory
    entry was allowed, flagged, quarantined or blocked.

    Attributes
    ----------
    memory_id : str | None
        Assigned only when the entry is stored (ALLOW or FLAG).
        None for QUARANTINE / BLOCK.
    decision : Decision
        The policy verdict.
    reason : str
        Human-readable explanation.
    risk_score : int
        Numeric risk score (0-100).
    risk_level : RiskLevel
        Corresponding risk band.
    findings : list[DetectorFinding]
        All security observations.  Secrets are always redacted.
    flagged : bool
        True when the entry was allowed but with warnings attached.
    timestamp : datetime
        When the processing completed (UTC).
    """

    memory_id: str | None = Field(
        default=None,
        description="ID of stored memory (None if not stored).",
    )
    decision: Decision
    reason: str
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    findings: list[DetectorFinding] = Field(default_factory=list)
    flagged: bool = Field(
        default=False,
        description="True when the entry is allowed but has warnings.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )


# ───────────────────────────────────────────────────────────────────
# DASHBOARD & QUERY SCHEMAS
# ─────────────────────────────────────────────────────────────────

class DashboardStatsResponse(BaseModel):
    """Aggregated security metrics for the Security Overview Dashboard."""

    total_processed: int = Field(..., ge=0)
    trusted_count: int = Field(..., ge=0)
    flagged_count: int = Field(..., ge=0)
    quarantined_count: int = Field(..., ge=0)
    blocked_count: int = Field(..., ge=0)
    threat_category_distribution: dict[str, int] = Field(default_factory=dict)
    risk_score_distribution: dict[str, int] = Field(default_factory=dict)
    recent_events: list[dict[str, Any]] = Field(default_factory=list)
    system_status: str = "operational"
    database_status: str = "connected"


class MemoryItemResponse(BaseModel):
    """Unified read schema for memory entries across all storage tiers."""

    id: str
    content: str | None = None
    content_sha256: str | None = None
    source: str
    user_id: str
    session_id: str | None = None
    decision: str
    risk_score: int
    risk_level: str
    flagged: bool = False
    quarantine_reason: str | None = None
    review_status: str | None = None
    metadata_json: dict[str, Any] | None = None
    findings_json: list[dict[str, Any]] = Field(default_factory=list)
    created_at: datetime


class MemoryListResponse(BaseModel):
    """Paginated list of memory entries."""

    total: int
    page: int
    page_size: int
    items: list[MemoryItemResponse]


class AuditEventItemResponse(BaseModel):
    """Schema for security audit log events."""

    id: str
    event_type: str
    decision: str
    reason: str
    risk_score: int
    risk_level: str
    user_id: str
    session_id: str | None = None
    source: str
    sanitized_evidence: str | None = None
    content_sha256: str
    findings_json: list[dict[str, Any]] = Field(default_factory=list)
    created_at: datetime


class ThreatItemResponse(BaseModel):
    """Individual threat detection incident for the Threat Detection screen."""

    id: str
    memory_id: str | None = None
    detector_name: str
    category: str
    severity: str
    description: str
    evidence: str
    risk_points: int
    decision: str
    user_id: str
    timestamp: datetime


# ─────────────────────────────────────────────────────────────────
# QUARANTINE WORKFLOW SCHEMAS
# ─────────────────────────────────────────────────────────────────

class QuarantineReviewAction(str, Enum):
    """Action taken by a security reviewer on a quarantined entry."""
    APPROVE = "approve"
    REJECT = "reject"


class QuarantineReviewRequest(BaseModel):
    """Request payload for reviewing and resolving a quarantined memory."""

    action: QuarantineReviewAction
    reviewer_notes: str | None = Field(default=None, max_length=1000)


class QuarantineReviewResponse(BaseModel):
    """Result of a quarantine review action."""

    memory_id: str
    action: QuarantineReviewAction
    status: str
    message: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ─────────────────────────────────────────────────────────────────
# ATTACK SIMULATOR SCHEMAS
# ─────────────────────────────────────────────────────────────────

class SimulationRequest(BaseModel):
    """Submission for the Attack Simulator (inspected but NEVER stored)."""

    content: str = Field(
        ...,
        min_length=MIN_CONTENT_LENGTH,
        max_length=MAX_CONTENT_LENGTH,
        description="Memory text to test against detectors and policies.",
    )
    source: MemorySource = Field(default=MemorySource.CONVERSATION)
    user_id: str = Field(default="simulator_user", min_length=1, max_length=256)
    session_id: str | None = Field(default=None, max_length=256)
    metadata: dict[str, Any] | None = None


class SimulationResponse(BaseModel):
    """Result of an Attack Simulator run."""

    decision: Decision
    reason: str
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    findings: list[DetectorFinding] = Field(default_factory=list)
    score_explanation: str
    is_simulation: bool = True
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

