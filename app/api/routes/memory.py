"""
SmritiRakshak — Memory Security API Routes
===========================================

Defines the HTTP interface for memory inspection, policy evaluation,
retrieval across segregated PostgreSQL tiers, quarantine workflows,
dashboard telemetry, and attack simulation.

Endpoints:
──────────
• POST /api/memories                     : Submit memory entry for security inspection & tiered persistence.
• GET  /api/memories                     : Filterable, paginated query of memories across segregated tiers.
• GET  /api/memories/{memory_id}         : Fetch a single memory item by ID from its storage tier.
• GET  /api/dashboard/stats              : Aggregate metrics, tier counts, and risk distribution.
• GET  /api/audit-events                 : Query security audit events (tamper-evident log for BLOCKs).
• GET  /api/threats                      : Structured listing of threat detection incidents.
• POST /api/quarantine/{memory_id}/review: Approve or reject quarantined memory.
• POST /api/simulate                     : Real-time attack simulator (runs inspection without database persistence).
• GET  /api/health                       : System operational status and database connectivity.
"""

from __future__ import annotations

from typing import Any
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.core.config import APP_NAME, APP_VERSION
from app.db.repository import MemoryRepository
from app.db.session import engine, get_db
from app.schemas.memory import (
    AuditEventItemResponse,
    DashboardStatsResponse,
    Decision,
    MemoryInput,
    MemoryItemResponse,
    MemoryListResponse,
    MemoryProcessingResponse,
    QuarantineReviewRequest,
    QuarantineReviewResponse,
    SimulationRequest,
    SimulationResponse,
    ThreatItemResponse,
)
from app.security.detector import scan_content
from app.security.policy_engine import evaluate_risk_assessment
from app.security.risk_scorer import calculate_risk
from app.services.memory_service import memory_service

router = APIRouter(tags=["Memory Security"])


# ─────────────────────────────────────────────────────────────────
# Telemetry & Health Endpoints
# ─────────────────────────────────────────────────────────────────

@router.get(
    "/health",
    summary="Health Check",
    description="Returns operational status, application name, version, and independent database connectivity.",
    status_code=status.HTTP_200_OK,
)
def get_health() -> dict[str, str]:
    """Return application health, version, and live PostgreSQL connection state independently."""
    db_state = "connected"
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        db_state = "disconnected"

    return {
        "status": "healthy" if db_state == "connected" else "degraded",
        "app": APP_NAME,
        "version": APP_VERSION,
        "database": db_state,
    }


@router.get(
    "/dashboard/stats",
    response_model=DashboardStatsResponse,
    summary="Security Dashboard Telemetry",
    description="Returns aggregated metrics across all physical PostgreSQL storage tiers.",
    status_code=status.HTTP_200_OK,
)
def get_dashboard_stats(db: Session = Depends(get_db)) -> DashboardStatsResponse:
    """Provide real, database-backed security telemetry for the dashboard."""
    try:
        raw_stats = MemoryRepository.get_dashboard_stats(db)
        return DashboardStatsResponse(**raw_stats)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to compute security telemetry.",
        ) from exc


# ─────────────────────────────────────────────────────────────────
# Core Memory Inspection & Persistence
# ─────────────────────────────────────────────────────────────────

@router.post(
    "/memories",
    response_model=MemoryProcessingResponse,
    status_code=status.HTTP_200_OK,
    summary="Inspect and Process Memory Entry",
    description=(
        "Analyzes an incoming memory entry for prompt injection and sensitive credentials, "
        "computes a bounded risk score, applies security policy, and stores approved items "
        "in segregated PostgreSQL repositories."
    ),
    responses={
        200: {
            "description": "Memory inspected. Result returned (FLAG, QUARANTINE, or BLOCK).",
            "model": MemoryProcessingResponse,
        },
        201: {
            "description": "Memory inspected, ALLOWED, and persisted in trusted memory.",
            "model": MemoryProcessingResponse,
        },
        422: {"description": "Validation error (e.g. empty or oversized content)."},
        500: {"description": "Internal security processing failure. Safe error returned."},
    },
)
def inspect_and_store_memory(
    memory_input: MemoryInput,
    response: Response,
    db: Session = Depends(get_db),
) -> MemoryProcessingResponse:
    """Submit a memory entry for security analysis and policy enforcement."""
    try:
        result = memory_service.process_memory(memory_input, db_session=db)

        # 201 Created for approved entries stored in trusted memory
        if result.decision == Decision.ALLOW:
            response.status_code = status.HTTP_201_CREATED
        else:
            response.status_code = status.HTTP_200_OK

        return result

    except HTTPException:
        raise
    except Exception:
        # Fail closed on unexpected top-level exception: suppress internal details/stack trace
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Security processing failure. Request rejected under fail-closed policy.",
        ) from None


# ─────────────────────────────────────────────────────────────────
# Memory Explorer & Retrieval Endpoints (PostgreSQL-backed)
# ─────────────────────────────────────────────────────────────────

@router.get(
    "/memories",
    response_model=MemoryListResponse,
    summary="List Stored Memories",
    description="Retrieve paginated memories filtered by security tier, user, or session.",
    status_code=status.HTTP_200_OK,
)
def list_memories(
    decision: str | None = Query(
        default=None,
        description="Filter by decision: 'allow', 'flag', 'quarantine', or 'block'.",
    ),
    user_id: str | None = Query(default=None, description="Filter by user identifier."),
    session_id: str | None = Query(default=None, description="Filter by session identifier."),
    page: int = Query(default=1, ge=1, description="Page number."),
    page_size: int = Query(default=50, ge=1, le=200, description="Items per page."),
    db: Session = Depends(get_db),
) -> MemoryListResponse:
    """Query memories from their respective segregated PostgreSQL storage tiers."""
    all_items: list[MemoryItemResponse] = []

    # Filter by specific tier or aggregate across all tiers
    target_decision = decision.lower() if decision else None

    if target_decision in (None, "allow"):
        for row in MemoryRepository.get_trusted_memories(db, user_id=user_id, session_id=session_id):
            all_items.append(
                MemoryItemResponse(
                    id=row.id,
                    content=row.content,
                    source=row.source,
                    user_id=row.user_id,
                    session_id=row.session_id,
                    decision="allow",
                    risk_score=row.risk_score,
                    risk_level=row.risk_level,
                    flagged=False,
                    metadata_json=row.metadata_json,
                    findings_json=row.findings_json or [],
                    created_at=row.created_at,
                )
            )

    if target_decision in (None, "flag"):
        for row in MemoryRepository.get_pending_memories(db, user_id=user_id, session_id=session_id):
            all_items.append(
                MemoryItemResponse(
                    id=row.id,
                    content=row.content,
                    source=row.source,
                    user_id=row.user_id,
                    session_id=row.session_id,
                    decision="flag",
                    risk_score=row.risk_score,
                    risk_level=row.risk_level,
                    flagged=True,
                    review_status=row.review_status,
                    metadata_json=row.metadata_json,
                    findings_json=row.findings_json or [],
                    created_at=row.created_at,
                )
            )

    if target_decision in (None, "quarantine"):
        for row in MemoryRepository.get_quarantined_memories(db, user_id=user_id, session_id=session_id):
            all_items.append(
                MemoryItemResponse(
                    id=row.id,
                    content=row.content,
                    source=row.source,
                    user_id=row.user_id,
                    session_id=row.session_id,
                    decision="quarantine",
                    risk_score=row.risk_score,
                    risk_level=row.risk_level,
                    flagged=False,
                    quarantine_reason=row.quarantine_reason,
                    metadata_json=row.metadata_json,
                    findings_json=row.findings_json or [],
                    created_at=row.created_at,
                )
            )

    if target_decision in (None, "block"):
        for row in MemoryRepository.get_security_audit_events(db, user_id=user_id, session_id=session_id):
            all_items.append(
                MemoryItemResponse(
                    id=row.id,
                    content=None,  # Malicious content is never returned as memory content
                    content_sha256=row.content_sha256,
                    source=row.source,
                    user_id=row.user_id,
                    session_id=row.session_id,
                    decision="block",
                    risk_score=row.risk_score,
                    risk_level=row.risk_level,
                    flagged=False,
                    metadata_json={"event_type": row.event_type, "reason": row.reason},
                    findings_json=row.findings_json or [],
                    created_at=row.created_at,
                )
            )

    # Sort unified results by creation date descending
    all_items.sort(key=lambda x: x.created_at, reverse=True)

    total = len(all_items)
    start_idx = (page - 1) * page_size
    paged_items = all_items[start_idx : start_idx + page_size]

    return MemoryListResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=paged_items,
    )


@router.get(
    "/memories/{memory_id}",
    response_model=MemoryItemResponse,
    summary="Get Memory Details",
    description="Retrieve details of a single memory item from its storage tier.",
    status_code=status.HTTP_200_OK,
)
def get_memory_detail(
    memory_id: str,
    db: Session = Depends(get_db),
) -> MemoryItemResponse:
    """Look up a memory across all physical tiers by its unique identifier."""
    # 1. Check trusted_memories
    trusted = MemoryRepository.get_trusted_memory_by_id(db, memory_id)
    if trusted:
        return MemoryItemResponse(
            id=trusted.id,
            content=trusted.content,
            source=trusted.source,
            user_id=trusted.user_id,
            session_id=trusted.session_id,
            decision="allow",
            risk_score=trusted.risk_score,
            risk_level=trusted.risk_level,
            flagged=False,
            metadata_json=trusted.metadata_json,
            findings_json=trusted.findings_json or [],
            created_at=trusted.created_at,
        )

    # 2. Check pending_review_memories
    pending = MemoryRepository.get_pending_memory_by_id(db, memory_id)
    if pending:
        return MemoryItemResponse(
            id=pending.id,
            content=pending.content,
            source=pending.source,
            user_id=pending.user_id,
            session_id=pending.session_id,
            decision="flag",
            risk_score=pending.risk_score,
            risk_level=pending.risk_level,
            flagged=True,
            review_status=pending.review_status,
            metadata_json=pending.metadata_json,
            findings_json=pending.findings_json or [],
            created_at=pending.created_at,
        )

    # 3. Check quarantined_memories
    quarantined = MemoryRepository.get_quarantined_memory_by_id(db, memory_id)
    if quarantined:
        return MemoryItemResponse(
            id=quarantined.id,
            content=quarantined.content,
            source=quarantined.source,
            user_id=quarantined.user_id,
            session_id=quarantined.session_id,
            decision="quarantine",
            risk_score=quarantined.risk_score,
            risk_level=quarantined.risk_level,
            flagged=False,
            quarantine_reason=quarantined.quarantine_reason,
            metadata_json=quarantined.metadata_json,
            findings_json=quarantined.findings_json or [],
            created_at=quarantined.created_at,
        )

    # 4. Check security_audit_events
    audit = MemoryRepository.get_security_audit_event_by_id(db, memory_id)
    if audit:
        return MemoryItemResponse(
            id=audit.id,
            content=None,
            content_sha256=audit.content_sha256,
            source=audit.source,
            user_id=audit.user_id,
            session_id=audit.session_id,
            decision="block",
            risk_score=audit.risk_score,
            risk_level=audit.risk_level,
            flagged=False,
            metadata_json={"event_type": audit.event_type, "reason": audit.reason},
            findings_json=audit.findings_json or [],
            created_at=audit.created_at,
        )

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Memory '{memory_id}' not found in any repository tier.",
    )


# ─────────────────────────────────────────────────────────────────
# Audit Trail & Threat Detection Endpoints
# ─────────────────────────────────────────────────────────────────

@router.get(
    "/audit-events",
    response_model=list[AuditEventItemResponse],
    summary="List Security Audit Events",
    description="Retrieve tamper-evident audit logs of blocked entries and security events.",
    status_code=status.HTTP_200_OK,
)
def list_audit_events(
    user_id: str | None = Query(default=None, description="Filter by user identifier."),
    session_id: str | None = Query(default=None, description="Filter by session identifier."),
    db: Session = Depends(get_db),
) -> list[AuditEventItemResponse]:
    """Return security audit events recorded in security_audit_events."""
    rows = MemoryRepository.get_security_audit_events(db, user_id=user_id, session_id=session_id)
    return [
        AuditEventItemResponse(
            id=r.id,
            event_type=r.event_type,
            decision=r.decision,
            reason=r.reason,
            risk_score=r.risk_score,
            risk_level=r.risk_level,
            user_id=r.user_id,
            session_id=r.session_id,
            source=r.source,
            sanitized_evidence=r.sanitized_evidence,
            content_sha256=r.content_sha256,
            findings_json=r.findings_json or [],
            created_at=r.created_at,
        )
        for r in rows
    ]


@router.get(
    "/threats",
    response_model=list[ThreatItemResponse],
    summary="List Detected Threats",
    description="Retrieve all threat findings detected across flagged, quarantined, and blocked events.",
    status_code=status.HTTP_200_OK,
)
def list_threats(
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[ThreatItemResponse]:
    """Collate and return threat detection instances for security monitoring."""
    threats: list[ThreatItemResponse] = []

    # Quarantine threats
    for q in MemoryRepository.get_quarantined_memories(db):
        for f in q.findings_json or []:
            threats.append(
                ThreatItemResponse(
                    id=f"{q.id}-{f.get('detector_name', 'threat')}",
                    memory_id=q.id,
                    detector_name=f.get("detector_name", "unknown"),
                    category=f.get("category", "threat"),
                    severity=f.get("severity", "high"),
                    description=f.get("description", ""),
                    evidence=f.get("evidence", "(redacted)"),
                    risk_points=f.get("risk_points", 0),
                    decision="quarantine",
                    user_id=q.user_id,
                    timestamp=q.created_at,
                )
            )

    # Flagged threats
    for p in MemoryRepository.get_pending_memories(db):
        for f in p.findings_json or []:
            threats.append(
                ThreatItemResponse(
                    id=f"{p.id}-{f.get('detector_name', 'threat')}",
                    memory_id=p.id,
                    detector_name=f.get("detector_name", "unknown"),
                    category=f.get("category", "threat"),
                    severity=f.get("severity", "medium"),
                    description=f.get("description", ""),
                    evidence=f.get("evidence", "(redacted)"),
                    risk_points=f.get("risk_points", 0),
                    decision="flag",
                    user_id=p.user_id,
                    timestamp=p.created_at,
                )
            )

    # Blocked threats
    for a in MemoryRepository.get_security_audit_events(db):
        for f in a.findings_json or []:
            threats.append(
                ThreatItemResponse(
                    id=f"{a.id}-{f.get('detector_name', 'threat')}",
                    memory_id=a.id,
                    detector_name=f.get("detector_name", "unknown"),
                    category=f.get("category", "threat"),
                    severity=f.get("severity", "critical"),
                    description=f.get("description", ""),
                    evidence=f.get("evidence", a.sanitized_evidence or "(redacted)"),
                    risk_points=f.get("risk_points", 0),
                    decision="block",
                    user_id=a.user_id,
                    timestamp=a.created_at,
                )
            )

    threats.sort(key=lambda t: t.timestamp, reverse=True)
    return threats[:limit]


# ─────────────────────────────────────────────────────────────────
# Quarantine Center Review Workflow
# ─────────────────────────────────────────────────────────────────

@router.post(
    "/quarantine/{memory_id}/review",
    response_model=QuarantineReviewResponse,
    summary="Review Quarantined Memory",
    description=(
        "Executes an authorized review decision on a quarantined memory: "
        "'approve' releases it to trusted memory; 'reject' logs a permanent "
        "rejection in security audit events."
    ),
    status_code=status.HTTP_200_OK,
)
def review_quarantine_entry(
    memory_id: str,
    request: QuarantineReviewRequest,
    db: Session = Depends(get_db),
) -> QuarantineReviewResponse:
    """Process quarantine resolution with transactional integrity."""
    success, message = MemoryRepository.review_quarantined_memory(
        session=db,
        memory_id=memory_id,
        action=request.action.value,
        reviewer_notes=request.reviewer_notes,
    )

    if not success:
        if "not found" in message.lower():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=message,
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message,
        )

    return QuarantineReviewResponse(
        memory_id=memory_id,
        action=request.action,
        status="resolved",
        message=message,
        timestamp=datetime.now(timezone.utc),
    )


# ─────────────────────────────────────────────────────────────────
# Attack Simulator (In-Memory Inspection Without Persistence)
# ─────────────────────────────────────────────────────────────────

@router.post(
    "/simulate",
    response_model=SimulationResponse,
    summary="Simulate Memory Threat Analysis",
    description=(
        "Runs the live rule-based detector, risk scorer, and policy engine "
        "against candidate memory text. Guarantees zero writes to PostgreSQL "
        "or persistent storage."
    ),
    status_code=status.HTTP_200_OK,
)
def simulate_attack(
    request: SimulationRequest,
) -> SimulationResponse:
    """Simulate security analysis for penetration testing and prompt evaluation."""
    # Step 1: Detect threats using live rules
    findings = scan_content(request.content)

    # Step 2: Calculate bounded risk score
    assessment = calculate_risk(findings)

    # Step 3: Evaluate policy thresholds & critical overrides
    decision = evaluate_risk_assessment(assessment)

    return SimulationResponse(
        decision=decision.decision,
        reason=decision.reason,
        risk_score=assessment.risk_score,
        risk_level=assessment.risk_level,
        findings=decision.findings,
        score_explanation=assessment.score_explanation,
        is_simulation=True,
        timestamp=datetime.now(timezone.utc),
    )
