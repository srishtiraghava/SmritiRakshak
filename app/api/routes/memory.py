"""
SmritiRakshak — Memory Security API Routes
===========================================

Defines the HTTP interface for memory inspection, policy evaluation,
and system health check.

Endpoints:
──────────
• POST /api/memories : Submit a candidate memory entry for security inspection.
• GET  /api/health   : System health check and metadata.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from app.core.config import APP_NAME, APP_VERSION
from app.db.session import get_db
from app.schemas.memory import (
    Decision,
    MemoryInput,
    MemoryProcessingResponse,
)
from app.services.memory_service import memory_service

router = APIRouter(tags=["Memory Security"])


@router.get(
    "/health",
    summary="Health Check",
    description="Returns the operational status, application name, and version.",
    status_code=status.HTTP_200_OK,
)
def get_health() -> dict[str, str]:
    """Return application health and version metadata."""
    return {
        "status": "healthy",
        "app": APP_NAME,
        "version": APP_VERSION,
    }


@router.post(
    "/memories",
    response_model=MemoryProcessingResponse,
    status_code=status.HTTP_200_OK,
    summary="Inspect and Process Memory Entry",
    description=(
        "Analyzes an incoming memory entry for prompt injection and sensitive credentials, "
        "computes a bounded risk score, applies security policy, and stores approved items "
        "in segregated repositories."
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
    """Submit a memory entry for security analysis and policy enforcement.

    Returns the decision (ALLOW, FLAG, QUARANTINE, or BLOCK), risk score,
    and redacted findings.
    """
    try:
        result = memory_service.process_memory(memory_input, db_session=db)

        # Set 201 Created if memory was successfully approved and stored in trusted memory
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
