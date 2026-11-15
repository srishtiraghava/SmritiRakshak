"""
SmritiRakshak — Memory Security Service
========================================

Orchestrates the end-to-end memory inspection and storage workflow:
  1. Input validation (via MemoryInput schema)
  2. Threat detection (via detector.scan_content)
  3. Risk scoring (via risk_scorer.calculate_risk)
  4. Policy enforcement (via policy_engine.evaluate_risk_assessment)
  5. Isolated in-memory repository storage based on decision:
     - ALLOW      → Trusted memory repository
     - FLAG       → Pending-review repository (flagged, not trusted)
     - QUARANTINE → Isolated quarantine repository
     - BLOCK      → Rejected / audit repository (never in trusted)

Security Guarantees:
────────────────────
• Fail-closed: Any unexpected runtime exception during detection or
  processing results in a BLOCK decision and no trusted write.
• Zero Secret Leakage: Safe explanations and findings with redacted
  evidence are returned; no credentials or stack traces are emitted.
• Complete Separation of Tiers: Flagged and quarantined memories are
  physically kept in separate repositories and never returned by
  trusted memory queries.
• Decoupled Architecture: Independent of FastAPI or HTTP frameworks,
  suitable for standalone reuse across any AI agent system.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.schemas.memory import (
    Decision,
    DetectorFinding,
    MemoryInput,
    MemoryProcessingResponse,
    RiskLevel,
    Severity,
)
from app.security.detector import scan_content
from app.security.policy_engine import evaluate_risk_assessment
from app.security.risk_scorer import calculate_risk


@dataclass
class StoredMemory:
    """Represents a memory entry stored in one of the repositories."""

    id: str
    content: str
    source: str
    user_id: str
    session_id: str | None
    metadata: dict[str, Any] | None
    decision: Decision
    risk_score: int
    risk_level: RiskLevel
    flagged: bool
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class MemoryService:
    """Coordinates memory security evaluation and segregated in-memory storage."""

    def __init__(self) -> None:
        # Segregated in-memory repositories
        self._trusted_repo: dict[str, StoredMemory] = {}
        self._pending_review_repo: dict[str, StoredMemory] = {}
        self._quarantine_repo: dict[str, StoredMemory] = {}
        self._blocked_repo: dict[str, StoredMemory] = {}

    def clear(self) -> None:
        """Clear all repositories (primarily for test isolation)."""
        self._trusted_repo.clear()
        self._pending_review_repo.clear()
        self._quarantine_repo.clear()
        self._blocked_repo.clear()

    # ─────────────────────────────────────────────────────────────────
    # Public Workflow Entry Point
    # ─────────────────────────────────────────────────────────────────

    def process_memory(
        self,
        memory_entry: MemoryInput | dict[str, Any],
    ) -> MemoryProcessingResponse:
        """Execute the full 5-step security pipeline on an incoming memory entry.

        Parameters
        ----------
        memory_entry : MemoryInput | dict
            The incoming memory payload. Validated via MemoryInput schema.

        Returns
        -------
        MemoryProcessingResponse
            The structured security decision and metadata.
        """
        # Step 1: Validate input
        try:
            if isinstance(memory_entry, dict):
                validated_input = MemoryInput(**memory_entry)
            elif isinstance(memory_entry, MemoryInput):
                validated_input = memory_entry
            else:
                raise TypeError(
                    f"Expected MemoryInput or dict, got {type(memory_entry).__name__}"
                )
        except Exception as validation_err:
            # Let validation errors raise or fail closed
            raise validation_err

        # Steps 2-5: Detection, Scoring, Policy, Storage (with fail-closed protection)
        try:
            # Step 2: Threat Detection
            findings = scan_content(validated_input.content)

            # Step 3: Risk Scoring
            risk_assessment = calculate_risk(findings)

            # Step 4: Policy Enforcement
            policy_decision = evaluate_risk_assessment(risk_assessment)

            # Step 5: Segregated Storage
            decision = policy_decision.decision
            entry_id = f"mem-{uuid.uuid4().hex[:12]}"
            now = datetime.now(timezone.utc)

            stored_record = StoredMemory(
                id=entry_id,
                content=validated_input.content,
                source=validated_input.source.value,
                user_id=validated_input.user_id,
                session_id=validated_input.session_id,
                metadata=validated_input.metadata,
                decision=decision,
                risk_score=risk_assessment.risk_score,
                risk_level=risk_assessment.risk_level,
                flagged=(decision == Decision.FLAG),
                created_at=now,
            )

            response_memory_id: str | None = None
            is_flagged = False

            if decision == Decision.ALLOW:
                self._trusted_repo[entry_id] = stored_record
                response_memory_id = entry_id
                is_flagged = False

            elif decision == Decision.FLAG:
                self._pending_review_repo[entry_id] = stored_record
                response_memory_id = entry_id
                is_flagged = True

            elif decision == Decision.QUARANTINE:
                self._quarantine_repo[entry_id] = stored_record
                response_memory_id = None
                is_flagged = False

            elif decision == Decision.BLOCK:
                self._blocked_repo[entry_id] = stored_record
                response_memory_id = None
                is_flagged = False

            return MemoryProcessingResponse(
                memory_id=response_memory_id,
                decision=decision,
                reason=policy_decision.reason,
                risk_score=risk_assessment.risk_score,
                risk_level=risk_assessment.risk_level,
                findings=policy_decision.findings,
                flagged=is_flagged,
                timestamp=now,
            )

        except Exception as exc:
            # Fail closed on any unexpected processing or detector failure
            return MemoryProcessingResponse(
                memory_id=None,
                decision=Decision.BLOCK,
                reason="Security inspection failed due to internal error. Entry rejected under fail-closed policy.",
                risk_score=100,
                risk_level=RiskLevel.CRITICAL,
                findings=[
                    DetectorFinding(
                        detector_name="system_fail_closed_error",
                        category="system_error",
                        severity=Severity.CRITICAL,
                        description="Internal security processing failure. Content was not trusted.",
                        evidence="(redacted: error occurred during evaluation)",
                        risk_points=100,
                    )
                ],
                flagged=False,
                timestamp=datetime.now(timezone.utc),
            )

    # ─────────────────────────────────────────────────────────────────
    # Repository Access Queries
    # ─────────────────────────────────────────────────────────────────

    def get_trusted_memories(self, user_id: str | None = None) -> list[StoredMemory]:
        """Retrieve memories from the trusted repository only (ALLOW).

        Flagged, quarantined, and blocked memories are strictly excluded.
        """
        records = list(self._trusted_repo.values())
        if user_id is not None:
            records = [r for r in records if r.user_id == user_id]
        return records

    def get_pending_memories(self, user_id: str | None = None) -> list[StoredMemory]:
        """Retrieve memories pending security review (FLAG)."""
        records = list(self._pending_review_repo.values())
        if user_id is not None:
            records = [r for r in records if r.user_id == user_id]
        return records

    def get_quarantined_memories(self, user_id: str | None = None) -> list[StoredMemory]:
        """Retrieve quarantined memories (QUARANTINE)."""
        records = list(self._quarantine_repo.values())
        if user_id is not None:
            records = [r for r in records if r.user_id == user_id]
        return records

    def get_blocked_memories(self, user_id: str | None = None) -> list[StoredMemory]:
        """Retrieve blocked memories (BLOCK)."""
        records = list(self._blocked_repo.values())
        if user_id is not None:
            records = [r for r in records if r.user_id == user_id]
        return records

    def get_trusted_memory_by_id(self, memory_id: str) -> StoredMemory | None:
        """Fetch a specific trusted memory by ID.

        Returns None if not found or if stored in review/quarantine/blocked tiers.
        """
        return self._trusted_repo.get(memory_id)


# Global singleton instance for app-wide use
memory_service = MemoryService()
