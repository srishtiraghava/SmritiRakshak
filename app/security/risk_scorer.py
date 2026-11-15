"""
SmritiRakshak — Memory Risk Scoring Engine
===========================================

Converts security findings into a normalized, explainable risk score
bounded between 0 and 100.

Responsibilities
────────────────
• Aggregates detector findings without duplicating detection logic.
• Deduplicates identical findings to prevent accidental double-counting.
• Applies configurable weights (by severity or detector name).
• Bounds the final score strictly between RISK_SCORE_MIN and RISK_SCORE_MAX (0–100).
• Maps the numeric score to a standardized RiskLevel (low, medium, high, critical).
• Produces a human-readable, auditable score explanation for transparency.
"""

from __future__ import annotations

from typing import Mapping

from app.core.config import (
    RISK_SCORE_MAX,
    RISK_SCORE_MIN,
    THRESHOLD_BLOCK,
    THRESHOLD_FLAG,
    THRESHOLD_QUARANTINE,
)
from app.schemas.memory import DetectorFinding, RiskAssessment, RiskLevel, Severity


# Default multipliers applied to risk_points based on severity
DEFAULT_SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.LOW: 1.0,
    Severity.MEDIUM: 1.0,
    Severity.HIGH: 1.0,
    Severity.CRITICAL: 1.0,
}


def deduplicate_findings(findings: list[DetectorFinding]) -> list[DetectorFinding]:
    """Filter out exact duplicate findings based on detector name, category, and evidence.

    This prevents accidental multi-counting when multiple detectors or repeated
    evaluation passes produce identical findings for the same matched snippet.
    """
    seen: set[tuple[str, str, str]] = set()
    unique: list[DetectorFinding] = []

    for f in findings:
        signature = (f.detector_name, f.category, f.evidence)
        if signature not in seen:
            seen.add(signature)
            unique.append(f)

    return unique


def determine_risk_level(score: int) -> RiskLevel:
    """Map a 0-100 risk score to a RiskLevel band using centralized thresholds."""
    if score >= THRESHOLD_BLOCK:
        return RiskLevel.CRITICAL
    if score >= THRESHOLD_QUARANTINE:
        return RiskLevel.HIGH
    if score >= THRESHOLD_FLAG:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def calculate_risk(
    findings: list[DetectorFinding],
    severity_weights: Mapping[Severity, float] | None = None,
    detector_weights: Mapping[str, float] | None = None,
) -> RiskAssessment:
    """Compute an aggregated risk score and explanation from security findings.

    Formula
    ───────
    1. Deduplicate findings to prevent duplicate point accumulation.
    2. For each unique finding:
         effective_points = round(finding.risk_points * severity_weight * detector_weight)
    3. raw_score = sum(effective_points)
    4. risk_score = clamp(raw_score, RISK_SCORE_MIN, RISK_SCORE_MAX)
    5. risk_level = map risk_score against configured thresholds

    Parameters
    ----------
    findings : list[DetectorFinding]
        Raw findings emitted by the threat detection engine.
    severity_weights : Mapping[Severity, float] | None
        Optional multiplier overrides per severity (default 1.0 for all).
    detector_weights : Mapping[str, float] | None
        Optional multiplier overrides per detector_name (default 1.0).

    Returns
    -------
    RiskAssessment
        Structured risk score, risk level, contributing findings, and explanation.
    """
    weights_sev = dict(DEFAULT_SEVERITY_WEIGHTS)
    if severity_weights:
        weights_sev.update(severity_weights)

    weights_det = dict(detector_weights or {})

    # 1. Deduplicate
    unique_findings = deduplicate_findings(findings)

    if not unique_findings:
        return RiskAssessment(
            risk_score=RISK_SCORE_MIN,
            risk_level=RiskLevel.LOW,
            contributing_findings=[],
            score_explanation="No security findings detected. Baseline risk score: 0/100 (Risk Level: low).",
        )

    # 2. Score calculation with detailed audit lines
    explanation_lines: list[str] = [
        "Risk calculation breakdown:",
    ]
    raw_score = 0

    for idx, f in enumerate(unique_findings, start=1):
        sev_multiplier = weights_sev.get(f.severity, 1.0)
        det_multiplier = weights_det.get(f.detector_name, 1.0)
        total_multiplier = sev_multiplier * det_multiplier

        calculated_points = int(round(f.risk_points * total_multiplier))
        # Ensure individual finding contribution is not negative
        effective_points = max(0, calculated_points)
        raw_score += effective_points

        multiplier_note = (
            f" [multiplier: {total_multiplier:.2f}x]" if total_multiplier != 1.0 else ""
        )
        explanation_lines.append(
            f"  {idx}. [{f.detector_name}] severity={f.severity.value}, base={f.risk_points} pts"
            f"{multiplier_note} -> +{effective_points} pts ({f.description})"
        )

    # 3. Bounding (Clamping)
    clamped_score = max(RISK_SCORE_MIN, min(RISK_SCORE_MAX, raw_score))

    if raw_score > RISK_SCORE_MAX:
        explanation_lines.append(
            f"Raw total points: {raw_score}. Exceeds maximum bound; capped at {RISK_SCORE_MAX}."
        )
    else:
        explanation_lines.append(f"Raw total points: {raw_score}.")

    # 4. Map risk level
    risk_level = determine_risk_level(clamped_score)
    explanation_lines.append(
        f"Final risk score: {clamped_score}/100. Assigned risk level: {risk_level.value}."
    )

    return RiskAssessment(
        risk_score=clamped_score,
        risk_level=risk_level,
        contributing_findings=unique_findings,
        score_explanation="\n".join(explanation_lines),
    )
