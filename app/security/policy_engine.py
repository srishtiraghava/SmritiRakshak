"""
SmritiRakshak — Security Policy Engine
=======================================

Applies security policy rules and thresholds to evaluate memory risk
scores and findings, producing a definitive decision:
  ALLOW, FLAG, QUARANTINE, or BLOCK.

Policy Thresholds (Configurable via app.core.config):
────────────────────────────────────────────────────
  0  .. THRESHOLD_FLAG - 1       (0–29)  → ALLOW
  THRESHOLD_FLAG .. QUARANTINE - 1 (30–49) → FLAG
  THRESHOLD_QUARANTINE .. BLOCK - 1 (50–79) → QUARANTINE
  THRESHOLD_BLOCK .. 100          (80–100) → BLOCK

Critical Override Rule:
───────────────────────
Any finding marked with Severity.CRITICAL (or matching CRITICAL_SEVERITY)
forces an immediate BLOCK decision, regardless of the numerical risk score.

Fail-Closed Philosophy:
───────────────────────
Invalid scores or unexpected input will fail closed by triggering a BLOCK
with a detailed explanation rather than allowing the entry.
"""

from __future__ import annotations

from app.core.config import (
    CRITICAL_SEVERITY,
    RISK_SCORE_MAX,
    RISK_SCORE_MIN,
    THRESHOLD_BLOCK,
    THRESHOLD_FLAG,
    THRESHOLD_QUARANTINE,
)
from app.schemas.memory import (
    Decision,
    DetectorFinding,
    PolicyDecision,
    RiskAssessment,
    Severity,
)


def evaluate_policy(
    risk_score: int,
    findings: list[DetectorFinding] | None = None,
    threshold_flag: int = THRESHOLD_FLAG,
    threshold_quarantine: int = THRESHOLD_QUARANTINE,
    threshold_block: int = THRESHOLD_BLOCK,
) -> PolicyDecision:
    """Evaluate a numeric risk score and findings list against security policy.

    Parameters
    ----------
    risk_score : int
        Computed risk score (expected between RISK_SCORE_MIN and RISK_SCORE_MAX).
    findings : list[DetectorFinding] | None
        List of detector findings associated with the memory entry.
    threshold_flag : int
        Lower bound for FLAG decision (inclusive).
    threshold_quarantine : int
        Lower bound for QUARANTINE decision (inclusive).
    threshold_block : int
        Lower bound for BLOCK decision (inclusive).

    Returns
    -------
    PolicyDecision
        Standardized policy verdict (decision, reason, risk_score, findings).
    """
    findings_list = list(findings or [])

    # 1. Fail-closed safety check on risk_score input
    if (
        not isinstance(risk_score, (int, float))
        or isinstance(risk_score, bool)
        or risk_score < RISK_SCORE_MIN
        or risk_score > RISK_SCORE_MAX
    ):
        return PolicyDecision(
            decision=Decision.BLOCK,
            reason=(
                f"Fail-closed policy trigger: Invalid risk score ({risk_score!r}) received. "
                f"Must be a number between {RISK_SCORE_MIN} and {RISK_SCORE_MAX}."
            ),
            risk_score=RISK_SCORE_MAX,
            findings=findings_list,
        )

    norm_score = int(risk_score)

    # 2. Critical findings override check:
    # Any finding with CRITICAL severity forces an immediate BLOCK.
    critical_findings = [
        f
        for f in findings_list
        if f.severity == Severity.CRITICAL or f.severity.value == CRITICAL_SEVERITY
    ]
    if critical_findings:
        critical_names = ", ".join(f.detector_name for f in critical_findings)
        return PolicyDecision(
            decision=Decision.BLOCK,
            reason=(
                f"Blocked due to critical security finding(s): [{critical_names}]. "
                f"Critical findings enforce BLOCK regardless of risk score ({norm_score})."
            ),
            risk_score=norm_score,
            findings=findings_list,
        )

    # 3. Threshold evaluation
    if norm_score >= threshold_block:
        return PolicyDecision(
            decision=Decision.BLOCK,
            reason=(
                f"Blocked: Risk score {norm_score} reached or exceeded block threshold "
                f"({threshold_block})."
            ),
            risk_score=norm_score,
            findings=findings_list,
        )

    if norm_score >= threshold_quarantine:
        return PolicyDecision(
            decision=Decision.QUARANTINE,
            reason=(
                f"Quarantined: Risk score {norm_score} reached or exceeded quarantine threshold "
                f"({threshold_quarantine}) but is below block threshold ({threshold_block})."
            ),
            risk_score=norm_score,
            findings=findings_list,
        )

    if norm_score >= threshold_flag:
        return PolicyDecision(
            decision=Decision.FLAG,
            reason=(
                f"Flagged: Risk score {norm_score} reached or exceeded flag threshold "
                f"({threshold_flag}) but is below quarantine threshold ({threshold_quarantine})."
            ),
            risk_score=norm_score,
            findings=findings_list,
        )

    return PolicyDecision(
        decision=Decision.ALLOW,
        reason=(
            f"Allowed: Risk score {norm_score} is below flag threshold ({threshold_flag}). "
            "No critical security issues detected."
        ),
        risk_score=norm_score,
        findings=findings_list,
    )


def evaluate_risk_assessment(
    assessment: RiskAssessment,
    threshold_flag: int = THRESHOLD_FLAG,
    threshold_quarantine: int = THRESHOLD_QUARANTINE,
    threshold_block: int = THRESHOLD_BLOCK,
) -> PolicyDecision:
    """Convenience helper to evaluate a complete RiskAssessment object."""
    return evaluate_policy(
        risk_score=assessment.risk_score,
        findings=assessment.contributing_findings,
        threshold_flag=threshold_flag,
        threshold_quarantine=threshold_quarantine,
        threshold_block=threshold_block,
    )
