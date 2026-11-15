"""
Tests for ``app.security.policy_engine`` — SmritiRakshak Policy Engine
======================================================================

Covers:
1. Standard threshold bands:
   - 0–29   -> ALLOW
   - 30–49  -> FLAG
   - 50–79  -> QUARANTINE
   - 80–100 -> BLOCK
2. Exact boundary values (0, 29, 30, 49, 50, 79, 80, 100).
3. Critical security finding overrides (forces BLOCK even with low score).
4. Invalid score inputs (negative numbers, >100, boolean, None, strings) -> fail closed.
5. Integration with RiskAssessment schema.
6. Custom threshold configurations.
7. Validation of output explanations and schema conformity.
"""

from __future__ import annotations

import pytest

from app.core.config import (
    THRESHOLD_BLOCK,
    THRESHOLD_FLAG,
    THRESHOLD_QUARANTINE,
)
from app.schemas.memory import (
    Decision,
    DetectorFinding,
    PolicyDecision,
    RiskAssessment,
    RiskLevel,
    Severity,
)
from app.security.policy_engine import evaluate_policy, evaluate_risk_assessment


def _make_finding(
    name: str = "policy_test_finding",
    severity: Severity = Severity.LOW,
    points: int = 10,
    evidence: str = "sample_evidence",
    description: str = "Sample finding description",
) -> DetectorFinding:
    """Helper to instantiate a valid DetectorFinding."""
    return DetectorFinding(
        detector_name=name,
        category="test_category",
        severity=severity,
        description=description,
        evidence=evidence,
        risk_points=points,
    )


class TestThresholdDecisions:
    """Tests for each score band."""

    def test_allow_band(self):
        decision = evaluate_policy(15)
        assert decision.decision == Decision.ALLOW
        assert decision.risk_score == 15
        assert "below flag threshold" in decision.reason

    def test_flag_band(self):
        decision = evaluate_policy(40)
        assert decision.decision == Decision.FLAG
        assert decision.risk_score == 40
        assert "flag threshold" in decision.reason

    def test_quarantine_band(self):
        decision = evaluate_policy(65)
        assert decision.decision == Decision.QUARANTINE
        assert decision.risk_score == 65
        assert "quarantine threshold" in decision.reason

    def test_block_band(self):
        decision = evaluate_policy(90)
        assert decision.decision == Decision.BLOCK
        assert decision.risk_score == 90
        assert "block threshold" in decision.reason


class TestBoundaryValues:
    """Tests boundary values for all policy tiers."""

    @pytest.mark.parametrize(
        "score,expected_decision",
        [
            (0, Decision.ALLOW),
            (29, Decision.ALLOW),
            (30, Decision.FLAG),
            (49, Decision.FLAG),
            (50, Decision.QUARANTINE),
            (79, Decision.QUARANTINE),
            (80, Decision.BLOCK),
            (100, Decision.BLOCK),
        ],
    )
    def test_boundary_transitions(self, score: int, expected_decision: Decision):
        decision = evaluate_policy(score)
        assert decision.decision == expected_decision
        assert decision.risk_score == score
        assert isinstance(decision.reason, str)
        assert len(decision.reason) > 0


class TestCriticalFindingOverride:
    """A critical finding must always force BLOCK regardless of risk score."""

    def test_critical_finding_overrides_zero_score(self):
        finding = _make_finding(
            name="prompt_injection_override",
            severity=Severity.CRITICAL,
            points=40,
            description="Attempt to override system prompt",
        )
        decision = evaluate_policy(risk_score=0, findings=[finding])
        assert decision.decision == Decision.BLOCK
        assert decision.risk_score == 0
        assert "critical security finding" in decision.reason.lower()
        assert "prompt_injection_override" in decision.reason

    def test_critical_finding_overrides_allow_band_score(self):
        finding = _make_finding(
            name="private_key_leak",
            severity=Severity.CRITICAL,
            points=25,
        )
        decision = evaluate_policy(risk_score=25, findings=[finding])
        assert decision.decision == Decision.BLOCK
        assert "private_key_leak" in decision.reason

    def test_non_critical_finding_does_not_override_low_score(self):
        finding = _make_finding(
            name="minor_hint",
            severity=Severity.LOW,
            points=10,
        )
        decision = evaluate_policy(risk_score=10, findings=[finding])
        assert decision.decision == Decision.ALLOW


class TestInvalidScoresFailClosed:
    """Invalid, out-of-range, or malformed risk scores must fail closed as BLOCK."""

    def test_negative_score_fails_closed(self):
        decision = evaluate_policy(risk_score=-1)
        assert decision.decision == Decision.BLOCK
        assert decision.risk_score == 100
        assert "Invalid risk score" in decision.reason

    def test_score_above_100_fails_closed(self):
        decision = evaluate_policy(risk_score=150)
        assert decision.decision == Decision.BLOCK
        assert decision.risk_score == 100
        assert "Invalid risk score" in decision.reason

    def test_boolean_input_fails_closed(self):
        # In Python, bool is a subclass of int (True == 1), so check explicit bool safety
        decision = evaluate_policy(risk_score=True)  # type: ignore[arg-type]
        assert decision.decision == Decision.BLOCK
        assert decision.risk_score == 100
        assert "Invalid risk score" in decision.reason

    def test_none_input_fails_closed(self):
        decision = evaluate_policy(risk_score=None)  # type: ignore[arg-type]
        assert decision.decision == Decision.BLOCK
        assert decision.risk_score == 100
        assert "Invalid risk score" in decision.reason

    def test_string_input_fails_closed(self):
        decision = evaluate_policy(risk_score="eighty")  # type: ignore[arg-type]
        assert decision.decision == Decision.BLOCK
        assert decision.risk_score == 100
        assert "Invalid risk score" in decision.reason


class TestEvaluateRiskAssessment:
    """Test helper that receives a full RiskAssessment instance."""

    def test_risk_assessment_evaluation(self):
        f = _make_finding(name="api_token", severity=Severity.HIGH, points=35)
        assessment = RiskAssessment(
            risk_score=35,
            risk_level=RiskLevel.MEDIUM,
            contributing_findings=[f],
            score_explanation="Calculated 35 points.",
        )
        decision = evaluate_risk_assessment(assessment)
        assert decision.decision == Decision.FLAG
        assert decision.risk_score == 35
        assert len(decision.findings) == 1
        assert decision.findings[0].detector_name == "api_token"


class TestCustomThresholds:
    """Configurable threshold parameters should be respected."""

    def test_stricter_custom_thresholds(self):
        # Strict policy: FLAG at 10, QUARANTINE at 20, BLOCK at 30
        decision = evaluate_policy(
            risk_score=25,
            threshold_flag=10,
            threshold_quarantine=20,
            threshold_block=30,
        )
        assert decision.decision == Decision.QUARANTINE
