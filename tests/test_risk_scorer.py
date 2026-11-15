"""
Tests for ``app.security.risk_scorer`` — SmritiRakshak Risk Scoring Engine
==========================================================================

Covers:
1. No findings (baseline zero score, LOW risk level).
2. Single low-risk finding (points mapped, LOW or MEDIUM band).
3. Multiple findings (points accumulate additively).
4. High-risk / critical findings (maps to HIGH / CRITICAL risk level).
5. Score never exceeding 100 (upper bound clamping).
6. Deduplication of identical findings (prevent double-counting).
7. Configurable severity and detector weight multipliers.
8. Plain-English explanation generation.
"""

from __future__ import annotations

import pytest

from app.core.config import (
    RISK_SCORE_MAX,
    RISK_SCORE_MIN,
    THRESHOLD_BLOCK,
    THRESHOLD_FLAG,
    THRESHOLD_QUARANTINE,
)
from app.schemas.memory import DetectorFinding, RiskLevel, Severity
from app.security.risk_scorer import (
    calculate_risk,
    deduplicate_findings,
    determine_risk_level,
)


def _make_finding(
    name: str = "test_rule",
    category: str = "test_cat",
    severity: Severity = Severity.LOW,
    points: int = 15,
    evidence: str = "snippet",
    description: str = "Test description",
) -> DetectorFinding:
    """Helper to instantiate a valid DetectorFinding."""
    return DetectorFinding(
        detector_name=name,
        category=category,
        severity=severity,
        description=description,
        evidence=evidence,
        risk_points=points,
    )


class TestNoFindings:
    """Zero findings should result in baseline zero score and LOW risk."""

    def test_empty_findings_list(self):
        result = calculate_risk([])
        assert result.risk_score == 0
        assert result.risk_level == RiskLevel.LOW
        assert result.contributing_findings == []
        assert "0/100" in result.score_explanation
        assert "low" in result.score_explanation.lower()


class TestSingleFinding:
    """Single finding scoring and classification."""

    def test_single_low_risk_finding(self):
        f = _make_finding(
            name="anti_logging_hint",
            severity=Severity.LOW,
            points=15,
            evidence="don't log",
            description="Minor anti-logging phrase",
        )
        result = calculate_risk([f])
        assert result.risk_score == 15
        assert result.risk_level == RiskLevel.LOW
        assert len(result.contributing_findings) == 1
        assert "anti_logging_hint" in result.score_explanation
        assert "+15 pts" in result.score_explanation

    def test_single_medium_risk_finding_crosses_flag_threshold(self):
        f = _make_finding(
            name="suspicious_context",
            severity=Severity.MEDIUM,
            points=35,
            evidence="potential bypass",
        )
        result = calculate_risk([f])
        assert result.risk_score == 35
        # 35 is >= THRESHOLD_FLAG (30) and < THRESHOLD_QUARANTINE (50) -> MEDIUM
        assert result.risk_level == RiskLevel.MEDIUM


class TestMultipleFindings:
    """Multiple findings should accumulate risk points additively."""

    def test_additive_scoring(self):
        f1 = _make_finding(name="rule_a", points=20, evidence="ev1")
        f2 = _make_finding(name="rule_b", points=25, evidence="ev2")
        result = calculate_risk([f1, f2])
        assert result.risk_score == 45
        assert result.risk_level == RiskLevel.MEDIUM
        assert len(result.contributing_findings) == 2
        assert "45" in result.score_explanation

    def test_multiple_findings_crossing_quarantine_threshold(self):
        f1 = _make_finding(name="api_key_rule", severity=Severity.HIGH, points=30, evidence="key1")
        f2 = _make_finding(name="prompt_override_rule", severity=Severity.HIGH, points=35, evidence="override")
        result = calculate_risk([f1, f2])
        # 30 + 35 = 65 -> >= THRESHOLD_QUARANTINE (50) and < THRESHOLD_BLOCK (80) -> HIGH
        assert result.risk_score == 65
        assert result.risk_level == RiskLevel.HIGH
        assert len(result.contributing_findings) == 2


class TestHighRiskFindings:
    """High risk and critical findings produce high scores and correct risk bands."""

    def test_critical_score_band(self):
        f1 = _make_finding(name="injection_critical", severity=Severity.CRITICAL, points=45, evidence="eval()")
        f2 = _make_finding(name="secret_exfil", severity=Severity.CRITICAL, points=40, evidence="curl evil.com")
        result = calculate_risk([f1, f2])
        # 45 + 40 = 85 -> >= THRESHOLD_BLOCK (80) -> CRITICAL
        assert result.risk_score == 85
        assert result.risk_level == RiskLevel.CRITICAL


class TestScoreBounds:
    """The final score must never exceed 100 or fall below 0."""

    def test_score_capped_at_100_when_exceeded(self):
        findings = [
            _make_finding(name=f"vuln_{i}", points=40, evidence=f"evidence_{i}")
            for i in range(5)
        ]
        # 5 * 40 = 200 raw points
        result = calculate_risk(findings)
        assert result.risk_score == 100
        assert result.risk_score <= RISK_SCORE_MAX
        assert result.risk_level == RiskLevel.CRITICAL
        assert "Exceeds maximum bound; capped at 100" in result.score_explanation

    def test_extreme_single_point_capped(self):
        f = _make_finding(name="exploit", points=100, evidence="super_payload")
        result = calculate_risk([f])
        assert result.risk_score == 100
        assert result.risk_level == RiskLevel.CRITICAL

    def test_determine_risk_level_boundaries(self):
        assert determine_risk_level(0) == RiskLevel.LOW
        assert determine_risk_level(THRESHOLD_FLAG - 1) == RiskLevel.LOW
        assert determine_risk_level(THRESHOLD_FLAG) == RiskLevel.MEDIUM
        assert determine_risk_level(THRESHOLD_QUARANTINE - 1) == RiskLevel.MEDIUM
        assert determine_risk_level(THRESHOLD_QUARANTINE) == RiskLevel.HIGH
        assert determine_risk_level(THRESHOLD_BLOCK - 1) == RiskLevel.HIGH
        assert determine_risk_level(THRESHOLD_BLOCK) == RiskLevel.CRITICAL
        assert determine_risk_level(100) == RiskLevel.CRITICAL


class TestDeduplication:
    """Identical findings must not be counted multiple times."""

    def test_identical_findings_deduplicated(self):
        f1 = _make_finding(name="same_rule", points=30, evidence="identical_snippet")
        f2 = _make_finding(name="same_rule", points=30, evidence="identical_snippet")
        result = calculate_risk([f1, f2])
        assert result.risk_score == 30
        assert len(result.contributing_findings) == 1

    def test_different_evidence_not_deduplicated(self):
        # Two distinct keys found by the same detector rule
        f1 = _make_finding(name="key_detector", points=30, evidence="key_1_redacted")
        f2 = _make_finding(name="key_detector", points=30, evidence="key_2_redacted")
        result = calculate_risk([f1, f2])
        assert result.risk_score == 60
        assert len(result.contributing_findings) == 2


class TestConfigurableWeights:
    """Weights and multipliers can adjust the calculated score."""

    def test_severity_weight_override(self):
        f = _make_finding(severity=Severity.HIGH, points=20, evidence="test")
        # Double the weight of HIGH findings
        result = calculate_risk([f], severity_weights={Severity.HIGH: 2.0})
        assert result.risk_score == 40
        assert "multiplier: 2.00x" in result.score_explanation

    def test_detector_weight_override(self):
        f = _make_finding(name="custom_scanner", points=20, evidence="test")
        result = calculate_risk([f], detector_weights={"custom_scanner": 1.5})
        assert result.risk_score == 30
        assert "multiplier: 1.50x" in result.score_explanation
