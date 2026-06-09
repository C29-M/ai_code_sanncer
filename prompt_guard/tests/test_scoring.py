"""Tests for the scoring module."""
import pytest
from prompt_guard.scoring import (
    calculate_risk_score,
    determine_risk_level,
    generate_summary,
    generate_recommendations,
    SEVERITY_WEIGHTS,
)
from prompt_guard.findings import Finding


def make_finding(type_="prompt_injection", severity="high", matched="test"):
    return Finding(
        type=type_,
        severity=severity,
        message="Test finding",
        explanation="Test explanation",
        matched_text=matched,
    )


def test_empty_findings_returns_zero():
    assert calculate_risk_score([]) == 0.0


def test_single_critical_finding():
    findings = [make_finding(severity="critical")]
    score = calculate_risk_score(findings)
    assert score == SEVERITY_WEIGHTS["critical"]


def test_multiple_findings_increase_score():
    findings = [
        make_finding(severity="high", type_="prompt_injection"),
        make_finding(severity="critical", type_="jailbreak_attempt"),
    ]
    score = calculate_risk_score(findings)
    assert score > SEVERITY_WEIGHTS["high"]


def test_score_capped_at_ten():
    findings = [make_finding(severity="critical") for _ in range(20)]
    score = calculate_risk_score(findings)
    assert score <= 10.0


def test_risk_level_low():
    assert determine_risk_level(1.0) == "low"


def test_risk_level_medium():
    assert determine_risk_level(3.0) == "medium"


def test_risk_level_high():
    assert determine_risk_level(6.0) == "high"


def test_risk_level_critical():
    assert determine_risk_level(8.0) == "critical"


def test_generate_summary_no_findings():
    summary = generate_summary([], "low")
    assert "safe" in summary.lower() or "no" in summary.lower()


def test_generate_summary_with_findings():
    findings = [make_finding(type_="prompt_injection")]
    summary = generate_summary(findings, "high")
    assert len(summary) > 0
    assert isinstance(summary, str)


def test_recommendations_not_empty_for_findings():
    findings = [make_finding(type_="prompt_injection")]
    recs = generate_recommendations(findings)
    assert len(recs) > 0


def test_recommendations_deduplicated():
    findings = [make_finding(type_="prompt_injection") for _ in range(5)]
    recs = generate_recommendations(findings)
    assert len(recs) == len(set(recs))
