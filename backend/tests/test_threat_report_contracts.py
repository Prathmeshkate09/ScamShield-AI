from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.models.analysis import Analysis
from app.schemas.analysis import AnalysisResponse, RiskLevel, ScamAssessment, SemanticAssessment, risk_level_for_score
from app.services.risk_policy import DEFAULT_RISK_POLICY, RiskPolicy


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, RiskLevel.SAFE),
        (19, RiskLevel.SAFE),
        (20, RiskLevel.LOW),
        (39, RiskLevel.LOW),
        (40, RiskLevel.MEDIUM),
        (59, RiskLevel.MEDIUM),
        (60, RiskLevel.HIGH),
        (79, RiskLevel.HIGH),
        (80, RiskLevel.CRITICAL),
        (100, RiskLevel.CRITICAL),
    ],
)
def test_risk_level_boundaries_are_centralized(score: int, expected: RiskLevel) -> None:
    assert risk_level_for_score(score) is expected


def test_contribution_caps_form_a_complete_policy() -> None:
    assert (
        DEFAULT_RISK_POLICY.semantic_cap
        + DEFAULT_RISK_POLICY.rules_cap
        + DEFAULT_RISK_POLICY.url_cap
        + DEFAULT_RISK_POLICY.corroboration_cap
    ) == 100
    with pytest.raises(ValueError, match="must total 100"):
        RiskPolicy(semantic_cap=34)
    with pytest.raises(ValueError, match="cannot be negative"):
        RiskPolicy(semantic_cap=-1, rules_cap=31)
    with pytest.raises(ValueError, match="must be ordered"):
        RiskPolicy(low_max=19)


def test_legacy_analysis_response_gets_backward_compatible_defaults() -> None:
    fixture_path = Path(__file__).parent / "fixtures" / "legacy_analysis_response.json"
    response = AnalysisResponse.model_validate(json.loads(fixture_path.read_text(encoding="utf-8")))

    assert response.recommendation
    assert response.signals == []
    assert response.evidence == []
    assert response.extracted_urls == []
    assert response.attack_chain.nodes == []
    assert response.attack_chain.edges == []
    assert response.scoring_version == "v1"


def test_semantic_assessment_has_no_final_risk_level_field() -> None:
    assessment = SemanticAssessment(
        semantic_risk_score=75,
        scam_type="Phishing",
        confidence=0.8,
        findings=[],
        explanation="The content contains pressure and a request to verify account details.",
        attack_pattern=[],
        recommended_actions=[],
    )

    assert "risk_level" not in assessment.model_dump()
    assert "risk_score" not in assessment.model_dump()


def test_existing_provider_assessment_schema_remains_compact() -> None:
    properties = set(ScamAssessment.model_json_schema()["properties"])

    assert properties == {
        "risk_score",
        "risk_level",
        "scam_type",
        "confidence",
        "red_flags",
        "explanation",
        "recommendation",
    }


def test_analysis_model_contains_additive_threat_report_columns() -> None:
    expected_columns = {
        "signals",
        "evidence",
        "extracted_urls",
        "url_intelligence",
        "attack_chain",
        "incident_response",
        "analysis_duration_ms",
        "ai_provider",
        "model_name",
        "scoring_version",
    }

    assert expected_columns <= set(Analysis.__table__.columns.keys())
