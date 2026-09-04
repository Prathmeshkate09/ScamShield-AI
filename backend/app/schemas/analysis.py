from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator

from app.services.risk_policy import DEFAULT_RISK_POLICY


class RiskLevel(StrEnum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


def risk_level_for_score(score: int) -> RiskLevel:
    return RiskLevel(DEFAULT_RISK_POLICY.level_for_score(score))


class SignalCategory(StrEnum):
    URGENCY = "urgency"
    IMPERSONATION = "impersonation"
    CREDENTIAL = "credential"
    FINANCIAL = "financial"
    SOCIAL_ENGINEERING = "social_engineering"
    COERCION = "coercion"
    URL = "url"
    SEMANTIC = "semantic"


class SignalSeverity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SignalSource(StrEnum):
    RULE = "rule"
    URL = "url"
    AI = "ai"
    CROSS_SIGNAL = "cross_signal"


class RiskSignal(BaseModel):
    code: str = Field(min_length=2, max_length=100)
    title: str = Field(min_length=2, max_length=160)
    category: SignalCategory
    severity: SignalSeverity
    raw_score: int = Field(ge=0, le=100)
    contribution: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=1)
    source: SignalSource
    evidence: str = Field(min_length=2, max_length=500)


class EvidenceItem(BaseModel):
    id: str = Field(min_length=2, max_length=100)
    title: str = Field(min_length=2, max_length=160)
    category: SignalCategory
    severity: SignalSeverity
    explanation: str = Field(min_length=2, max_length=500)
    source: str = Field(min_length=2, max_length=100)
    score_contribution: int = Field(ge=0, le=100)
    artifact_reference: str | None = Field(default=None, max_length=200)


class UrlFinding(BaseModel):
    code: str = Field(min_length=2, max_length=100)
    title: str = Field(min_length=2, max_length=160)
    severity: SignalSeverity
    explanation: str = Field(min_length=2, max_length=500)
    score: int = Field(ge=0, le=100)


class UrlIntelligenceResult(BaseModel):
    normalized_url: str = Field(min_length=8, max_length=2_048)
    hostname: str = Field(min_length=1, max_length=253)
    registrable_domain: str | None = Field(default=None, max_length=253)
    scheme: str = Field(min_length=2, max_length=10)
    port: int | None = Field(default=None, ge=1, le=65_535)
    path: str = Field(default="/", max_length=2_048)
    query_parameter_count: int = Field(default=0, ge=0, le=1_000)
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    findings: list[UrlFinding] = Field(default_factory=list, max_length=20)


class AttackChainNode(BaseModel):
    id: str = Field(min_length=1, max_length=100)
    label: str = Field(min_length=2, max_length=160)
    type: str = Field(min_length=2, max_length=50)
    severity: SignalSeverity | None = None


class AttackChainEdge(BaseModel):
    source: str = Field(min_length=1, max_length=100)
    target: str = Field(min_length=1, max_length=100)


class AttackChain(BaseModel):
    nodes: list[AttackChainNode] = Field(default_factory=list, max_length=20)
    edges: list[AttackChainEdge] = Field(default_factory=list, max_length=30)


class IncidentStage(StrEnum):
    RECEIVED_ONLY = "received_only"
    CLICKED_LINK = "clicked_link"
    ENTERED_INFORMATION = "entered_information"
    SHARED_CREDENTIAL = "shared_credential"
    SENT_MONEY = "sent_money"


class IncidentResponseGuidance(BaseModel):
    stage: IncidentStage
    title: str = Field(min_length=2, max_length=160)
    actions: list[str] = Field(min_length=1, max_length=8)

    @field_validator("actions")
    @classmethod
    def normalize_actions(cls, values: list[str]) -> list[str]:
        normalized = [value.strip() for value in values if value and value.strip()]
        return list(dict.fromkeys(normalized))


class SemanticFinding(BaseModel):
    code: str = Field(min_length=2, max_length=100)
    title: str = Field(min_length=2, max_length=160)
    category: SignalCategory
    severity: SignalSeverity
    confidence: float = Field(ge=0, le=1)
    explanation: str = Field(min_length=2, max_length=500)


class SemanticAssessment(BaseModel):
    """Future provider contract; it never owns the final server risk score."""

    semantic_risk_score: int = Field(ge=0, le=100)
    scam_type: str = Field(min_length=2, max_length=100)
    confidence: float = Field(ge=0, le=1)
    findings: list[SemanticFinding] = Field(max_length=12)
    explanation: str = Field(min_length=10, max_length=1_500)
    attack_pattern: list[str] = Field(max_length=8)
    recommended_actions: list[str] = Field(max_length=8)


class TextAnalysisRequest(BaseModel):
    text: str = Field(min_length=2, max_length=10_000)

    @field_validator("text")
    @classmethod
    def strip_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Text cannot be empty")
        return value


class UrlAnalysisRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2_048)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        from urllib.parse import urlsplit

        value = value.strip()
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("A complete HTTP or HTTPS URL is required")
        return value


class VoiceAnalysisRequest(BaseModel):
    transcript: str = Field(min_length=2, max_length=10_000)

    @field_validator("transcript")
    @classmethod
    def strip_transcript(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Transcript cannot be empty")
        return value


class ScamAssessment(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    scam_type: str = Field(min_length=2, max_length=100)
    confidence: float = Field(ge=0, le=1)
    red_flags: list[str] = Field(min_length=0, max_length=8)
    explanation: str = Field(min_length=10, max_length=1_500)
    recommendation: list[str] = Field(min_length=1, max_length=6)

    @field_validator("red_flags", "recommendation")
    @classmethod
    def normalize_lists(cls, values: list[str]) -> list[str]:
        normalized = [value.strip() for value in values if value and value.strip()]
        return list(dict.fromkeys(normalized))

    @model_validator(mode="after")
    def normalize_risk_level(self) -> "ScamAssessment":
        self.risk_level = risk_level_for_score(self.risk_score)
        return self


class AnalysisResponse(ScamAssessment):
    id: UUID
    input_type: str
    signals: list[RiskSignal] = Field(default_factory=list, max_length=50)
    evidence: list[EvidenceItem] = Field(default_factory=list, max_length=50)
    extracted_urls: list[str] = Field(default_factory=list, max_length=20)
    url_intelligence: list[UrlIntelligenceResult] = Field(default_factory=list, max_length=20)
    attack_chain: AttackChain = Field(default_factory=AttackChain)
    incident_response: list[IncidentResponseGuidance] = Field(default_factory=list, max_length=5)
    analysis_duration_ms: int | None = Field(default=None, ge=0)
    ai_provider: str | None = Field(default=None, max_length=40)
    model_name: str | None = Field(default=None, max_length=120)
    scoring_version: str = Field(default=DEFAULT_RISK_POLICY.version, min_length=1, max_length=30)
    created_at: datetime


class AnalysisListResponse(BaseModel):
    items: list[AnalysisResponse]
    page: int
    page_size: int
    total: int


class DashboardStats(BaseModel):
    total_analyses: int
    high_risk_detected: int
    critical_scams: int
    most_common_scam_type: str | None
