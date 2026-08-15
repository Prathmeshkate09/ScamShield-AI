from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator


class RiskLevel(StrEnum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


def risk_level_for_score(score: int) -> RiskLevel:
    if score <= 14:
        return RiskLevel.SAFE
    if score <= 34:
        return RiskLevel.LOW
    if score <= 59:
        return RiskLevel.MEDIUM
    if score <= 79:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


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
