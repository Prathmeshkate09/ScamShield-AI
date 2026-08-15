from __future__ import annotations

from app.schemas.analysis import ScamAssessment, risk_level_for_score
from app.services.ai_service import AIProvider, parse_assessment
from app.services.url_signals import inspect_url


class ScamAnalyzer:
    def __init__(self, provider: AIProvider) -> None:
        self.provider = provider

    async def analyze_text(self, text: str, input_type: str = "text") -> tuple[ScamAssessment, int]:
        result = await self.provider.analyze_text(text, input_type)
        return parse_assessment(result.raw_json), result.latency_ms
    async def analyze_url(self, url: str) -> tuple[ScamAssessment, int]:
        signals = inspect_url(url)
        result = await self.provider.analyze_text(url, "url", signals.summary + "\nFlags: " + "; ".join(signals.red_flags))
        assessment = parse_assessment(result.raw_json)
        merged_flags = list(dict.fromkeys([*assessment.red_flags, *signals.red_flags]))
        score = max(assessment.risk_score, signals.risk_floor)
        explanation = assessment.explanation
        if signals.red_flags:
            explanation = f"{assessment.explanation} {signals.summary}"
        return (
            assessment.model_copy(
                update={
                    "risk_score": score,
                    "risk_level": risk_level_for_score(score),
                    "red_flags": merged_flags,
                    "explanation": explanation,
                }
            ),
            result.latency_ms,
        )

    async def analyze_image(self, image: bytes, content_type: str) -> tuple[ScamAssessment, int]:
        result = await self.provider.analyze_image(image, content_type)
        return parse_assessment(result.raw_json), result.latency_ms
