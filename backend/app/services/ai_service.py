from __future__ import annotations

import base64
import json
import re
import time
from dataclasses import dataclass
from typing import Protocol

from app.config import Settings
from app.core.errors import AppError, ProviderResponseError
from app.schemas.analysis import ScamAssessment


SYSTEM_PROMPT = """You are ScamShield AI, a cautious security assistant. Analyze user-provided messages, URL strings, voice transcripts, and screenshots for scam risk. Assess evidence such as urgency, threats, impersonation, financial requests, credential or OTP requests, suspicious URLs, social engineering, authority claims, emotional manipulation, and unusual instructions. Do not classify only by keywords. Explain the risk in clear user-facing language. Never provide instructions that would make a scam more effective. Return only the required JSON object."""


@dataclass(frozen=True)
class ProviderResult:
    raw_json: str
    latency_ms: int


class AIProvider(Protocol):
    name: str
    mode: str

    async def analyze_text(self, content: str, input_type: str, context: str | None = None) -> ProviderResult: ...

    async def analyze_image(self, content: bytes, content_type: str) -> ProviderResult: ...


def parse_assessment(raw_json: str) -> ScamAssessment:
    try:
        return ScamAssessment.model_validate_json(raw_json)
    except (ValueError, TypeError):
        match = re.search(r"\{.*\}", raw_json, flags=re.DOTALL)
        if match:
            try:
                return ScamAssessment.model_validate(json.loads(match.group(0)))
            except (ValueError, TypeError, json.JSONDecodeError):
                pass
    raise ProviderResponseError()


def build_prompt(content: str, input_type: str, context: str | None = None) -> str:
    sections = [f"Input type: {input_type}", f"Content to analyze:\n{content}"]
    if context:
        sections.append(f"Verified deterministic context:\n{context}")
    sections.append("Return risk_score, risk_level, scam_type, confidence, red_flags, explanation, and recommendation as JSON.")
    return "\n\n".join(sections)


class DemoProvider:
    name = "demo"
    mode = "demo"

    async def analyze_text(self, content: str, input_type: str, context: str | None = None) -> ProviderResult:
        started_at = time.perf_counter()
        lowered_content = content.lower()
        banking_terms = ("otp", "kyc", "account blocked", "account will be blocked", "bank", "suspend")
        investment_terms = ("guaranteed return", "double your money", "crypto", "investment", "profit")
        urgency_terms = ("immediately", "urgent", "minutes", "today", "limited time")

        if sum(term in lowered_content for term in banking_terms) >= 2:
            assessment = ScamAssessment(
                risk_score=96,
                risk_level="CRITICAL",
                scam_type="Banking / Phishing",
                confidence=0.96,
                red_flags=["Artificial urgency", "Account suspension threat", "Request for OTP or credentials", "Possible financial impersonation"],
                explanation="This message combines a threat of account disruption with pressure to complete KYC and share sensitive verification details. Legitimate banks do not ask for OTPs through an unsolicited message.",
                recommendation=["Do not click any link in the message", "Do not share your OTP, PIN, or password", "Contact the bank through its official app or website"],
            )
        elif sum(term in lowered_content for term in investment_terms) >= 2:
            assessment = ScamAssessment(
                risk_score=88,
                risk_level="CRITICAL",
                scam_type="Investment Scam",
                confidence=0.90,
                red_flags=["Promises unusually high returns", "Pressure to invest quickly", "Financial gain claim without verifiable details"],
                explanation="The message uses a guaranteed-profit claim and urgency to push a financial decision. Those patterns are common in investment scams and should be independently verified before any payment.",
                recommendation=["Do not transfer money or connect a wallet", "Verify the firm through an official regulator or website", "Discuss investment decisions with a trusted adviser"],
            )
        elif any(term in lowered_content for term in urgency_terms) and any(term in lowered_content for term in ("click", "pay", "verify", "login")):
            assessment = ScamAssessment(
                risk_score=65,
                risk_level="HIGH",
                scam_type="Social Engineering / Phishing",
                confidence=0.78,
                red_flags=["Urgent action request", "Unsolicited verification or payment prompt"],
                explanation="The message pressures you to act before you can verify the request. Treat links and payment prompts in unexpected messages with caution.",
                recommendation=["Pause before responding", "Use an official channel to verify the sender", "Avoid entering credentials after following message links"],
            )
        else:
            assessment = ScamAssessment(
                risk_score=8,
                risk_level="SAFE",
                scam_type="No Clear Scam Pattern",
                confidence=0.72,
                red_flags=[],
                explanation="This content does not show strong scam indicators in demo mode. A low score is not a guarantee of safety; verify unexpected requests independently.",
                recommendation=["Verify unexpected requests through a trusted channel", "Avoid sharing sensitive information unless you initiated the interaction"],
            )
        return ProviderResult(raw_json=assessment.model_dump_json(), latency_ms=round((time.perf_counter() - started_at) * 1000))

    async def analyze_image(self, content: bytes, content_type: str) -> ProviderResult:
        raise AppError("Screenshot analysis requires a configured OpenAI or Gemini provider.", 503, "vision_provider_unavailable")


class OpenAIProvider:
    name = "openai"
    mode = "live"

    def __init__(self, api_key: str, model: str) -> None:
        from openai import AsyncOpenAI

        self.client = AsyncOpenAI(api_key=api_key)
        self.model = model

    async def analyze_text(self, content: str, input_type: str, context: str | None = None) -> ProviderResult:
        started_at = time.perf_counter()
        response = await self.client.responses.create(
            model=self.model,
            instructions=SYSTEM_PROMPT,
            input=build_prompt(content, input_type, context),
            text={"format": {"type": "json_schema", "name": "scam_assessment", "strict": True, "schema": ScamAssessment.model_json_schema()}},
        )
        return ProviderResult(raw_json=response.output_text, latency_ms=round((time.perf_counter() - started_at) * 1000))

    async def analyze_image(self, content: bytes, content_type: str) -> ProviderResult:
        started_at = time.perf_counter()
        image_data = base64.b64encode(content).decode("ascii")
        response = await self.client.responses.create(
            model=self.model,
            instructions=SYSTEM_PROMPT,
            input=[
                {
                    "role": "user",
                    "content": [
                        {"type": "input_text", "text": build_prompt("Analyze this uploaded screenshot for scam indicators.", "image")},
                        {"type": "input_image", "image_url": f"data:{content_type};base64,{image_data}"},
                    ],
                }
            ],
            text={"format": {"type": "json_schema", "name": "scam_assessment", "strict": True, "schema": ScamAssessment.model_json_schema()}},
        )
        return ProviderResult(raw_json=response.output_text, latency_ms=round((time.perf_counter() - started_at) * 1000))


class GeminiProvider:
    name = "gemini"
    mode = "live"

    def __init__(self, api_key: str, model: str) -> None:
        from google import genai

        self.client = genai.Client(api_key=api_key)
        self.model = model

    async def analyze_text(self, content: str, input_type: str, context: str | None = None) -> ProviderResult:
        started_at = time.perf_counter()
        response = await self.client.aio.models.generate_content(
            model=self.model,
            contents=[SYSTEM_PROMPT, build_prompt(content, input_type, context)],
            config={"response_format": {"text": {"mime_type": "application/json", "schema": ScamAssessment.model_json_schema()}}},
        )
        return ProviderResult(raw_json=response.text, latency_ms=round((time.perf_counter() - started_at) * 1000))

    async def analyze_image(self, content: bytes, content_type: str) -> ProviderResult:
        from google.genai import types

        started_at = time.perf_counter()
        response = await self.client.aio.models.generate_content(
            model=self.model,
            contents=[
                SYSTEM_PROMPT,
                build_prompt("Analyze this uploaded screenshot for scam indicators.", "image"),
                types.Part.from_bytes(data=content, mime_type=content_type),
            ],
            config={"response_format": {"text": {"mime_type": "application/json", "schema": ScamAssessment.model_json_schema()}}},
        )
        return ProviderResult(raw_json=response.text, latency_ms=round((time.perf_counter() - started_at) * 1000))


def select_provider(settings: Settings) -> AIProvider:
    if settings.ai_provider == "demo":
        return DemoProvider()
    if settings.ai_provider == "openai":
        if not settings.openai_api_key:
            raise AppError("OPENAI_API_KEY is required when AI_PROVIDER=openai.", 503, "provider_not_configured")
        return OpenAIProvider(settings.openai_api_key, settings.openai_model)
    if settings.ai_provider == "gemini":
        if not settings.gemini_api_key:
            raise AppError("GEMINI_API_KEY is required when AI_PROVIDER=gemini.", 503, "provider_not_configured")
        return GeminiProvider(settings.gemini_api_key, settings.gemini_model)
    if settings.openai_api_key:
        return OpenAIProvider(settings.openai_api_key, settings.openai_model)
    if settings.gemini_api_key:
        return GeminiProvider(settings.gemini_api_key, settings.gemini_model)
    return DemoProvider()
