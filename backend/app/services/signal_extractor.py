from __future__ import annotations

from dataclasses import dataclass

from app.schemas.analysis import RiskSignal
from app.services.risk_policy import DEFAULT_RISK_POLICY, RiskPolicy
from app.services.rules_engine import RulesEngine
from app.services.text_normalizer import normalize_security_text


@dataclass(frozen=True)
class ExtractedTextSignals:
    normalized_text: str
    signals: list[RiskSignal]


class SignalExtractor:
    def __init__(self, rules_engine: RulesEngine | None = None, policy: RiskPolicy = DEFAULT_RISK_POLICY) -> None:
        self.rules_engine = rules_engine or RulesEngine()
        self.policy = policy

    def extract_text(self, text: str) -> ExtractedTextSignals:
        normalized_text = normalize_security_text(text)
        signals = self._cap_contributions(self.rules_engine.analyze(normalized_text))
        return ExtractedTextSignals(normalized_text=normalized_text, signals=signals)

    def _cap_contributions(self, signals: list[RiskSignal]) -> list[RiskSignal]:
        remaining = self.policy.rules_cap
        capped: list[RiskSignal] = []
        for signal in signals:
            contribution = min(signal.contribution, remaining)
            capped.append(signal.model_copy(update={"contribution": contribution}))
            remaining -= contribution
        return capped
