from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RiskPolicy:
    """Versioned, centralized limits for deterministic risk aggregation."""

    version: str = "v1"
    semantic_cap: int = 35
    rules_cap: int = 30
    url_cap: int = 25
    corroboration_cap: int = 10
    safe_max: int = 19
    low_max: int = 39
    medium_max: int = 59
    high_max: int = 79

    def __post_init__(self) -> None:
        caps = (self.semantic_cap, self.rules_cap, self.url_cap, self.corroboration_cap)
        if any(cap < 0 for cap in caps):
            raise ValueError("risk contribution caps cannot be negative")
        contribution_total = sum(caps)
        if contribution_total != 100:
            raise ValueError("risk contribution caps must total 100")
        thresholds = (self.safe_max, self.low_max, self.medium_max, self.high_max)
        if (
            self.safe_max < 0
            or self.high_max >= 100
            or any(left >= right for left, right in zip(thresholds, thresholds[1:]))
        ):
            raise ValueError("risk thresholds must be ordered within the 0-100 range")
        if not self.version.strip():
            raise ValueError("risk policy version cannot be empty")

    def level_for_score(self, score: int) -> str:
        if not 0 <= score <= 100:
            raise ValueError("risk score must be between 0 and 100")
        if score <= self.safe_max:
            return "SAFE"
        if score <= self.low_max:
            return "LOW"
        if score <= self.medium_max:
            return "MEDIUM"
        if score <= self.high_max:
            return "HIGH"
        return "CRITICAL"


DEFAULT_RISK_POLICY = RiskPolicy()
