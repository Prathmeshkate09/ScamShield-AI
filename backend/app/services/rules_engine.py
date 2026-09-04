from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from app.schemas.analysis import RiskSignal, SignalCategory, SignalSeverity, SignalSource


RuleMatcher = Callable[[str], bool]


def _pattern(value: str) -> re.Pattern[str]:
    return re.compile(value, flags=re.IGNORECASE)


def _matches(pattern: re.Pattern[str]) -> RuleMatcher:
    return lambda text: pattern.search(text) is not None


def _matches_after_removing(
    positive: re.Pattern[str],
    suppressions: Sequence[re.Pattern[str]],
) -> RuleMatcher:
    def matcher(text: str) -> bool:
        candidate = text
        for suppression in suppressions:
            candidate = suppression.sub(" ", candidate)
        return positive.search(candidate) is not None

    return matcher


@dataclass(frozen=True)
class SecurityRule:
    code: str
    title: str
    category: SignalCategory
    severity: SignalSeverity
    raw_score: int
    contribution: int
    evidence: str
    matcher: RuleMatcher

    def evaluate(self, text: str) -> RiskSignal | None:
        if not self.matcher(text):
            return None
        return RiskSignal(
            code=self.code,
            title=self.title,
            category=self.category,
            severity=self.severity,
            raw_score=self.raw_score,
            contribution=self.contribution,
            confidence=1.0,
            source=SignalSource.RULE,
            evidence=self.evidence,
        )


_SAFE_CREDENTIAL_ADVISORY = _pattern(
    r"\b(?:never|do\s+not|don't)\s+(?:share|send|provide|enter|reveal|tell)\s+(?:anyone\s+)?(?:your\s+)?"
    r"(?:otp|one[- ]time password|pin|password|cvv|upi pin|security code|card number)\b"
)
_CREDENTIAL_REQUEST = _pattern(
    r"\b(?:share|send|provide|enter|reveal|tell|reply\s+with|confirm)\s+(?:us\s+)?(?:your\s+)?"
    r"(?:otp|one[- ]time password|pin|password|cvv|upi pin|security code|card number)\b"
    r"|\b(?:otp|one[- ]time password|pin|password|cvv|upi pin|security code|card number)\b"
    r".{0,45}\b(?:required|needed|send|share|provide|enter|confirm)\b"
)
_SAFE_PAYMENT_ADVISORY = _pattern(
    r"\b(?:never|do\s+not|don't)\s+(?:pay|send|transfer|deposit)\b.{0,45}"
    r"\b(?:money|funds|fee|payment|deposit|crypto|upi)\b"
)
_PAYMENT_PRESSURE = _pattern(
    r"\b(?:pay|send|transfer|deposit)\b.{0,55}\b(?:money|funds|fee|payment|deposit|crypto|upi)\b"
    r"|\b(?:processing|release|unlock|withdrawal|registration|recruitment)\s+fee\b"
)


DEFAULT_RULES: tuple[SecurityRule, ...] = (
    SecurityRule(
        code="URGENT_ACTION",
        title="Artificial urgency",
        category=SignalCategory.URGENCY,
        severity=SignalSeverity.HIGH,
        raw_score=75,
        contribution=10,
        evidence="The message pressures the recipient to act within an unusually short deadline.",
        matcher=_matches(
            _pattern(
                r"\b(?:act|respond|verify|complete|click|pay)\s+(?:now|immediately|urgently)\b"
                r"|\bwithin\s+(?:the\s+next\s+)?\d{1,3}\s+(?:minutes?|hours?)\b"
                r"|\b(?:last|final)\s+warning\b|\bexpires?\s+(?:today|soon)\b"
            )
        ),
    ),
    SecurityRule(
        code="ACCOUNT_THREAT",
        title="Account or service threat",
        category=SignalCategory.COERCION,
        severity=SignalSeverity.HIGH,
        raw_score=85,
        contribution=14,
        evidence="The message threatens account blocking, suspension, arrest, or another penalty to force action.",
        matcher=_matches(
            _pattern(
                r"\b(?:account|service|sim|card)\b.{0,45}\b(?:blocked|suspended|closed|disabled|deactivated)\b"
                r"|\b(?:blocked|suspended|closed|disabled|deactivated)\b.{0,45}\b(?:account|service|sim|card)\b"
                r"|\b(?:legal action|arrest|penalty)\b.{0,50}\b(?:unless|if you do not|if you don't)\b"
            )
        ),
    ),
    SecurityRule(
        code="CREDENTIAL_REQUEST",
        title="Sensitive credential request",
        category=SignalCategory.CREDENTIAL,
        severity=SignalSeverity.CRITICAL,
        raw_score=95,
        contribution=20,
        evidence="The message asks the recipient to disclose or enter an OTP, PIN, password, CVV, card number, or security code.",
        matcher=_matches_after_removing(_CREDENTIAL_REQUEST, (_SAFE_CREDENTIAL_ADVISORY,)),
    ),
    SecurityRule(
        code="PAYMENT_PRESSURE",
        title="Payment or transfer pressure",
        category=SignalCategory.FINANCIAL,
        severity=SignalSeverity.HIGH,
        raw_score=82,
        contribution=14,
        evidence="The message asks for money, a transfer, deposit, or advance fee as part of the requested action.",
        matcher=_matches_after_removing(_PAYMENT_PRESSURE, (_SAFE_PAYMENT_ADVISORY,)),
    ),
    SecurityRule(
        code="GUARANTEED_INVESTMENT_RETURN",
        title="Guaranteed investment return",
        category=SignalCategory.FINANCIAL,
        severity=SignalSeverity.CRITICAL,
        raw_score=92,
        contribution=20,
        evidence="The message promotes guaranteed, risk-free, or implausibly rapid investment profit.",
        matcher=_matches(
            _pattern(
                r"\bguaranteed\s+(?:returns?|profits?|income)\b|\brisk[- ]free\s+(?:returns?|profits?|investment)\b"
                r"|\bdouble\s+(?:your\s+)?(?:money|investment)\b|\b\d{2,4}%\s+(?:return|profit)\b"
            )
        ),
    ),
    SecurityRule(
        code="RECRUITMENT_FEE",
        title="Recruitment fee request",
        category=SignalCategory.FINANCIAL,
        severity=SignalSeverity.HIGH,
        raw_score=88,
        contribution=17,
        evidence="The message connects a job, interview, or offer to an advance recruitment or registration payment.",
        matcher=_matches(
            _pattern(
                r"\b(?:job|interview|employment|offer letter|recruitment)\b.{0,80}"
                r"\b(?:pay|fee|deposit|registration charge)\b"
                r"|\b(?:pay|fee|deposit|registration charge)\b.{0,80}"
                r"\b(?:job|interview|employment|offer letter|recruitment)\b"
            )
        ),
    ),
    SecurityRule(
        code="AUTHORITY_IMPERSONATION",
        title="Authority or organization impersonation",
        category=SignalCategory.IMPERSONATION,
        severity=SignalSeverity.MEDIUM,
        raw_score=65,
        contribution=8,
        evidence="The message invokes a bank, government body, police, delivery company, employer, or technical support while requesting account-related action.",
        matcher=_matches(
            _pattern(
                r"\b(?:sbi|hdfc|icici|axis|bank|government|police|tax department|income tax|courier|delivery|employer|technical support)\b"
                r".{0,100}\b(?:account|kyc|verify|payment|refund|blocked|suspended|click|login|fee)\b"
            )
        ),
    ),
    SecurityRule(
        code="SECRECY_REQUEST",
        title="Secrecy or isolation request",
        category=SignalCategory.SOCIAL_ENGINEERING,
        severity=SignalSeverity.HIGH,
        raw_score=78,
        contribution=12,
        evidence="The message discourages the recipient from verifying the request with other people or official support.",
        matcher=_matches(
            _pattern(
                r"\b(?:keep\s+(?:this|it)\s+secret|do\s+not\s+tell\s+anyone|don't\s+tell\s+anyone|"
                r"do\s+not\s+contact\s+(?:the\s+)?(?:bank|police|support))\b"
            )
        ),
    ),
    SecurityRule(
        code="REWARD_LURE",
        title="Unexpected reward lure",
        category=SignalCategory.SOCIAL_ENGINEERING,
        severity=SignalSeverity.MEDIUM,
        raw_score=58,
        contribution=7,
        evidence="The message uses an unexpected prize, reward, or refund to encourage immediate engagement.",
        matcher=_matches(
            _pattern(
                r"\b(?:you(?:'ve| have)?\s+won|claim\s+(?:your\s+)?(?:prize|reward)|unexpected\s+refund|"
                r"cash\s+prize|lottery\s+winner)\b"
            )
        ),
    ),
)


class RulesEngine:
    def __init__(self, rules: Sequence[SecurityRule] = DEFAULT_RULES) -> None:
        codes = [rule.code for rule in rules]
        if len(codes) != len(set(codes)):
            raise ValueError("security rule codes must be unique")
        self.rules = tuple(rules)

    def analyze(self, normalized_text: str) -> list[RiskSignal]:
        findings = [finding for rule in self.rules if (finding := rule.evaluate(normalized_text)) is not None]
        return sorted(findings, key=lambda signal: (-signal.raw_score, signal.code))
