from __future__ import annotations

import pytest

from app.services.risk_policy import DEFAULT_RISK_POLICY
from app.services.rules_engine import RulesEngine, SecurityRule
from app.services.signal_extractor import SignalExtractor
from app.services.text_normalizer import normalize_security_text
from app.schemas.analysis import SignalCategory, SignalSeverity


def _codes(text: str) -> set[str]:
    return {signal.code for signal in SignalExtractor().extract_text(text).signals}


def test_normalizer_handles_unicode_whitespace_and_zero_width_text() -> None:
    assert normalize_security_text("  ACT\u200b  Immediately\nNow  ") == "act immediately now"


def test_safe_delivery_and_security_advice_avoid_credential_false_positive() -> None:
    signals = SignalExtractor().extract_text(
        "Your parcel will arrive tomorrow. Never share your OTP or password with anyone."
    ).signals

    assert signals == []


def test_credential_request_and_urgency_create_separate_evidence() -> None:
    codes = _codes("Act immediately and send your OTP to prevent your account from being blocked.")

    assert {"URGENT_ACTION", "CREDENTIAL_REQUEST", "ACCOUNT_THREAT"} <= codes


def test_investment_and_job_scam_concepts_are_detected() -> None:
    assert "GUARANTEED_INVESTMENT_RETURN" in _codes("Double your money with guaranteed returns today.")
    assert "RECRUITMENT_FEE" in _codes("Pay a registration fee before we release your job offer letter.")


def test_payment_advice_is_not_treated_as_payment_pressure() -> None:
    assert "PAYMENT_PRESSURE" not in _codes("Do not transfer money or pay a processing fee to unknown callers.")


def test_repeated_terms_create_one_signal_and_respect_the_rule_cap() -> None:
    extraction = SignalExtractor().extract_text(
        "Urgent urgent urgent. Act immediately. Send your OTP. Your bank account will be blocked. "
        "Pay a processing fee and keep this secret."
    )

    assert len([signal for signal in extraction.signals if signal.code == "URGENT_ACTION"]) == 1
    assert sum(signal.contribution for signal in extraction.signals) == DEFAULT_RISK_POLICY.rules_cap


def test_extraction_is_deterministic() -> None:
    extractor = SignalExtractor()
    text = "Your SBI account will be suspended. Verify immediately and provide your security code."

    assert extractor.extract_text(text) == extractor.extract_text(text)


def test_duplicate_rule_codes_are_rejected() -> None:
    rule = SecurityRule(
        code="DUPLICATE",
        title="Duplicate test",
        category=SignalCategory.URGENCY,
        severity=SignalSeverity.LOW,
        raw_score=10,
        contribution=1,
        evidence="Test-only evidence.",
        matcher=lambda _: True,
    )

    with pytest.raises(ValueError, match="must be unique"):
        RulesEngine((rule, rule))
