from __future__ import annotations

import re
import unicodedata


_ZERO_WIDTH_CHARACTERS = re.compile(r"[\u200b-\u200d\ufeff]")
_WHITESPACE = re.compile(r"\s+")


def normalize_security_text(value: str) -> str:
    """Normalize text for deterministic matching without mutating stored input."""

    normalized = unicodedata.normalize("NFKC", value)
    normalized = _ZERO_WIDTH_CHARACTERS.sub("", normalized)
    normalized = _WHITESPACE.sub(" ", normalized)
    return normalized.strip().casefold()
