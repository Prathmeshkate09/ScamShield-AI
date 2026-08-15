from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit


@dataclass(frozen=True)
class UrlSignals:
    red_flags: list[str]
    risk_floor: int
    summary: str


SUSPICIOUS_TLDS = {"zip", "top", "click", "xyz", "rest", "live", "gq", "work", "country"}
SENSITIVE_QUERY_TERMS = {"otp", "password", "pin", "cvv", "token", "login", "verify"}
BRAND_NAMES = {"paypal", "google", "microsoft", "amazon", "netflix", "hdfc", "sbi", "icici", "axis"}


def inspect_url(url: str) -> UrlSignals:
    parsed = urlsplit(url)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    red_flags: list[str] = []
    risk_floor = 0

    if parsed.scheme != "https":
        red_flags.append("Uses HTTP instead of encrypted HTTPS")
        risk_floor = max(risk_floor, 25)

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        red_flags.append("Uses an IP address instead of a recognizable domain")
        risk_floor = max(risk_floor, 60)

    if hostname.startswith("xn--") or ".xn--" in hostname:
        red_flags.append("Uses punycode that can visually imitate a trusted domain")
        risk_floor = max(risk_floor, 55)

    labels = hostname.split(".")
    if len(labels) >= 5:
        red_flags.append("Uses an unusually deep subdomain chain")
        risk_floor = max(risk_floor, 35)

    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        red_flags.append(f"Uses a high-risk .{tld} top-level domain")
        risk_floor = max(risk_floor, 35)

    if len(url) > 180:
        red_flags.append("Has an unusually long URL")
        risk_floor = max(risk_floor, 20)

    query_names = {name.lower() for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}
    if query_names & SENSITIVE_QUERY_TERMS:
        red_flags.append("Includes query fields associated with sensitive credentials")
        risk_floor = max(risk_floor, 40)

    compact_hostname = re.sub(r"[^a-z]", "", hostname)
    for brand in BRAND_NAMES:
        if brand in compact_hostname and not hostname.endswith(f"{brand}.com"):
            red_flags.append("Contains a brand-like name outside the brand's primary domain")
            risk_floor = max(risk_floor, 55)
            break

    if not red_flags:
        summary = "The URL string has no strong structural warning signs. It was not opened or fetched."
    else:
        summary = "The URL was not opened or fetched. Structural warning signs were detected in the URL string."
    return UrlSignals(red_flags=red_flags, risk_floor=risk_floor, summary=summary)
