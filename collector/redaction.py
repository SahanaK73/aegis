"""Sensitive-data detection and redaction.

Used in two places:
  1. On raw local text, to count and mask sensitive items (raw text itself never leaves).
  2. As a final scan over the serialized outbound payload (fail closed).

Only category names and counts are ever reported. Matched values are never logged.
"""

from __future__ import annotations

import re
from typing import Callable, Optional

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_PHONE = re.compile(r"(?<![\w.])(?:\+91[-\s]?|91[-\s]?|0)?[6-9]\d{9}(?!\w)")
_INTL_PHONE = re.compile(r"(?<![\w.])\+\d{1,3}[-\s]?\d{6,12}(?!\w)")
_CARD = re.compile(r"(?<![\d-])(?:\d[ -]?){13,19}(?!\d)")


def _luhn_ok(candidate: str) -> bool:
    digits = re.sub(r"\D", "", candidate)
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# (category, compiled pattern, optional validator on the matched text)
PATTERNS: list[tuple[str, "re.Pattern[str]", Optional[Callable[[str], bool]]]] = [
    ("api_key", re.compile(r"(?i)\bapi[_-]?key\s*[=:]\s*\S+"), None),
    ("api_key", re.compile(r"(?i)\b(?:sk|pk|rk)[-_](?:live|test)[-_][A-Za-z0-9]{8,}\b"), None),
    ("api_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), None),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), None),
    ("token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"), None),
    (
        "token",
        re.compile(r"(?i)\b(?:access[_-]?token|auth[_-]?token|client[_-]?secret|token|secret)\s*[=:]\s*\S+"),
        None,
    ),
    ("password", re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[=:]\s*\S+"), None),
    ("email", _EMAIL, None),
    ("phone", _PHONE, None),
    ("phone", _INTL_PHONE, None),
    ("ip_address", _IPV4, None),
    ("card_number", _CARD, _luhn_ok),
]


def find_sensitive(text: str) -> dict[str, int]:
    """Return {category: count} for sensitive items found. Never returns the values."""
    found: dict[str, int] = {}
    for category, pattern, validator in PATTERNS:
        for match in pattern.finditer(text):
            if validator is not None and not validator(match.group(0)):
                continue
            found[category] = found.get(category, 0) + 1
    return found


def redact(text: str) -> tuple[str, dict[str, int]]:
    """Mask sensitive items. Returns (masked_text, {category: count})."""
    counts: dict[str, int] = {}
    masked = text
    for category, pattern, validator in PATTERNS:

        def _sub(match: "re.Match[str]", category: str = category, validator=validator) -> str:
            if validator is not None and not validator(match.group(0)):
                return match.group(0)
            counts[category] = counts.get(category, 0) + 1
            return f"[REDACTED:{category}]"

        masked = pattern.sub(_sub, masked)
    return masked, counts
