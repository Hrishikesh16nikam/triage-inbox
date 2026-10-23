"""Redact personal identifiers before anything is stored, shown or sent to
a model.

Pattern-based redaction is a safety net, not a guarantee: it misses
identifiers spelled out in words ("five five five...") and unusual
formats. docs/THREAT_MODEL.md lists this as a residual risk.
"""

from __future__ import annotations

import re
from typing import Callable

_MONTHS = (r"(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|June?|July?|Aug(?:ust)?|"
           r"Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)")


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _card(match: re.Match) -> str | None:
    digits = re.sub(r"\D", "", match.group(0))
    return "[CARD]" if 13 <= len(digits) <= 19 and _luhn_ok(digits) else None


# Order matters: more specific patterns run first so, for example, a card
# number is not partly consumed by the phone pattern.
_RULES: list[tuple[str, re.Pattern, Callable[[re.Match], str | None] | None]] = [
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), None),
    ("ID", re.compile(r"\b(?:MRN|medical record(?: number)?|member id|patient id|policy(?: number)?)"
                      r"[\s:#-]*[A-Z0-9][A-Z0-9-]{4,}\b", re.IGNORECASE), None),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), None),
    ("CARD", re.compile(r"\b(?:\d[ -]?){12,18}\d\b"), _card),
    ("PHONE", re.compile(r"(?<![\w-])(?:\+?1[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}(?![\w-])"), None),
    ("DATE", re.compile(rf"\b(?:\d{{1,2}}[/-]\d{{1,2}}[/-](?:\d{{4}}|\d{{2}})|{_MONTHS}\.? \d{{1,2}}(?:st|nd|rd|th)?,? \d{{4}})\b",
                        re.IGNORECASE), None),
]


def redact(text: str) -> tuple[str, dict[str, int]]:
    """Return the redacted text and how many of each kind were removed."""
    counts: dict[str, int] = {}
    for label, pattern, check in _RULES:
        def repl(m: re.Match, label=label, check=check) -> str:
            replacement = check(m) if check else f"[{label}]"
            if replacement is None:
                return m.group(0)
            counts[label] = counts.get(label, 0) + 1
            return replacement
        text = pattern.sub(repl, text)
    return text, counts
