"""PII pattern detection.

Lightweight, dependency-free detectors for the PII types that commonly leak in
customer-support workloads. In production you would layer this with a managed
service (e.g. Amazon Comprehend PII detection or Bedrock Guardrails), but
pattern detection is fast, explainable, and easy to run inside the tracing
path.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Dict, List


@dataclass(frozen=True)
class PIIMatch:
    type: str
    value: str
    start: int
    end: int

    def redacted(self) -> str:
        return f"[{self.type}]"

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


# Order matters: more specific patterns first.
_PATTERNS = [
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    (
        "CREDIT_CARD",
        re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    ),
    (
        "PHONE",
        re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    ),
    ("IP_ADDRESS", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("CUSTOMER_ID", re.compile(r"\bCUST-[0-9]{6,}\b")),
]


def _luhn_ok(number: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", number)]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def detect(text: str) -> List[PIIMatch]:
    """Return all PII matches in ``text`` without double-counting spans."""
    matches: List[PIIMatch] = []
    claimed: List[range] = []

    for pii_type, pattern in _PATTERNS:
        for m in pattern.finditer(text):
            span = range(m.start(), m.end())
            if any(span.start < c.stop and c.start < span.stop for c in claimed):
                continue  # overlaps an already-claimed span
            value = m.group(0)
            if pii_type == "CREDIT_CARD" and not _luhn_ok(value):
                continue
            if pii_type == "IP_ADDRESS" and any(
                int(o) > 255 for o in value.split(".")
            ):
                continue
            matches.append(PIIMatch(pii_type, value, m.start(), m.end()))
            claimed.append(span)

    return sorted(matches, key=lambda x: x.start)


def redact(text: str) -> str:
    """Replace all detected PII in ``text`` with type placeholders."""
    result = text
    for match in sorted(detect(text), key=lambda x: x.start, reverse=True):
        result = result[: match.start] + match.redacted() + result[match.end :]
    return result


def values(text: str) -> List[str]:
    return [m.value for m in detect(text)]
