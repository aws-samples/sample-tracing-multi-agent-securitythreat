"""Naive instruction understanding used by the simulated agents.

Real LLM agents infer intent from natural language. To keep the demo
deterministic (and to make the vulnerability crisp), our simulated agents parse
text for imperative instructions and act on them. Crucially — and this is the
whole point — they do not distinguish an instruction written by the user from
one hidden inside an ingested document. That is exactly how prompt injection
hijacks a pipeline.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


@dataclass
class Instruction:
    intent: str                 # export_customers | send_email | refund | none
    raw: str
    target_email: Optional[str] = None
    customer_id: Optional[str] = None
    amount: Optional[float] = None


def _sentences(text: str) -> List[str]:
    parts = re.split(r"(?<=[.!?\n])\s+", text)
    return [p.strip() for p in parts if p.strip()]


def extract(text: str) -> List[Instruction]:
    """Extract actionable instructions from arbitrary text."""
    instructions: List[Instruction] = []
    for sentence in _sentences(text):
        low = sentence.lower()

        if re.search(r"\b(export|dump|extract|download)\b.*\b(customer|client|user)\b", low):
            instructions.append(Instruction("export_customers", sentence))
            # An export is frequently paired with an exfiltration channel.
            email = _EMAIL_RE.search(sentence)
            if email:
                instructions.append(
                    Instruction("send_email", sentence, target_email=email.group(0))
                )
            continue

        if re.search(r"\b(email|send|forward|exfiltrate|leak)\b", low):
            email = _EMAIL_RE.search(sentence)
            if email:
                instructions.append(
                    Instruction("send_email", sentence, target_email=email.group(0))
                )
                continue

        if "refund" in low:
            cust = re.search(r"CUST-\d+", sentence)
            amount = re.search(r"\$?\s*(\d+(?:\.\d{1,2})?)", sentence)
            instructions.append(
                Instruction(
                    "refund",
                    sentence,
                    customer_id=cust.group(0) if cust else None,
                    amount=float(amount.group(1)) if amount else None,
                )
            )

    return instructions
