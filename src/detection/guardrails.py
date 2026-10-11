"""Guardrails that stop the attacks before they reach production.

Three layers, each mapping to a threat the tracing layer revealed:

1.  ``sanitize_document``  - input guardrail: neutralize injection markers in
    untrusted documents before an agent ever reads them.
2.  ``check_tool_call``    - provenance-based tool access control: refuse
    dangerous tool calls whose lineage includes untrusted content. This is the
    single most effective control against injection propagation.
3.  ``check_response``     - output guardrail: block/redact a response that
    carries PII whose provenance belongs to a different tenant.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, List

from .. import pii, provenance
from ..agents.instructions import Instruction

# Tools that can move data out of the system. Only these need lineage checks.
DANGEROUS_INTENTS = {"export_customers", "send_email"}

_INJECTION_MARKERS = [
    re.compile(r"ignore (all )?(previous|prior) instructions", re.I),
    re.compile(r"system (update|override|prompt)", re.I),
    re.compile(r"\b(export|dump|exfiltrate|leak)\b.*\b(customer|client|user)\b", re.I),
    re.compile(r"\bemail\b.*@", re.I),
]


@dataclass
class Verdict:
    allowed: bool
    reason: str = ""
    sanitized_text: str = ""


class Guardrail:
    def __init__(self, block_dangerous_from_untrusted: bool = True):
        self.block_dangerous_from_untrusted = block_dangerous_from_untrusted

    # 1) Input guardrail --------------------------------------------------
    def sanitize_document(self, document: Dict[str, str]) -> Dict[str, str]:
        cleaned = dict(document)
        body = document.get("body", "")
        sentences = re.split(r"(?<=[.!?\n])\s+", body)
        kept: List[str] = []
        for sentence in sentences:
            if any(marker.search(sentence) for marker in _INJECTION_MARKERS):
                kept.append("[removed: suspected injected instruction]")
            else:
                kept.append(sentence)
        cleaned["body"] = " ".join(kept)
        return cleaned

    # 2) Tool-call guardrail (provenance-based access control) ------------
    def check_tool_call(self, instruction: Instruction, prov: Iterable[str]) -> Verdict:
        prov = list(prov)
        if (
            self.block_dangerous_from_untrusted
            and instruction.intent in DANGEROUS_INTENTS
            and provenance.has_untrusted(prov)
        ):
            tainted = ", ".join(provenance.untrusted_tags(prov))
            return Verdict(
                allowed=False,
                reason=f"dangerous action '{instruction.intent}' derived from untrusted source(s): {tainted}",
            )
        return Verdict(allowed=True)

    # 3) Output guardrail --------------------------------------------------
    def check_response(self, text: str, tenant_id: str, prov: Iterable[str]) -> Verdict:
        found = pii.detect(text)
        if not found:
            return Verdict(allowed=True, sanitized_text=text)

        # A response that contains PII and inherited provenance from more than
        # one user session is mixing data across conversations (and, in a
        # multi-tenant deployment, across tenants). Redact before responding.
        user_sessions = {t for t in prov if provenance.kind_of(t) == "user"}
        if len(user_sessions) > 1:
            return Verdict(
                allowed=False,
                reason="response carried PII with cross-session provenance; redacted",
                sanitized_text=pii.redact(text),
            )
        return Verdict(allowed=True, sanitized_text=text)
