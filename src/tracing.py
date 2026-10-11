"""Tracing layer: turns every agent interaction into an indexed span.

A span records the text produced at a hop, its embedding, the provenance it
inherited, any PII found in it, and any tool calls made. This is the raw
material every detector works from.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import pii
from .backends.base import SearchBackend
from .embeddings import get_embedder


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


@dataclass
class Span:
    """One recorded agent interaction."""

    trace_id: str
    tenant_id: str
    session_id: str
    agent: str
    role: str
    phase: str
    text: str
    provenance: List[str]
    span_id: str = field(default_factory=lambda: new_id("span"))
    parent_span_id: Optional[str] = None
    input_text: str = ""
    output_text: str = ""
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    blocked: bool = False
    block_reason: str = ""

    def to_document(self, embedding: List[float]) -> Dict[str, Any]:
        matches = pii.detect(self.text)
        return {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "timestamp": _now(),
            "agent": self.agent,
            "role": self.role,
            "phase": self.phase,
            "tenant_id": self.tenant_id,
            "session_id": self.session_id,
            "text": self.text,
            "input_text": self.input_text,
            "output_text": self.output_text,
            "provenance": list(self.provenance),
            "tool_calls": self.tool_calls,
            "pii_types": sorted({m.type for m in matches}),
            "pii_values": [m.value for m in matches],
            "blocked": self.blocked,
            "block_reason": self.block_reason,
            "embedding": embedding,
        }


class Tracer:
    """Embeds span text and writes spans to the search backend."""

    def __init__(self, backend: SearchBackend):
        self.backend = backend
        self.embedder = get_embedder()

    def record(self, span: Span) -> Dict[str, Any]:
        embedding = self.embedder.embed(span.text or "")
        doc = span.to_document(embedding)
        self.backend.index_span(doc)
        return doc
