"""Ingestion agent: reads an external, untrusted document and normalizes it.

This is the entry point for attacker-controlled content (support tickets,
emails, web pages). It tags everything it emits with ``document:<id>``
provenance so downstream lineage is preserved.
"""
from __future__ import annotations

from typing import Dict

from .. import provenance
from ..tracing import Span, Tracer


class IngestionAgent:
    name = "ingestion-agent"
    role = "ingest"

    def __init__(self, tracer: Tracer):
        self.tracer = tracer

    def ingest(
        self,
        document: Dict[str, str],
        *,
        trace_id: str,
        tenant_id: str,
        session_id: str,
    ) -> Span:
        doc_id = document["id"]
        # A real agent would OCR/parse/clean. We concatenate the fields — and
        # in doing so we carry any hidden instructions straight through.
        content = f"{document.get('subject', '')}\n{document.get('body', '')}".strip()

        span = Span(
            trace_id=trace_id,
            tenant_id=tenant_id,
            session_id=session_id,
            agent=self.name,
            role=self.role,
            phase="ingest",
            text=content,
            input_text=content,
            output_text=content,
            provenance=[provenance.tag("document", doc_id)],
        )
        self.tracer.record(span)
        return span
