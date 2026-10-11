"""Reasoning agent: combines the user's request with ingested context and
produces a plan.

It inherits provenance from every input it reads. Because it does not separate
trusted user intent from untrusted document content, an instruction hidden in
the ingested document becomes part of the plan it hands to the action agent.
"""
from __future__ import annotations

from typing import List, Optional

from .. import provenance
from ..tracing import Span, Tracer
from . import instructions


class ReasoningAgent:
    name = "reasoning-agent"
    role = "reason"

    def __init__(self, tracer: Tracer):
        self.tracer = tracer

    def plan(
        self,
        user_request: str,
        ingested: Span,
        *,
        trace_id: str,
        tenant_id: str,
        session_id: str,
        extra_context: Optional[str] = None,
    ) -> Span:
        # The agent "thinks" over user request + ingested content + any context.
        combined = "\n".join(filter(None, [user_request, ingested.text, extra_context]))
        found = instructions.extract(combined)

        plan_lines: List[str] = ["PLAN:"]
        for ins in found:
            plan_lines.append(f"- {ins.intent}: {ins.raw}")
        if len(plan_lines) == 1:
            plan_lines.append("- respond to customer with support answer")
        plan_text = "\n".join(plan_lines)

        merged_provenance = provenance.merge(
            [provenance.tag("user", session_id)],
            ingested.provenance,
        )

        span = Span(
            trace_id=trace_id,
            tenant_id=tenant_id,
            session_id=session_id,
            agent=self.name,
            role=self.role,
            phase="reason",
            text=plan_text,
            input_text=combined,
            output_text=plan_text,
            provenance=merged_provenance,
            parent_span_id=ingested.span_id,
        )
        self.tracer.record(span)
        span_instructions = found  # attach for the pipeline to consume
        setattr(span, "instructions", span_instructions)
        return span
