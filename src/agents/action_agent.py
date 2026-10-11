"""Action agent: the one with tool access.

It executes the plan from the reasoning agent by calling tools. This is the
agent an attacker ultimately wants to control, because it can query the CRM,
export data, and send messages. It inherits the plan's provenance, so any tool
call it makes carries the lineage of whatever caused it — including an untrusted
document.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..tracing import Span, Tracer
from ..tools import ToolRegistry
from .instructions import Instruction


class ActionAgent:
    name = "action-agent"
    role = "act"

    def __init__(self, tracer: Tracer, tools: ToolRegistry):
        self.tracer = tracer
        self.tools = tools

    def act(
        self,
        plan_span: Span,
        instructions_: List[Instruction],
        *,
        trace_id: str,
        tenant_id: str,
        session_id: str,
        guardrail=None,
    ) -> Span:
        tool_calls: List[Dict[str, Any]] = []
        blocked_reasons: List[str] = []

        for ins in instructions_:
            # Optional guardrail veto (see detection/guardrails.py).
            if guardrail is not None:
                verdict = guardrail.check_tool_call(ins, plan_span.provenance)
                if not verdict.allowed:
                    blocked_reasons.append(verdict.reason)
                    tool_calls.append(
                        {"name": self._tool_for(ins), "args": {}, "result": f"BLOCKED: {verdict.reason}", "blocked": True}
                    )
                    continue

            tool_calls.append(self._execute(ins, tenant_id))

        summary = "; ".join(
            f"{c['name']}->{c['result']}" for c in tool_calls
        ) or "no actions taken"

        span = Span(
            trace_id=trace_id,
            tenant_id=tenant_id,
            session_id=session_id,
            agent=self.name,
            role=self.role,
            phase="act",
            text=summary,
            input_text=plan_span.text,
            output_text=summary,
            provenance=list(plan_span.provenance),
            parent_span_id=plan_span.span_id,
            tool_calls=tool_calls,
            blocked=bool(blocked_reasons),
            block_reason="; ".join(blocked_reasons),
        )
        self.tracer.record(span)
        return span

    # ------------------------------------------------------------------ utils
    @staticmethod
    def _tool_for(ins: Instruction) -> str:
        return {
            "export_customers": "export_customer_list",
            "send_email": "send_email",
            "refund": "issue_refund",
        }.get(ins.intent, "noop")

    def _execute(self, ins: Instruction, tenant_id: str) -> Dict[str, Any]:
        if ins.intent == "export_customers":
            return self.tools.export_customer_list(tenant_id)
        if ins.intent == "send_email" and ins.target_email:
            return self.tools.send_email(ins.target_email, "requested data attached")
        if ins.intent == "refund":
            return self.tools.issue_refund(
                tenant_id, ins.customer_id or "CUST-000000", ins.amount or 0.0
            )
        return {"name": "noop", "args": {}, "result": "no-op"}
