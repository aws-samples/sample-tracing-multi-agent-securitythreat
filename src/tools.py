"""Simulated tools available to the action agent.

These stand in for the real capabilities a support agent might have: querying a
CRM, exporting data, and sending messages. Each records what it did so the demo
can show impact. ``export_customer_list`` and ``send_email`` are the
"dangerous" tools an attacker wants to reach.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


# A tiny per-tenant "CRM". Note tenant-a holds sensitive PII.
_CRM: Dict[str, List[Dict[str, str]]] = {
    "tenant-a": [
        {"customer_id": "CUST-100001", "name": "Dana Ruiz", "email": "dana.ruiz@example.com", "ssn": "000-12-3456"},
        {"customer_id": "CUST-100002", "name": "Sam Osei", "email": "sam.osei@example.com", "ssn": "000-45-6789"},
    ],
    "tenant-b": [
        {"customer_id": "CUST-200001", "name": "Lee Park", "email": "lee.park@example.net", "ssn": "000-78-9012"},
    ],
}


@dataclass
class ToolRegistry:
    """Records every tool invocation for tracing and impact reporting."""

    invocations: List[Dict[str, object]] = field(default_factory=list)
    sent_messages: List[Dict[str, str]] = field(default_factory=list)
    exported_records: List[Dict[str, str]] = field(default_factory=list)

    def _record(self, name: str, args: Dict[str, object], result: str) -> Dict[str, object]:
        entry = {"name": name, "args": args, "result": result}
        self.invocations.append(entry)
        return entry

    # ---- benign tools -----------------------------------------------------
    def crm_lookup(self, tenant_id: str, customer_id: str) -> Dict[str, object]:
        record = next(
            (r for r in _CRM.get(tenant_id, []) if r["customer_id"] == customer_id),
            None,
        )
        return self._record("crm_lookup", {"tenant_id": tenant_id, "customer_id": customer_id}, str(record))

    def issue_refund(self, tenant_id: str, customer_id: str, amount: float) -> Dict[str, object]:
        return self._record(
            "issue_refund",
            {"tenant_id": tenant_id, "customer_id": customer_id, "amount": amount},
            f"refund of ${amount:.2f} issued to {customer_id}",
        )

    # ---- dangerous tools --------------------------------------------------
    def export_customer_list(self, tenant_id: str) -> Dict[str, object]:
        records = list(_CRM.get(tenant_id, []))
        self.exported_records.extend(records)
        return self._record(
            "export_customer_list",
            {"tenant_id": tenant_id},
            f"exported {len(records)} customer records",
        )

    def send_email(self, to: str, body: str) -> Dict[str, object]:
        self.sent_messages.append({"to": to, "body": body})
        return self._record("send_email", {"to": to, "body": body}, f"email sent to {to}")
