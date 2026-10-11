"""Cross-tenant leak-path reconstruction.

A leak is a PII value that surfaces in one tenant's span but originated in
another tenant's data. We find these by:

1.  Scanning the ``agent-traces`` index for spans that contain PII values.
2.  For each such span, following its ``provenance`` back to the originating
    user session, then resolving that session's tenant.
3.  Flagging any span whose PII traces back to a *different* tenant.

As a second, provenance-independent signal, we also flag any single PII value
that appears under more than one tenant.

The output is the reconstructed path: origin tenant/session -> shared retrieval
-> the response that leaked it.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .. import provenance
from ..backends.base import SearchBackend


@dataclass
class LeakFinding:
    pii_value: str
    pii_present_in_span: str
    exposed_to_tenant: str
    origin_tenant: str
    origin_session: str
    path: List[str] = field(default_factory=list)


class LeakPathReconstructor:
    def __init__(self, backend: SearchBackend):
        self.backend = backend

    def _session_tenant_map(self, spans: List[Dict]) -> Dict[str, str]:
        mapping: Dict[str, str] = {}
        for span in spans:
            sid = span.get("session_id")
            if sid and sid not in mapping:
                mapping[sid] = span.get("tenant_id", "?")
        return mapping

    def reconstruct(self) -> List[LeakFinding]:
        spans = self.backend.all_spans()
        session_tenant = self._session_tenant_map(spans)

        findings: List[LeakFinding] = []

        # Signal A: provenance points back to a different tenant's session.
        for span in spans:
            pii_values = span.get("pii_values") or []
            if not pii_values:
                continue
            exposed_tenant = span.get("tenant_id", "?")

            for tag in span.get("provenance", []):
                if provenance.kind_of(tag) != "user":
                    continue
                origin_session = tag.split(":", 1)[1]
                origin_tenant = session_tenant.get(origin_session, exposed_tenant)
                if origin_tenant != exposed_tenant:
                    for value in pii_values:
                        findings.append(
                            LeakFinding(
                                pii_value=value,
                                pii_present_in_span=span["span_id"],
                                exposed_to_tenant=exposed_tenant,
                                origin_tenant=origin_tenant,
                                origin_session=origin_session,
                                path=[
                                    f"{origin_tenant}/{origin_session} (origin)",
                                    "shared-retrieval-memory",
                                    f"{exposed_tenant}/{span.get('session_id')} (leaked here: {span['span_id']})",
                                ],
                            )
                        )

        # Signal B: same PII value observed under more than one tenant.
        value_tenants: Dict[str, Set[str]] = defaultdict(set)
        value_spans: Dict[str, List[Dict]] = defaultdict(list)
        for span in spans:
            for value in span.get("pii_values") or []:
                value_tenants[value].add(span.get("tenant_id", "?"))
                value_spans[value].append(span)

        already = {(f.pii_value, f.exposed_to_tenant) for f in findings}
        for value, tenants in value_tenants.items():
            if len(tenants) > 1:
                for span in value_spans[value]:
                    key = (value, span.get("tenant_id", "?"))
                    if key in already:
                        continue
                    already.add(key)
                    others = tenants - {span.get("tenant_id")}
                    findings.append(
                        LeakFinding(
                            pii_value=value,
                            pii_present_in_span=span["span_id"],
                            exposed_to_tenant=span.get("tenant_id", "?"),
                            origin_tenant=", ".join(sorted(others)),
                            origin_session="(multi-tenant value overlap)",
                            path=[
                                f"value seen under tenants: {', '.join(sorted(tenants))}",
                                f"leaked in span {span['span_id']}",
                            ],
                        )
                    )

        return findings

    @staticmethod
    def render(findings: List[LeakFinding]) -> str:
        if not findings:
            return "Leak-path reconstruction\n" + "=" * 32 + "\nNo cross-tenant leaks detected."
        lines = ["Leak-path reconstruction", "=" * 32]
        for f in findings:
            lines.append(
                f"LEAK: {f.pii_value!r} from tenant {f.origin_tenant} exposed to {f.exposed_to_tenant}"
            )
            lines.append("      path: " + "  ->  ".join(f.path))
        return "\n".join(lines)
