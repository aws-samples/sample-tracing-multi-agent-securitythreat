"""Scenario 2: cross-tenant PII leak through a shared retrieval memory.

Tenant A shares PII in a support chat. The retrieval memory is not partitioned
by tenant, so when tenant B asks a similar question the pipeline retrieves
tenant A's content and leaks it into tenant B's response. We reconstruct the
leak path from the OpenSearch traces, then enable guardrails + tenant
partitioning to stop it.

    python -m scenarios.scenario_leak
"""
from __future__ import annotations

from src.backends import get_backend
from src.detection import Guardrail, LeakPathReconstructor
from src.pipeline import Pipeline, SharedMemory

TENANT_A_MSG = (
    "I need help with my billing refund. My SSN is 000-12-3456 and my email is "
    "dana.ruiz@example.com."
)
TENANT_B_MSG = "I need help with my billing refund, can you look into it?"


def _rule(title: str) -> None:
    print("\n" + "#" * 70)
    print(f"# {title}")
    print("#" * 70)


def run_leaky() -> None:
    _rule("1. Shared retrieval memory NOT partitioned by tenant (the bug)")
    backend = get_backend()
    backend.ensure_index()
    memory = SharedMemory(partition_by_tenant=False)
    pipeline = Pipeline(backend, guardrail=None, shared_memory=memory)

    # Tenant A talks to support and shares PII (stored in shared memory).
    pipeline.handle_conversation(TENANT_A_MSG, tenant_id="tenant-a", session_id="session-a1")

    # Tenant B asks a similar question later.
    span = pipeline.handle_conversation(TENANT_B_MSG, tenant_id="tenant-b", session_id="session-b1")

    print("\nResponse returned to tenant-b:")
    print(f"  {span.text!r}")

    _rule("2. Reconstruct the leak path via OpenSearch")
    reconstructor = LeakPathReconstructor(backend)
    findings = reconstructor.reconstruct()
    print("\n" + reconstructor.render(findings))


def run_fixed() -> None:
    _rule("3. Guardrails + tenant partitioning enabled")
    backend = get_backend()
    backend.ensure_index()
    memory = SharedMemory(partition_by_tenant=True)  # the fix
    guardrail = Guardrail()
    pipeline = Pipeline(backend, guardrail=guardrail, shared_memory=memory)

    pipeline.handle_conversation(TENANT_A_MSG, tenant_id="tenant-a", session_id="session-a1")
    span = pipeline.handle_conversation(TENANT_B_MSG, tenant_id="tenant-b", session_id="session-b1")

    print("\nResponse returned to tenant-b:")
    print(f"  {span.text!r}")

    reconstructor = LeakPathReconstructor(backend)
    findings = reconstructor.reconstruct()
    print("\n" + reconstructor.render(findings))


if __name__ == "__main__":
    run_leaky()
    run_fixed()
