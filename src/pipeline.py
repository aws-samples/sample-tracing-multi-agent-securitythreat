"""Wires the multi-agent pipeline and records every hop to OpenSearch.

Two entry points:

* ``handle_ticket``      - ingest -> reason -> act. Used for the prompt
                           injection scenario.
* ``handle_conversation``- a chat turn that reads/writes a shared retrieval
                           memory. Used for the cross-tenant leak scenario,
                           where the memory is (buggily) not partitioned by
                           tenant.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import pii, provenance
from .agents import ActionAgent, IngestionAgent, ReasoningAgent
from .backends.base import SearchBackend
from .embeddings import cosine_similarity, get_embedder
from .tools import ToolRegistry
from .tracing import Span, Tracer, new_id


@dataclass
class MemoryItem:
    text: str
    tenant_id: str
    session_id: str
    embedding: List[float]
    provenance: List[str]


@dataclass
class SharedMemory:
    """A retrieval store shared across sessions.

    The bug: it is NOT partitioned by tenant, so a similarity search for one
    tenant can surface another tenant's content. This is the seed of the
    cross-tenant leak.
    """

    partition_by_tenant: bool = False
    _items: List[MemoryItem] = field(default_factory=list)

    def add(self, item: MemoryItem) -> None:
        self._items.append(item)

    def retrieve(self, query_embedding: List[float], tenant_id: str, k: int = 1) -> List[MemoryItem]:
        candidates = self._items
        if self.partition_by_tenant:  # the fix
            candidates = [i for i in self._items if i.tenant_id == tenant_id]
        scored = sorted(
            candidates,
            key=lambda i: cosine_similarity(query_embedding, i.embedding),
            reverse=True,
        )
        return scored[:k]


class Pipeline:
    def __init__(self, backend: SearchBackend, guardrail=None, shared_memory: Optional[SharedMemory] = None):
        self.backend = backend
        self.tracer = Tracer(backend)
        self.tools = ToolRegistry()
        self.guardrail = guardrail
        self.memory = shared_memory or SharedMemory()
        self.embedder = get_embedder()

        self.ingestion = IngestionAgent(self.tracer)
        self.reasoning = ReasoningAgent(self.tracer)
        self.action = ActionAgent(self.tracer, self.tools)

    # ----------------------------------------------- injection scenario path
    def handle_ticket(
        self,
        document: Dict[str, str],
        user_request: str,
        *,
        tenant_id: str,
        session_id: Optional[str] = None,
    ) -> Dict[str, Span]:
        trace_id = new_id("trace")
        session_id = session_id or new_id("session")

        # Optional input guardrail on the untrusted document.
        if self.guardrail is not None:
            document = self.guardrail.sanitize_document(document)

        ingested = self.ingestion.ingest(
            document, trace_id=trace_id, tenant_id=tenant_id, session_id=session_id
        )
        plan = self.reasoning.plan(
            user_request, ingested, trace_id=trace_id, tenant_id=tenant_id, session_id=session_id
        )
        acted = self.action.act(
            plan,
            getattr(plan, "instructions", []),
            trace_id=trace_id,
            tenant_id=tenant_id,
            session_id=session_id,
            guardrail=self.guardrail,
        )
        self.backend.refresh()
        return {"ingested": ingested, "plan": plan, "acted": acted}

    # ----------------------------------------------------- leak scenario path
    def handle_conversation(
        self,
        message: str,
        *,
        tenant_id: str,
        session_id: Optional[str] = None,
        remember: bool = True,
    ) -> Span:
        trace_id = new_id("trace")
        session_id = session_id or new_id("session")
        query_emb = self.embedder.embed(message)

        # Retrieve "relevant" context from shared memory (the leak source).
        retrieved = self.memory.retrieve(query_emb, tenant_id, k=1)
        context_text = ""
        inherited_provenance: List[str] = [provenance.tag("user", session_id)]
        if retrieved:
            item = retrieved[0]
            context_text = item.text
            inherited_provenance = provenance.merge(inherited_provenance, item.provenance)

        # The assistant composes a reply that (buggily) includes retrieved
        # context verbatim.
        reply = f"Here is the information related to your request. {context_text}".strip()

        # Optional output guardrail: redact cross-tenant PII before responding.
        blocked = False
        block_reason = ""
        if self.guardrail is not None:
            verdict = self.guardrail.check_response(reply, tenant_id, inherited_provenance)
            if not verdict.allowed:
                reply = verdict.sanitized_text
                blocked = True
                block_reason = verdict.reason

        span = Span(
            trace_id=trace_id,
            tenant_id=tenant_id,
            session_id=session_id,
            agent="reasoning-agent",
            role="reason",
            phase="output",
            text=reply,
            input_text=message,
            output_text=reply,
            provenance=inherited_provenance,
            blocked=blocked,
            block_reason=block_reason,
        )
        self.tracer.record(span)

        # Persist this turn's content to shared memory for future retrieval.
        if remember:
            self.memory.add(
                MemoryItem(
                    text=message,
                    tenant_id=tenant_id,
                    session_id=session_id,
                    embedding=query_emb,
                    provenance=[provenance.tag("user", session_id)],
                )
            )

        self.backend.refresh()
        return span
