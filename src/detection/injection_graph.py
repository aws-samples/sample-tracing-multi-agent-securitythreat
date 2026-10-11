"""Injection propagation graph.

Given a seed — the text of a suspected injection (or an embedding of it) — this
reconstructs how that instruction propagated through the pipeline:

1.  kNN similarity search over the ``agent-traces`` index finds every span
    whose content is semantically close to the seed, even if it was reworded.
2.  We connect those spans using ``parent_span_id`` (the agent-to-agent hop)
    and ``provenance`` (the originating document), producing a directed graph.
3.  We flag the *impact*: any matched span that made a tool call.

The result is a source-to-impact path: untrusted document -> ingestion ->
reasoning -> tool call.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .. import provenance
from ..backends.base import SearchBackend
from ..config import get_settings
from ..embeddings import get_embedder

_PHASE_ORDER = {"ingest": 0, "reason": 1, "act": 2, "output": 3}


@dataclass
class GraphNode:
    span_id: str
    agent: str
    phase: str
    similarity: float
    text: str
    provenance: List[str]
    tool_calls: List[Dict[str, Any]]

    @property
    def reached_tool(self) -> bool:
        return any(not c.get("blocked") for c in self.tool_calls)


@dataclass
class InjectionFinding:
    seed: str
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[Dict[str, str]] = field(default_factory=list)
    source_documents: List[str] = field(default_factory=list)
    impacts: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def propagated_to_tool(self) -> bool:
        return bool(self.impacts)


class InjectionPropagationGraph:
    def __init__(self, backend: SearchBackend, threshold: Optional[float] = None):
        self.backend = backend
        self.embedder = get_embedder()
        self.threshold = (
            threshold
            if threshold is not None
            else get_settings().injection_similarity_threshold
        )

    def trace(self, seed_text: str, k: int = 50) -> InjectionFinding:
        seed_vec = self.embedder.embed(seed_text)
        neighbours = self.backend.knn_search(seed_vec, k=k)
        matched = [(span, score) for span, score in neighbours if score >= self.threshold]

        # Index every span so we can walk parent -> child propagation edges.
        all_spans = self.backend.all_spans()
        children: Dict[str, List[Dict[str, Any]]] = {}
        for span in all_spans:
            parent = span.get("parent_span_id")
            if parent:
                children.setdefault(parent, []).append(span)

        finding = InjectionFinding(seed=seed_text)
        similarity_by_id = {span["span_id"]: score for span, score in matched}
        included: Dict[str, Dict[str, Any]] = {}

        def include(span: Dict[str, Any], similarity: float) -> None:
            sid = span["span_id"]
            if sid in included:
                return
            included[sid] = span
            node = GraphNode(
                span_id=sid,
                agent=span.get("agent", "?"),
                phase=span.get("phase", "?"),
                similarity=round(similarity, 4),
                text=span.get("text", ""),
                provenance=span.get("provenance", []),
                tool_calls=span.get("tool_calls", []),
            )
            finding.nodes.append(node)
            for tag in node.provenance:
                if provenance.is_untrusted(tag) and tag not in finding.source_documents:
                    finding.source_documents.append(tag)
            if node.reached_tool:
                for call in node.tool_calls:
                    if not call.get("blocked"):
                        finding.impacts.append(
                            {"span_id": sid, "tool": call.get("name"), "args": call.get("args")}
                        )

        # Seed the graph with the semantically-matched spans, then follow their
        # descendants: a downstream span is a consequence of the injection even
        # if its own text (e.g. a tool-call summary) is not similar to the seed.
        for span, score in matched:
            include(span, score)

        frontier = list(included.values())
        while frontier:
            current = frontier.pop()
            for child in children.get(current["span_id"], []):
                if child["span_id"] not in included:
                    include(child, similarity_by_id.get(child["span_id"], 0.0))
                    finding.edges.append({"from": current["span_id"], "to": child["span_id"]})
                    frontier.append(child)
                else:
                    finding.edges.append({"from": current["span_id"], "to": child["span_id"]})

        finding.nodes.sort(key=lambda n: _PHASE_ORDER.get(n.phase, 99))
        return finding

    @staticmethod
    def render(finding: InjectionFinding) -> str:
        lines = ["Injection propagation graph", "=" * 32]
        lines.append(f"seed: {finding.seed[:80]!r}")
        lines.append(f"source(s): {', '.join(finding.source_documents) or 'none'}")
        lines.append("")
        for node in finding.nodes:
            marker = "  !! TOOL CALL" if node.reached_tool else ""
            score = (
                f"sim={node.similarity:.3f}"
                if node.similarity > 0
                else "via-propagation"
            )
            lines.append(f"[{node.phase:>6}] {node.agent:<16} {score}{marker}")
            lines.append(f"          {node.text[:90]!r}")
        lines.append("")
        if finding.propagated_to_tool:
            lines.append("VERDICT: injection PROPAGATED to a tool call:")
            for impact in finding.impacts:
                lines.append(f"  -> {impact['tool']} {impact['args']}")
        else:
            lines.append("VERDICT: no tool impact detected")
        return "\n".join(lines)
