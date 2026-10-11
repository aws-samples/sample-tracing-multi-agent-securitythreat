"""In-memory backend that mirrors the OpenSearch query semantics used here.

This lets the whole demo run with zero infrastructure. It implements the same
three operations the detectors rely on: exact-match term filtering, kNN cosine
similarity search, and fetch-by-id. It is intentionally simple — for anything
beyond the demo, use the real OpenSearch backend.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from ..config import Settings
from ..embeddings import cosine_similarity
from .base import SearchBackend


def _matches(span: Dict[str, Any], filters: Optional[Dict[str, Any]]) -> bool:
    if not filters:
        return True
    for field, expected in filters.items():
        actual = span.get(field)
        allowed = expected if isinstance(expected, list) else [expected]
        if isinstance(actual, list):
            # Match if the span's list shares any value with the filter.
            if not any(a in allowed for a in actual):
                return False
        else:
            if actual not in allowed:
                return False
    return True


class InMemoryBackend(SearchBackend):
    def __init__(self, settings: Settings):
        self.settings = settings
        self._spans: Dict[str, Dict[str, Any]] = {}

    def ensure_index(self) -> None:
        self._spans.clear()

    def index_span(self, span: Dict[str, Any]) -> None:
        if "span_id" not in span:
            raise ValueError("span must contain 'span_id'")
        self._spans[span["span_id"]] = dict(span)

    def refresh(self) -> None:  # no-op; writes are immediately visible
        return None

    def get(self, span_id: str) -> Optional[Dict[str, Any]]:
        span = self._spans.get(span_id)
        return dict(span) if span else None

    def knn_search(
        self,
        vector: List[float],
        k: int,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[Tuple[Dict[str, Any], float]]:
        scored: List[Tuple[Dict[str, Any], float]] = []
        for span in self._spans.values():
            if not _matches(span, filters):
                continue
            emb = span.get("embedding")
            if not emb:
                continue
            score = cosine_similarity(vector, emb)
            scored.append((dict(span), score))
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored[:k]

    def query(
        self, filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        return [
            dict(span) for span in self._spans.values() if _matches(span, filters)
        ]

    def all_spans(self) -> List[Dict[str, Any]]:
        return [dict(span) for span in self._spans.values()]
