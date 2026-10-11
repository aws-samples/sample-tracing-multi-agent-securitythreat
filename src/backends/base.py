"""Backend interface shared by the in-memory store and the OpenSearch client."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple


class SearchBackend(ABC):
    """Minimal search interface used by the tracing + detection layers.

    A "span" is a single document representing one agent interaction. See
    ``src/backends/opensearch_backend.py`` for the concrete index mapping.
    """

    @abstractmethod
    def ensure_index(self) -> None:
        """Create the traces index (with kNN vector mapping) if absent."""

    @abstractmethod
    def index_span(self, span: Dict[str, Any]) -> None:
        """Index a single agent-interaction span. Must contain ``span_id``."""

    @abstractmethod
    def refresh(self) -> None:
        """Make recently indexed spans searchable."""

    @abstractmethod
    def get(self, span_id: str) -> Optional[Dict[str, Any]]:
        """Fetch one span by id."""

    @abstractmethod
    def knn_search(
        self,
        vector: List[float],
        k: int,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[Tuple[Dict[str, Any], float]]:
        """Return up to ``k`` (span, cosine_similarity) pairs nearest to
        ``vector``. ``filters`` is a dict of exact-match term filters."""

    @abstractmethod
    def query(
        self, filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Return all spans matching the exact-match term ``filters``.
        A filter value may be a scalar or a list (matches any)."""

    @abstractmethod
    def all_spans(self) -> List[Dict[str, Any]]:
        """Return every span (used for demo reporting)."""
