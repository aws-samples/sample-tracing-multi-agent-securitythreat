"""Search backends: an in-memory store and a real Amazon OpenSearch client.

Both expose the same small interface (see ``base.SearchBackend``) so the demo,
detectors and guardrails are written once and run against either.
"""
from __future__ import annotations

from ..config import get_settings
from .base import SearchBackend
from .memory_backend import InMemoryBackend


def get_backend() -> SearchBackend:
    settings = get_settings()
    if settings.backend == "opensearch":
        from .opensearch_backend import OpenSearchBackend

        return OpenSearchBackend(settings)
    return InMemoryBackend(settings)


__all__ = ["SearchBackend", "InMemoryBackend", "get_backend"]
