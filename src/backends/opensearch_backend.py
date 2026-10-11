"""Amazon OpenSearch Service backend.

This is the code the blog post walks through. It shows:

* the index mapping, including a ``knn_vector`` field for embedding similarity,
* how spans are indexed,
* the exact query DSL used by the detectors (kNN with a filter, and bool/term
  filtering for provenance and tenant traversal).

Connection supports either basic auth or AWS SigV4 (recommended for a managed
Amazon OpenSearch Service domain).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from ..config import Settings
from .base import SearchBackend


class OpenSearchBackend(SearchBackend):
    def __init__(self, settings: Settings):
        from opensearchpy import OpenSearch, RequestsHttpConnection

        self.settings = settings
        self.index = settings.traces_index

        from urllib.parse import urlparse

        parsed = urlparse(
            settings.endpoint
            if "://" in settings.endpoint
            else f"https://{settings.endpoint}"
        )
        host = parsed.hostname or settings.endpoint
        port = parsed.port or 443

        if settings.use_sigv4:
            import boto3
            from requests_aws4auth import AWS4Auth

            creds = boto3.Session().get_credentials()
            http_auth = AWS4Auth(
                creds.access_key,
                creds.secret_key,
                settings.aws_region,
                "es",
                session_token=creds.token,
            )
        else:
            http_auth = (settings.username, settings.password)

        self.client = OpenSearch(
            hosts=[{"host": host, "port": port}],
            http_auth=http_auth,
            use_ssl=True,
            verify_certs=settings.verify_certs,
            ssl_show_warn=settings.verify_certs,
            connection_class=RequestsHttpConnection,
        )

    # ------------------------------------------------------------------ index
    def ensure_index(self) -> None:
        if self.client.indices.exists(index=self.index):
            return
        mapping = {
            "settings": {
                "index": {
                    "knn": True,          # enable approximate kNN
                    "knn.algo_param.ef_search": 100,
                }
            },
            "mappings": {
                "properties": {
                    "trace_id": {"type": "keyword"},
                    "span_id": {"type": "keyword"},
                    "parent_span_id": {"type": "keyword"},
                    "timestamp": {"type": "date"},
                    "agent": {"type": "keyword"},
                    "role": {"type": "keyword"},
                    "phase": {"type": "keyword"},
                    "tenant_id": {"type": "keyword"},
                    "session_id": {"type": "keyword"},
                    "text": {"type": "text"},
                    "input_text": {"type": "text"},
                    "output_text": {"type": "text"},
                    "provenance": {"type": "keyword"},
                    "tool_calls": {"type": "object", "enabled": True},
                    "pii_types": {"type": "keyword"},
                    "pii_values": {"type": "keyword"},
                    "blocked": {"type": "boolean"},
                    "block_reason": {"type": "keyword"},
                    "embedding": {
                        "type": "knn_vector",
                        "dimension": self.settings.embedding_dim,
                        "method": {
                            "name": "hnsw",
                            "space_type": "cosinesimil",
                            "engine": "lucene",
                        },
                    },
                }
            },
        }
        self.client.indices.create(index=self.index, body=mapping)

    def index_span(self, span: Dict[str, Any]) -> None:
        self.client.index(index=self.index, id=span["span_id"], body=span)

    def refresh(self) -> None:
        self.client.indices.refresh(index=self.index)

    def get(self, span_id: str) -> Optional[Dict[str, Any]]:
        if not self.client.exists(index=self.index, id=span_id):
            return None
        return self.client.get(index=self.index, id=span_id)["_source"]

    # ----------------------------------------------------------------- search
    @staticmethod
    def _term_filters(filters: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        clauses: List[Dict[str, Any]] = []
        for field, value in (filters or {}).items():
            if isinstance(value, list):
                clauses.append({"terms": {field: value}})
            else:
                clauses.append({"term": {field: value}})
        return clauses

    def knn_search(
        self,
        vector: List[float],
        k: int,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[Tuple[Dict[str, Any], float]]:
        knn_query: Dict[str, Any] = {"vector": vector, "k": k}
        filter_clauses = self._term_filters(filters)
        if filter_clauses:
            # Post-filter the kNN neighbours to a tenant / phase / etc.
            knn_query["filter"] = {"bool": {"filter": filter_clauses}}

        body = {"size": k, "query": {"knn": {"embedding": knn_query}}}
        resp = self.client.search(index=self.index, body=body)

        results: List[Tuple[Dict[str, Any], float]] = []
        for hit in resp["hits"]["hits"]:
            # Lucene cosine score is (1 + cos) / 2; map back to cosine [-1, 1].
            cosine = hit["_score"] * 2.0 - 1.0
            results.append((hit["_source"], cosine))
        return results

    def query(
        self, filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        clauses = self._term_filters(filters)
        body = {
            "size": 10000,
            "query": {"bool": {"filter": clauses}} if clauses else {"match_all": {}},
        }
        resp = self.client.search(index=self.index, body=body)
        return [hit["_source"] for hit in resp["hits"]["hits"]]

    def all_spans(self) -> List[Dict[str, Any]]:
        return self.query(None)
