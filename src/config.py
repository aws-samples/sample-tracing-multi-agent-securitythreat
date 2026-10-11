"""Central configuration, read from environment with safe local defaults."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


# Name of the OpenSearch index that stores every agent interaction ("span").
TRACES_INDEX = os.environ.get("OPENSEARCH_TRACES_INDEX", "agent-traces")

# Dimensionality of the embedding vectors. Amazon Titan Text Embeddings V2
# (the default provider) supports 256, 512, or 1024; we use 1024 for best
# quality. The optional local embedder honors the same value.
EMBEDDING_DIM = int(os.environ.get("EMBEDDING_DIM", "1024"))


@dataclass
class Settings:
    """Runtime settings for the demo."""

    # "memory" (default, no infra needed) or "opensearch" (real client).
    backend: str = field(
        default_factory=lambda: os.environ.get("OPENSEARCH_BACKEND", "memory")
    )
    # "bedrock" (default, Amazon Titan Text Embeddings V2) or "local"
    # (deterministic, dependency-free fallback for running without AWS).
    embedding_provider: str = field(
        default_factory=lambda: os.environ.get("EMBEDDING_PROVIDER", "bedrock")
    )
    traces_index: str = TRACES_INDEX
    embedding_dim: int = EMBEDDING_DIM

    # OpenSearch connection (only used when backend == "opensearch").
    endpoint: str = field(
        default_factory=lambda: os.environ.get("OPENSEARCH_ENDPOINT", "")
    )
    username: str = field(
        default_factory=lambda: os.environ.get("OPENSEARCH_USERNAME", "")
    )
    password: str = field(
        default_factory=lambda: os.environ.get("OPENSEARCH_PASSWORD", "")
    )
    aws_region: str = field(
        default_factory=lambda: os.environ.get("AWS_REGION", "us-east-1")
    )
    use_sigv4: bool = field(
        default_factory=lambda: os.environ.get("OPENSEARCH_USE_SIGV4", "false").lower()
        == "true"
    )
    verify_certs: bool = field(
        default_factory=lambda: os.environ.get("OPENSEARCH_VERIFY_CERTS", "true").lower()
        != "false"
    )

    # Detection thresholds.
    # Tuned for Amazon Titan Text Embeddings V2: benign spans score < 0.33
    # against the injection seed, the attack path scores > 0.49.
    injection_similarity_threshold: float = float(
        os.environ.get("INJECTION_SIMILARITY_THRESHOLD", "0.4")
    )


def get_settings() -> Settings:
    return Settings()
