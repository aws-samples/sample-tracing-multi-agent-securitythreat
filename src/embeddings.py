"""Pluggable embedding provider.

Two backends:

* ``bedrock`` - **default.** Amazon Titan Text Embeddings V2 via boto3. Produces
                true semantic embeddings, so the injection-propagation kNN
                search follows an instruction even when it is heavily reworded.
* ``local``   - a deterministic, dependency-free fallback built from hashed
                word + character n-grams. Captures lexical overlap only; handy
                for running the demo without AWS access.

Both return L2-normalized vectors so that a dot product equals cosine
similarity, which is what the kNN queries rely on.
"""
from __future__ import annotations

import hashlib
import math
import re
from typing import List

from .config import get_settings

_WORD_RE = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> List[str]:
    return _WORD_RE.findall(text.lower())


def _char_ngrams(text: str, n: int = 4) -> List[str]:
    text = re.sub(r"\s+", " ", text.lower()).strip()
    if len(text) <= n:
        return [text] if text else []
    return [text[i : i + n] for i in range(len(text) - n + 1)]


def _hash_bucket(feature: str, dim: int) -> int:
    # MD5 is used only as a fast, stable hash to map a feature string to a
    # vector bucket (the hashing trick). It is not used for any security or
    # integrity purpose, so usedforsecurity=False is set explicitly.
    digest = hashlib.md5(feature.encode("utf-8"), usedforsecurity=False).digest()
    return int.from_bytes(digest[:4], "big") % dim


class LocalEmbedder:
    """Deterministic hashing embedder over words, bigrams and char n-grams."""

    def __init__(self, dim: int):
        self.dim = dim

    def embed(self, text: str) -> List[float]:
        vec = [0.0] * self.dim
        words = _tokens(text)

        features: List[str] = []
        features.extend(f"w:{w}" for w in words)
        features.extend(f"b:{a}_{b}" for a, b in zip(words, words[1:]))
        features.extend(f"c:{g}" for g in _char_ngrams(text, 4))

        for feat in features:
            bucket = _hash_bucket(feat, self.dim)
            # Sign hashing reduces collisions cancelling incorrectly.
            sign = 1.0 if _hash_bucket("s:" + feat, 2) == 0 else -1.0
            vec[bucket] += sign

        norm = math.sqrt(sum(v * v for v in vec))
        if norm == 0.0:
            return vec
        return [v / norm for v in vec]

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        return [self.embed(t) for t in texts]


class BedrockEmbedder:
    """Amazon Titan Text Embeddings. Requires boto3 + credentials."""

    def __init__(self, dim: int, region: str, model_id: str = "amazon.titan-embed-text-v2:0"):
        import boto3  # imported lazily so the demo runs without boto3

        self.dim = dim
        self.model_id = model_id
        self.client = boto3.client("bedrock-runtime", region_name=region)

    def embed(self, text: str) -> List[float]:
        import json

        body = json.dumps({"inputText": text, "dimensions": self.dim, "normalize": True})
        resp = self.client.invoke_model(modelId=self.model_id, body=body)
        payload = json.loads(resp["body"].read())
        return payload["embedding"]

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        return [self.embed(t) for t in texts]


def cosine_similarity(a: List[float], b: List[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


def get_embedder():
    settings = get_settings()
    if settings.embedding_provider == "bedrock":
        return BedrockEmbedder(settings.embedding_dim, settings.aws_region)
    return LocalEmbedder(settings.embedding_dim)
