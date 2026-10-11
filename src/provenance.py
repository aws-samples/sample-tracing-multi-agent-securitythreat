"""Provenance tagging.

Every piece of content that flows through the pipeline carries a set of source
tags describing where it came from. When an agent produces output, the output
inherits the provenance of every input that contributed to it. This inherited
lineage is what lets us reconstruct a full source-to-impact path later.

A provenance tag is a simple string of the form ``<kind>:<id>``, for example:

    document:ticket-4417        (an external, untrusted ingested document)
    user:tenant-b:session-12    (first-party user input)
    tool:crm_lookup             (data returned by a tool call)
"""
from __future__ import annotations

from typing import Iterable, List, Set

# Provenance kinds we treat as UNTRUSTED (external / attacker-controllable).
UNTRUSTED_KINDS = {"document", "web", "email", "ticket"}


def tag(kind: str, identifier: str) -> str:
    return f"{kind}:{identifier}"


def kind_of(provenance_tag: str) -> str:
    return provenance_tag.split(":", 1)[0]


def is_untrusted(provenance_tag: str) -> bool:
    return kind_of(provenance_tag) in UNTRUSTED_KINDS


def merge(*sources: Iterable[str]) -> List[str]:
    """Combine provenance from multiple inputs, de-duplicated and stable."""
    seen: Set[str] = set()
    merged: List[str] = []
    for source in sources:
        for t in source:
            if t not in seen:
                seen.add(t)
                merged.append(t)
    return merged


def has_untrusted(tags: Iterable[str]) -> bool:
    return any(is_untrusted(t) for t in tags)


def untrusted_tags(tags: Iterable[str]) -> List[str]:
    return [t for t in tags if is_untrusted(t)]
