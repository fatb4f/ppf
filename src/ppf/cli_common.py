"""Shared JSON document and command rendering helpers."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import rfc8785

from .core import _document_id
from .validation import ValidationContext, validate_paths

Json = Any


def load_valid_bundle(
    paths: list[Path],
    *,
    repository_root: Path,
) -> dict[str, dict[str, Json]]:
    """Validate a complete bundle before indexing any document."""
    result = validate_paths(
        paths,
        context=ValidationContext(repository_root),
    )
    if not result.valid:
        raise ValueError(json.dumps(result.as_dict(), sort_keys=True))
    documents: dict[str, dict[str, Json]] = {}
    expanded: list[Path] = []
    for path in paths:
        if path.is_dir():
            expanded.extend(sorted(path.rglob("*.json")))
        else:
            expanded.append(path)
    for path in expanded:
        document = json.loads(path.read_bytes())
        identifier = _document_id(document)
        if identifier is not None:
            documents[identifier] = document
    return documents


def exact_bundle_refs(paths: list[Path]) -> dict[str, dict[str, Json]]:
    """Index exact supplied document bytes as content references."""
    references: dict[str, dict[str, Json]] = {}
    expanded: list[Path] = []
    for path in paths:
        if path.is_dir():
            expanded.extend(sorted(path.rglob("*.json")))
        else:
            expanded.append(path)
    for path in expanded:
        raw = path.read_bytes()
        document = json.loads(raw)
        identifier = _document_id(document)
        if identifier is not None:
            references[identifier] = {
                "id": identifier,
                "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                "uri": f"bundle:{path.name}",
                "mediaType": "application/json",
            }
    return references


def by_type(
    documents: dict[str, dict[str, Json]],
    document_type: str,
) -> dict[str, Json]:
    matches = [
        document
        for document in documents.values()
        if document.get("documentType") == document_type
    ]
    if len(matches) != 1:
        raise ValueError(
            f"expected exactly one {document_type!r} document, found {len(matches)}"
        )
    return matches[0]


def content_ref(
    identifier: str,
    document: dict[str, Json],
    *,
    uri: str | None = None,
) -> dict[str, Json]:
    """Create a canonical content reference for an in-memory document."""
    result: dict[str, Json] = {
        "id": identifier,
        "digest": "sha256:" + hashlib.sha256(rfc8785.dumps(document)).hexdigest(),
    }
    if uri is not None:
        result["uri"] = uri
    return result


def render_json(
    payload: dict[str, Json],
    *,
    write: Callable[[str], object] = print,
) -> None:
    write(json.dumps(payload, sort_keys=True))
