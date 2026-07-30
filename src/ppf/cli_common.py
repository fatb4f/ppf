"""Shared JSON document and command rendering helpers."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import rfc8785
from pydantic import BaseModel

from .contracts import load_contract_bytes
from .core import _document_id, _expand_inputs
from .validation import ValidationContext, validate_documents

Json = Any


@dataclass(frozen=True)
class ValidatedBundle:
    """One immutable in-memory snapshot of validated contract input bytes."""

    documents: dict[str, dict[str, Json]]
    references: dict[str, dict[str, Json]]
    transports: dict[str, BaseModel]
    raw_documents: tuple[tuple[Path, bytes], ...]


def load_valid_bundle(
    paths: list[Path],
    *,
    repository_root: Path,
) -> ValidatedBundle:
    """Validate a complete bundle before indexing any document."""
    loaded: list[tuple[Path, bytes]] = []
    for path in _expand_inputs(paths):
        try:
            loaded.append((path, path.read_bytes()))
        except OSError as error:
            raise ValueError(f"cannot read contract {path}: {error}") from error
    result = validate_documents(
        loaded,
        context=ValidationContext(repository_root),
    )
    if not result.valid:
        raise ValueError(json.dumps(result.as_dict(), sort_keys=True))
    documents: dict[str, dict[str, Json]] = {}
    references: dict[str, dict[str, Json]] = {}
    transports: dict[str, BaseModel] = {}
    for path, raw in loaded:
        loaded_contract = load_contract_bytes(
            path,
            raw,
            repository_root=repository_root,
            require_bundle=False,
        )
        document = loaded_contract.document
        identifier = _document_id(document)
        if identifier is not None:
            documents[identifier] = document
            transports[identifier] = loaded_contract.transport
            references[identifier] = {
                "id": identifier,
                "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                "uri": f"bundle:{path.name}",
                "mediaType": "application/json",
            }
    return ValidatedBundle(
        documents=documents,
        references=references,
        transports=transports,
        raw_documents=tuple(loaded),
    )


def exact_bundle_refs(bundle: ValidatedBundle) -> dict[str, dict[str, Json]]:
    """Index exact supplied document bytes as content references."""
    return {identifier: dict(reference) for identifier, reference in bundle.references.items()}


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
