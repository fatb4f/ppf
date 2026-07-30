"""Schema-first loading into generated transport and handwritten domain boundaries."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, RootModel
from pydantic import ValidationError as PydanticValidationError

from .generated.models import PythonPolicyPpfComposedSidecarExtensions03
from .json_input import strict_json_loads
from .validation import ValidationContext, validate_documents

Json = Any


class ContractValidationError(ValueError):
    """Raised when authoritative validation rejects a contract document."""


@dataclass(frozen=True)
class LoadedContract:
    """A validated raw document and its generated typed boundary."""

    raw: bytes
    document: dict[str, Json]
    transport: BaseModel


def _generated_transport(document: dict[str, Json]) -> BaseModel:
    transport: BaseModel | Json = PythonPolicyPpfComposedSidecarExtensions03.model_validate(
        document
    )
    while isinstance(transport, RootModel):
        transport = transport.root
    if not isinstance(transport, BaseModel):
        raise TypeError("generated contract boundary did not produce a model")
    return transport


def load_contract_bytes(
    path: Path,
    raw: bytes,
    *,
    repository_root: Path | None = None,
    require_bundle: bool = True,
) -> LoadedContract:
    """Validate exact bytes before parsing through the generated boundary."""
    result = validate_documents(
        [(path, raw)],
        context=(ValidationContext(repository_root) if repository_root is not None else None),
        require_bundle=require_bundle,
    )
    if not result.valid:
        diagnostics = [
            error.as_dict() for document in result.documents for error in document.errors
        ]
        raise ContractValidationError(json.dumps(diagnostics, sort_keys=True))
    document = strict_json_loads(raw)
    try:
        transport = _generated_transport(document)
    except PydanticValidationError as error:
        raise ContractValidationError(error.json()) from error
    return LoadedContract(raw=raw, document=document, transport=transport)


def load_execution_contract(
    path: Path,
    *,
    repository_root: Path | None = None,
) -> LoadedContract:
    """Validate with packaged contracts before parsing through generated models."""
    raw = path.read_bytes()
    return load_contract_bytes(
        path,
        raw,
        repository_root=repository_root,
    )
