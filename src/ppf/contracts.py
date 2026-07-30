"""Schema-first loading into generated transport and handwritten domain boundaries."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from .generated.models import PythonPolicyPpfExecutionAndRepairExtension
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


def load_execution_contract(
    path: Path,
    *,
    repository_root: Path | None = None,
) -> LoadedContract:
    """Validate with packaged contracts before parsing through generated models."""
    raw = path.read_bytes()
    result = validate_documents(
        [(path, raw)],
        context=(
            ValidationContext(repository_root)
            if repository_root is not None
            else None
        ),
    )
    if not result.valid:
        diagnostics = [
            error.as_dict()
            for document in result.documents
            for error in document.errors
        ]
        raise ContractValidationError(json.dumps(diagnostics, sort_keys=True))
    document = json.loads(raw)
    transport = PythonPolicyPpfExecutionAndRepairExtension.model_validate(document).root
    return LoadedContract(raw=raw, document=document, transport=transport)
