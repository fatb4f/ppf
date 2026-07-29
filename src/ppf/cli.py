"""Command-line adapters for the authoritative PPF validation API."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Protocol

from cyclopts import App, Parameter

from .catalog import SchemaCatalog
from .validation import ValidationContext, ValidationResult, validate_paths


class ValidationService(Protocol):
    """Injectable validation boundary used by the command adapter."""

    def __call__(
        self,
        paths: list[Path],
        *,
        context: ValidationContext | None = None,
    ) -> ValidationResult: ...


def _write_json(payload: dict[str, object], write: Callable[[str], object]) -> None:
    write(json.dumps(payload, indent=None if payload.get("valid", True) else 2))


def run_validation(
    documents: list[Path],
    *,
    repository_root: Path | None = None,
    service: ValidationService = validate_paths,
    write: Callable[[str], object] = print,
) -> int:
    """Validate documents and render the stable JSON command response."""
    result = service(
        documents,
        context=ValidationContext(repository_root) if repository_root is not None else None,
    )
    payload = result.as_dict()
    _write_json(payload, write)
    return 0 if result.valid else 1


def run_catalog(
    document_type: str | None = None,
    *,
    catalog: SchemaCatalog | None = None,
    write: Callable[[str], object] = print,
) -> int:
    """Render deterministic catalog discovery JSON."""
    catalog = catalog or SchemaCatalog.load()
    try:
        payload = catalog.as_dict(document_type)
    except KeyError:
        payload = {
            "valid": False,
            "error": f"unsupported documentType {document_type!r}",
        }
        _write_json(payload, write)
        return 1
    _write_json(payload, write)
    return 0


app = App(
    name="ppf-validate",
    help="Discover and validate Python Policy PPF contracts.",
    result_action="return_value",
)


@app.command
def catalog(document_type: str | None = None) -> int:
    """List supported documents or disclose one document schema."""
    return run_catalog(document_type)


@app.command(name="validate")
def validate_command(
    document: Annotated[
        list[Path],
        Parameter(help="One or more JSON files or directories."),
    ],
    *,
    repository_root: Annotated[
        Path | None,
        Parameter(help="Explicit root for local references and repository locks."),
    ] = None,
) -> int:
    """Validate a bundle through the explicit command form."""
    return run_validation(document, repository_root=repository_root)


@app.default
def validate_alias(
    document: Annotated[
        list[Path],
        Parameter(help="One or more JSON files or directories."),
    ],
    *,
    repository_root: Annotated[
        Path | None,
        Parameter(help="Explicit root for local references and repository locks."),
    ] = None,
) -> int:
    """Validate a bundle through the compatibility direct-path form."""
    return run_validation(document, repository_root=repository_root)


def main() -> int:
    """Run the shared Cyclopts application for console scripts and shims."""
    return app()


if __name__ == "__main__":
    sys.exit(main())
