"""Repository-aware command-line interface for PPF validation."""

from __future__ import annotations

import hashlib
import json
import sys
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any, Protocol
from urllib.parse import urlsplit

from cyclopts import App, Parameter
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from .core import (
    ValidationError,
    _content_refs,
    _expand_inputs,
    _format_path,
    validate_bundle,
    validate_semantics,
)
from .evaluation import validate_evaluation_semantics

Json = Any

EVALUATION_TYPES = {
    "evaluation-evidence-catalog",
    "evaluation-input-binding",
    "evaluation-producer-envelope",
    "evaluation-run-assembly",
    "evaluation-workflow",
    "evidence-admission-derivation",
    "qualification-integrity",
}
IMPLEMENTATION_TYPES = {
    "implementation-policy-extension",
    "shaping-policy",
    "shaping-profile-registry",
    "shaping-implementation-binding",
    "shaping-decision-record",
    "capability-provider-registry",
    "dependency-wiring-plan",
    "capability-assembly-record",
    "qualification-fixture-projection",
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _schema_paths(root: Path) -> tuple[Path, Path, Path]:
    package = root / ".codex" / "skills" / "python-policy-ppf"
    official = package / "references" / "python-policy-ppf.schema.json"
    evaluation = package / "extensions" / "python-policy-ppf.eval-workflow-extension.schema.json"
    implementation = package / "extensions" / "python-policy-implementation.extension.schema.json"
    return official, evaluation, implementation


def _load(path: Path) -> Json:
    return json.loads(path.read_text(encoding="utf-8"))


def _local_uri_path(document_path: Path, uri: str) -> Path | None:
    parsed = urlsplit(uri)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        return None
    candidate = Path(parsed.path)
    if candidate.is_absolute():
        return candidate
    for parent in (document_path.parent, *document_path.parents):
        resolved = parent / candidate
        if resolved.is_file():
            return resolved
    return document_path.parent / candidate


def _local_ref_errors(path: Path, document: dict[str, Json]) -> list[ValidationError]:
    if document.get("documentType") != "implementation-policy-extension":
        return []
    errors: list[ValidationError] = []
    for ref_path, reference in _content_refs(document):
        uri = reference.get("uri")
        if not isinstance(uri, str):
            continue
        local = _local_uri_path(path, uri)
        if local is None:
            continue
        if not local.is_file():
            errors.append(
                ValidationError(
                    (*ref_path, "uri"), f"local content does not exist: {uri}", "semantic"
                )
            )
            continue
        digest = "sha256:" + hashlib.sha256(local.read_bytes()).hexdigest()
        if digest != reference.get("digest"):
            errors.append(
                ValidationError(
                    (*ref_path, "digest"),
                    f"digest does not match local content {local}",
                    "semantic",
                )
            )
    return errors


def _implementation_lock_errors(
    path: Path,
    document: dict[str, Json],
    root: Path,
) -> list[ValidationError]:
    if document.get("documentType") != "implementation-policy-extension":
        return []
    errors: list[ValidationError] = []
    generator = document.get("projection", {}).get("generator", {})
    lock = tomllib.loads((root / "uv.lock").read_text(encoding="utf-8"))
    package = next(
        (
            item
            for item in lock.get("package", [])
            if item.get("name") == "datamodel-code-generator"
        ),
        None,
    )
    if package is None:
        return [
            ValidationError(
                ("projection", "generator"),
                "datamodel-code-generator is absent from uv.lock",
                "semantic",
            )
        ]
    if generator.get("version") != package.get("version"):
        errors.append(
            ValidationError(
                ("projection", "generator", "version"),
                f"must equal uv.lock version {package.get('version')}",
                "semantic",
            )
        )
    distribution = generator.get("distributionRef", {})
    locked_hashes = {
        item.get("hash")
        for item in [package.get("sdist", {}), *package.get("wheels", [])]
        if isinstance(item, dict)
    }
    if distribution.get("digest") not in locked_hashes:
        errors.append(
            ValidationError(
                ("projection", "generator", "distributionRef", "digest"),
                "distribution digest is absent from uv.lock",
                "semantic",
            )
        )
    return errors


def validate_paths(paths: list[Path], root: Path | None = None) -> dict[str, Json]:
    root = root or _repo_root()
    official_path, evaluation_path, implementation_path = _schema_paths(root)
    schemas = [_load(path) for path in (official_path, evaluation_path, implementation_path)]
    for schema in schemas:
        Draft202012Validator.check_schema(schema)
    registry = Registry()
    for schema in schemas:
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    validators = {
        "official": Draft202012Validator(
            schemas[0], registry=registry, format_checker=FormatChecker()
        ),
        "evaluation": Draft202012Validator(
            schemas[1], registry=registry, format_checker=FormatChecker()
        ),
        "implementation": Draft202012Validator(
            schemas[2], registry=registry, format_checker=FormatChecker()
        ),
    }

    loaded: list[tuple[Path, bytes, dict[str, Json]]] = []
    results: dict[Path, list[ValidationError]] = {}
    for path in _expand_inputs(paths):
        try:
            raw = path.read_bytes()
            document = json.loads(raw)
            if not isinstance(document, dict):
                raise TypeError("top-level document must be an object")
        except (OSError, json.JSONDecodeError, TypeError) as error:
            results[path] = [ValidationError((), str(error), "input")]
            continue
        loaded.append((path, raw, document))
        results[path] = []
        document_type = document.get("documentType")
        family = (
            "evaluation"
            if document_type in EVALUATION_TYPES
            else "implementation"
            if document_type in IMPLEMENTATION_TYPES
            else "official"
        )
        for error in validators[family].iter_errors(document):
            results[path].append(
                ValidationError(tuple(error.absolute_path), error.message, "structural")
            )
        if not results[path] and family == "official":
            results[path].extend(validate_semantics(document))
        results[path].extend(_local_ref_errors(path, document))
        results[path].extend(_implementation_lock_errors(path, document, root))

    for path, errors in validate_bundle(loaded).items():
        results.setdefault(path, []).extend(errors)
    for path, errors in validate_evaluation_semantics(loaded).items():
        results.setdefault(path, []).extend(errors)

    valid = all(not errors for errors in results.values())
    return {
        "valid": valid,
        "documents": [
            {
                "document": str(path),
                "valid": not errors,
                "errors": [
                    {
                        "kind": error.kind,
                        "path": _format_path(error.path),
                        "message": error.message,
                    }
                    for error in sorted(
                        errors, key=lambda item: (item.kind, item.path, item.message)
                    )
                ],
            }
            for path, errors in results.items()
        ],
    }


class ValidationService(Protocol):
    """Filesystem-independent validation boundary used by the CLI."""

    def __call__(self, paths: list[Path]) -> dict[str, Json]: ...


def run_validation(
    documents: list[Path],
    *,
    service: ValidationService = validate_paths,
    write: Callable[[str], object] = print,
) -> int:
    """Validate documents and render the stable JSON command response."""
    payload = service(documents)
    write(json.dumps(payload, indent=None if payload["valid"] else 2))
    return 0 if payload["valid"] else 1


app = App(
    name="ppf-validate",
    help="Validate structural and semantic Python Policy PPF contracts.",
    result_action="return_value",
)


@app.default
def validate(
    document: Annotated[
        list[Path],
        Parameter(help="One or more JSON files or directories."),
    ],
) -> int:
    """Validate a bundle of Python Policy PPF documents."""
    return run_validation(document)


def main() -> int:
    """Run the shared Cyclopts application for the console-script entrypoint."""
    return app()


if __name__ == "__main__":
    sys.exit(main())
