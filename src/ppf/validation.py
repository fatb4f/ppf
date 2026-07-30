"""Typed orchestration for structural, semantic, and repository validation."""

from __future__ import annotations

import hashlib
import re
import tomllib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from json import JSONDecodeError
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote_to_bytes, urlsplit

from .catalog import SchemaCatalog
from .core import (
    ValidationError,
    _content_refs,
    _expand_inputs,
    validate_bundle,
    validate_semantics,
)
from .evaluation import validate_evaluation_semantics
from .execution_contracts import validate_execution_semantics
from .json_input import strict_json_loads

Json = Any
LoadedDocument = tuple[Path, bytes, dict[str, Json]]
_SHA256_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


@dataclass(frozen=True)
class ValidationContext:
    """Explicit repository boundary for filesystem-aware validation passes."""

    repository_root: Path | None = None


@dataclass(frozen=True)
class DocumentValidationResult:
    """Validation outcome for one input document."""

    document: Path
    errors: tuple[ValidationError, ...]

    @property
    def valid(self) -> bool:
        return not self.errors

    def as_dict(self) -> dict[str, Json]:
        return {
            "document": str(self.document),
            "valid": self.valid,
            "errors": [error.as_dict() for error in self.errors],
        }


@dataclass(frozen=True)
class ValidationResult:
    """Deterministic validation outcome for a document bundle."""

    documents: tuple[DocumentValidationResult, ...]

    @property
    def valid(self) -> bool:
        return all(document.valid for document in self.documents)

    def as_dict(self) -> dict[str, Json]:
        return {
            "valid": self.valid,
            "documents": [document.as_dict() for document in self.documents],
        }

    def __getitem__(self, key: str) -> Json:
        """Preserve read compatibility with the former dictionary result."""
        return self.as_dict()[key]


def _sorted_errors(errors: Iterable[ValidationError]) -> tuple[ValidationError, ...]:
    return tuple(
        sorted(
            errors,
            key=lambda item: (
                item.kind,
                tuple((type(part).__name__, str(part)) for part in item.path),
                item.message,
            ),
        )
    )


def _result(errors: dict[Path, list[ValidationError]]) -> ValidationResult:
    return ValidationResult(
        tuple(
            DocumentValidationResult(path, _sorted_errors(path_errors))
            for path, path_errors in sorted(errors.items(), key=lambda item: str(item[0]))
        )
    )


def _resolved_root(context: ValidationContext | None) -> tuple[Path | None, str | None]:
    if context is None or context.repository_root is None:
        return None, "repository context is required"
    try:
        root = context.repository_root.resolve(strict=True)
    except OSError as error:
        return None, f"repository root cannot be resolved: {error}"
    if not root.is_dir():
        return None, f"repository root is not a directory: {root}"
    return root, None


def _decoded_uri_path(uri: str) -> tuple[str | None, str | None]:
    try:
        decoded = unquote_to_bytes(urlsplit(uri).path).decode("utf-8")
    except (UnicodeDecodeError, ValueError) as error:
        return None, f"local URI path cannot be decoded: {error}"
    if "\x00" in decoded:
        return None, "local URI path contains a NUL byte"
    posix = PurePosixPath(decoded)
    native = Path(decoded)
    if posix.is_absolute() or native.is_absolute():
        return None, "local URI path must be repository-root-relative"
    if ".." in posix.parts or ".." in native.parts:
        return None, "local URI path must not contain '..' segments"
    return decoded, None


def _local_ref_errors(
    document: dict[str, Json],
    context: ValidationContext | None,
) -> list[ValidationError]:
    errors: list[ValidationError] = []
    root: Path | None = None
    root_error: str | None = None
    root_loaded = False

    for ref_path, reference in _content_refs(document):
        uri = reference.get("uri")
        if not isinstance(uri, str):
            continue
        try:
            parsed = urlsplit(uri)
        except ValueError as error:
            errors.append(
                ValidationError(
                    (*ref_path, "uri"),
                    f"invalid URI reference {uri!r}: {error}",
                    "semantic",
                )
            )
            continue
        if parsed.netloc and not parsed.scheme:
            errors.append(
                ValidationError(
                    (*ref_path, "uri"),
                    f"scheme-less URI must not contain an authority: {uri!r}",
                    "semantic",
                )
            )
            continue
        if parsed.scheme and parsed.scheme != "file":
            continue
        if parsed.netloc:
            errors.append(
                ValidationError(
                    (*ref_path, "uri"),
                    f"local URI must not contain an authority: {uri!r}",
                    "semantic",
                )
            )
            continue
        if parsed.query:
            errors.append(
                ValidationError(
                    (*ref_path, "uri"),
                    f"local URI must not contain a query: {uri!r}",
                    "semantic",
                )
            )
            continue

        decoded, path_error = _decoded_uri_path(uri)
        if path_error is not None:
            errors.append(ValidationError((*ref_path, "uri"), f"{path_error}: {uri!r}", "semantic"))
            continue
        if not root_loaded:
            root, root_error = _resolved_root(context)
            root_loaded = True
        if root_error is not None or root is None:
            errors.append(
                ValidationError(
                    (*ref_path, "uri"),
                    f"{root_error} for local URI {uri!r}",
                    "semantic",
                )
            )
            continue

        try:
            candidate = (root / str(decoded)).resolve()
        except OSError as error:
            errors.append(
                ValidationError(
                    (*ref_path, "uri"),
                    f"local URI cannot be resolved {uri!r}: {error}",
                    "semantic",
                )
            )
            continue
        if not candidate.is_relative_to(root):
            errors.append(
                ValidationError(
                    (*ref_path, "uri"),
                    f"local URI escapes repository root: {uri!r}",
                    "semantic",
                )
            )
            continue
        if not candidate.is_file():
            errors.append(
                ValidationError(
                    (*ref_path, "uri"),
                    f"local URI does not resolve to a regular file: {uri!r}",
                    "semantic",
                )
            )
            continue
        try:
            content = candidate.read_bytes()
        except OSError as error:
            errors.append(
                ValidationError(
                    (*ref_path, "uri"),
                    f"local URI cannot be read {uri!r}: {error}",
                    "semantic",
                )
            )
            continue
        digest = "sha256:" + hashlib.sha256(content).hexdigest()
        if digest != reference.get("digest"):
            errors.append(
                ValidationError(
                    (*ref_path, "digest"),
                    f"digest does not match local URI {uri!r}",
                    "semantic",
                )
            )
    return errors


def _implementation_lock_errors(
    document: dict[str, Json],
    context: ValidationContext | None,
) -> list[ValidationError]:
    if document.get("documentType") != "implementation-policy-extension":
        return []
    root, root_error = _resolved_root(context)
    if root_error is not None or root is None:
        return [
            ValidationError(
                ("projection", "generator"),
                f"{root_error} for implementation lock validation",
                "semantic",
            )
        ]

    lock_path = root / "uv.lock"
    try:
        lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        return [
            ValidationError(
                ("projection", "generator"),
                f"cannot load repository uv.lock: {error}",
                "semantic",
            )
        ]
    packages = lock.get("package")
    if not isinstance(packages, list):
        return [
            ValidationError(
                ("projection", "generator"),
                "uv.lock package table is missing or malformed",
                "semantic",
            )
        ]
    package = next(
        (
            item
            for item in packages
            if isinstance(item, dict) and item.get("name") == "datamodel-code-generator"
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

    distribution_rows: list[tuple[str, Json]] = []
    metadata_errors: list[ValidationError] = []
    sdist = package.get("sdist")
    if not isinstance(sdist, dict):
        metadata_errors.append(
            ValidationError(
                ("projection", "generator", "distributionRef", "digest"),
                "uv.lock sdist entry is missing or malformed",
                "semantic",
            )
        )
    else:
        distribution_rows.append(("sdist", sdist))

    wheels = package.get("wheels")
    if not isinstance(wheels, list):
        metadata_errors.append(
            ValidationError(
                ("projection", "generator", "distributionRef", "digest"),
                "uv.lock wheels list is missing or malformed",
                "semantic",
            )
        )
    else:
        for index, wheel in enumerate(wheels):
            if not isinstance(wheel, dict):
                metadata_errors.append(
                    ValidationError(
                        ("projection", "generator", "distributionRef", "digest"),
                        f"uv.lock wheel entry {index} is malformed",
                        "semantic",
                    )
                )
                continue
            distribution_rows.append((f"wheel entry {index}", wheel))

    locked_hashes: set[str] = set()
    for label, row in distribution_rows:
        distribution_hash = row.get("hash")
        if (
            not isinstance(distribution_hash, str)
            or _SHA256_DIGEST.fullmatch(distribution_hash) is None
        ):
            metadata_errors.append(
                ValidationError(
                    ("projection", "generator", "distributionRef", "digest"),
                    f"uv.lock {label} hash is missing or malformed",
                    "semantic",
                )
            )
            continue
        locked_hashes.add(distribution_hash)

    if metadata_errors:
        return metadata_errors

    generator = document["projection"]["generator"]
    errors: list[ValidationError] = []
    if generator.get("version") != package.get("version"):
        errors.append(
            ValidationError(
                ("projection", "generator", "version"),
                f"must equal uv.lock version {package.get('version')}",
                "semantic",
            )
        )
    distribution = generator["distributionRef"]
    if distribution.get("digest") not in locked_hashes:
        errors.append(
            ValidationError(
                ("projection", "generator", "distributionRef", "digest"),
                "distribution digest is absent from uv.lock",
                "semantic",
            )
        )
    return errors


def validate_documents(
    documents: Sequence[tuple[Path, bytes]],
    *,
    context: ValidationContext | None = None,
    catalog: SchemaCatalog | None = None,
    require_bundle: bool = True,
) -> ValidationResult:
    """Validate exact document bytes through the authoritative orchestration path."""
    catalog = catalog or SchemaCatalog.load()
    structurally_valid: list[LoadedDocument] = []
    errors: dict[Path, list[ValidationError]] = {}

    for path, raw in sorted(documents, key=lambda item: str(item[0])):
        path_errors = errors.setdefault(path, [])
        try:
            document = strict_json_loads(raw)
            if not isinstance(document, dict):
                raise TypeError("top-level document must be an object")
        except (JSONDecodeError, TypeError, UnicodeError, ValueError) as error:
            path_errors.append(ValidationError((), str(error), "input"))
            continue

        loaded_document = (path, raw, document)
        document_type = document.get("documentType")
        entry = catalog.entry(document_type) if isinstance(document_type, str) else None
        if entry is None:
            path_errors.append(
                ValidationError(
                    ("documentType",),
                    f"unsupported documentType {document_type!r}",
                    "structural",
                )
            )
            continue
        for error in catalog.validator(document_type).iter_errors(document):
            path_errors.append(
                ValidationError(tuple(error.absolute_path), error.message, "structural")
            )
        if path_errors:
            continue

        structurally_valid.append(loaded_document)
        path_errors.extend(validate_semantics(document))
        path_errors.extend(_local_ref_errors(document, context))
        path_errors.extend(_implementation_lock_errors(document, context))

    if require_bundle:
        for path, bundle_errors in validate_bundle(structurally_valid).items():
            errors[path].extend(bundle_errors)
        for path, semantic_errors in validate_evaluation_semantics(structurally_valid).items():
            errors[path].extend(semantic_errors)
        for path, semantic_errors in validate_execution_semantics(structurally_valid).items():
            errors[path].extend(semantic_errors)
    return _result(errors)


def validate_paths(
    paths: Sequence[Path],
    *,
    context: ValidationContext | None = None,
    catalog: SchemaCatalog | None = None,
) -> ValidationResult:
    """Read paths or JSON directories and validate their exact bytes."""
    inputs: list[tuple[Path, bytes]] = []
    input_errors: dict[Path, list[ValidationError]] = {}
    for path in _expand_inputs(list(paths)):
        try:
            inputs.append((path, path.read_bytes()))
        except OSError as error:
            input_errors.setdefault(path, []).append(ValidationError((), str(error), "input"))
    result = validate_documents(inputs, context=context, catalog=catalog)
    for document in result.documents:
        input_errors.setdefault(document.document, []).extend(document.errors)
    return _result(input_errors)
