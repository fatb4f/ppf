"""Semantic validation for the evaluation-workflow sidecar."""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import rfc8785

from .core import ValidationError, _document_id, _semantic

Json = Any
PathParts = tuple[str | int, ...]

_CLOSURE_COMPONENTS = {
    "adapterSet": "adapter-set",
    "catalog": "catalog",
    "environment": "environment",
    "inputManifest": "input-manifest",
    "invocationSet": "invocation-set",
    "plan": "plan",
    "profile": "profile",
    "sandboxProfile": "sandbox-profile",
    "stageRegistry": "stage-registry",
    "toolchain": "toolchain",
    "worktree": "worktree",
}
_MANIFEST_FIELDS = (
    "profile",
    "plan",
    "worktree",
    "environment",
    "toolchain",
    "invocationSet",
    "sandboxProfile",
    "adapterSet",
)
_CLOSURE_DOCUMENT_TYPES = {
    "profile": "generation-policy-profile",
    "plan": "evaluation-plan",
    "catalog": "evaluation-evidence-catalog",
    "stageRegistry": "stage-registry",
    "environment": "environment-profile",
    "toolchain": "toolchain-lock",
    "invocationSet": "evaluation-invocation-set",
    "sandboxProfile": "sandbox-profile",
    "adapterSet": "assessor-profile",
}


@dataclass(frozen=True)
class _ExpectedOccurrence:
    digest: str
    provenance: str


def closure_digest(closure: dict[str, Json]) -> str:
    """Return the normative RFC 8785 SHA-256 digest for an input closure."""
    return "sha256:" + hashlib.sha256(rfc8785.dumps(closure)).hexdigest()


def content_refs_match(left: Json, right: Json) -> bool:
    """Compare the immutable identity of two content references."""
    return (
        isinstance(left, dict)
        and isinstance(right, dict)
        and left.get("id") == right.get("id")
        and left.get("digest") == right.get("digest")
    )


def _add_expected(
    expected: dict[tuple[str, str], list[_ExpectedOccurrence]],
    component: str,
    reference: Json,
    provenance: str,
) -> None:
    if not isinstance(reference, dict):
        return
    identifier = reference.get("id")
    digest = reference.get("digest")
    if isinstance(identifier, str) and isinstance(digest, str):
        expected.setdefault((component, identifier), []).append(
            _ExpectedOccurrence(digest, provenance)
        )


def _expected_checks(
    binding: dict[str, Json],
    assembly: dict[str, Json],
    documents: dict[str, dict[str, Json]],
) -> dict[tuple[str, str], list[_ExpectedOccurrence]]:
    expected: dict[tuple[str, str], list[_ExpectedOccurrence]] = {}
    binding_id = binding.get("bindingId", "<unknown-binding>")
    assembly_id = assembly.get("assemblyId", "<unknown-assembly>")
    closure = binding.get("closure", {})
    if isinstance(closure, dict):
        for field, component in _CLOSURE_COMPONENTS.items():
            _add_expected(
                expected,
                component,
                closure.get(field),
                f"{binding_id}/closure/{field}",
            )

    _add_expected(
        expected,
        "assembler",
        assembly.get("assemblerRef"),
        f"{assembly_id}/assemblerRef",
    )
    for index, reference in enumerate(assembly.get("rawArtifactRefs", [])):
        _add_expected(
            expected,
            "raw-artifact",
            reference,
            f"{assembly_id}/rawArtifactRefs/{index}",
        )

    for binding_index, fragment_binding in enumerate(assembly.get("fragmentBindings", [])):
        if not isinstance(fragment_binding, dict):
            continue
        envelope_ref = fragment_binding.get("producerEnvelopeRef", {})
        envelope = documents.get(envelope_ref.get("id"))
        if not isinstance(envelope, dict):
            continue
        envelope_id = envelope.get("envelopeId", f"<envelope-{binding_index}>")
        _add_expected(
            expected,
            "producer",
            envelope.get("producerRef"),
            f"{envelope_id}/producerRef",
        )
        for execution_index, execution in enumerate(envelope.get("executions", [])):
            if not isinstance(execution, dict):
                continue
            prefix = f"{envelope_id}/executions/{execution_index}"
            _add_expected(
                expected,
                "invocation",
                execution.get("invocationRef"),
                f"{prefix}/invocationRef",
            )
            for artifact_index, reference in enumerate(execution.get("rawArtifactRefs", [])):
                _add_expected(
                    expected,
                    "raw-artifact",
                    reference,
                    f"{prefix}/rawArtifactRefs/{artifact_index}",
                )
    return expected


def validate_evaluation_semantics(
    loaded: list[tuple[Path, bytes, dict[str, Json]]],
) -> dict[Path, list[ValidationError]]:
    """Validate digest closure and fail-closed qualification integrity."""
    errors = {path: [] for path, _, _ in loaded}
    documents: dict[str, dict[str, Json]] = {}
    paths: dict[str, Path] = {}
    references: dict[str, dict[str, str]] = {}
    by_document_type: dict[str, list[tuple[Path, dict[str, Json]]]] = {}
    for path, raw, document in loaded:
        identifier = _document_id(document)
        if identifier is not None:
            documents[identifier] = document
            paths[identifier] = path
            references[identifier] = {
                "id": identifier,
                "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
            }
        document_type = document.get("documentType")
        if isinstance(document_type, str):
            by_document_type.setdefault(document_type, []).append((path, document))

    for path, _, document in loaded:
        if document.get("documentType") != "evaluation-input-binding":
            continue
        closure = document.get("closure")
        if isinstance(closure, dict):
            actual = closure_digest(closure)
            if document.get("closureDigest") != actual:
                errors[path].append(
                    _semantic(
                        ("closureDigest",),
                        f"must equal RFC 8785 closure digest {actual}",
                    )
                )
            manifest_ref = closure.get("inputManifest")
            manifest = (
                documents.get(manifest_ref.get("id")) if isinstance(manifest_ref, dict) else None
            )
            if isinstance(manifest, dict) and manifest.get("documentType") == (
                "evaluation-input-manifest"
            ):
                actual_manifest_ref = references.get(manifest["manifestId"])
                if not content_refs_match(manifest_ref, actual_manifest_ref):
                    errors[path].append(
                        _semantic(
                            ("closure", "inputManifest"),
                            "must exactly reference the supplied evaluation input manifest",
                        )
                    )
                for field in _MANIFEST_FIELDS:
                    if not content_refs_match(closure.get(field), manifest.get(field)):
                        errors[path].append(
                            _semantic(
                                ("closure", field),
                                f"must equal evaluation input manifest field {field!r}",
                            )
                        )

            for field, document_type in _CLOSURE_DOCUMENT_TYPES.items():
                matches = by_document_type.get(document_type, [])
                if len(matches) != 1:
                    continue
                _, supplied = matches[0]
                supplied_id = _document_id(supplied)
                actual_ref = references.get(supplied_id) if supplied_id is not None else None
                if not content_refs_match(closure.get(field), actual_ref):
                    errors[path].append(
                        _semantic(
                            ("closure", field),
                            f"must exactly reference the supplied {document_type}",
                        )
                    )

    for path, _, integrity in loaded:
        if integrity.get("documentType") != "qualification-integrity":
            continue
        binding_id = integrity.get("inputBindingRef", {}).get("id")
        assembly_id = integrity.get("runAssemblyRef", {}).get("id")
        binding = documents.get(binding_id)
        assembly = documents.get(assembly_id)
        if not isinstance(binding, dict) or not isinstance(assembly, dict):
            continue

        occurrences = _expected_checks(binding, assembly, documents)
        expected: dict[tuple[str, str], str] = {}
        conflicts: dict[tuple[str, str], list[_ExpectedOccurrence]] = {}
        for key, values in occurrences.items():
            digests = {value.digest for value in values}
            if len(digests) == 1:
                expected[key] = next(iter(digests))
            else:
                conflicts[key] = values
                detail = ", ".join(f"{value.provenance}={value.digest}" for value in values)
                errors[path].append(
                    _semantic(
                        ("checks",),
                        f"conflicting expected source occurrences for {key!r}: {detail}",
                    )
                )
        checks = integrity.get("checks", [])
        keys: list[tuple[str, str]] = []
        incomplete = False
        failed = bool(conflicts)
        for index, check in enumerate(checks):
            if not isinstance(check, dict):
                continue
            key = (check.get("component"), check.get("componentRef"))
            if not all(isinstance(item, str) for item in key):
                continue
            keys.append(key)
            expected_digest = expected.get(key)
            declared_expected = check.get("expectedDigest")
            actual_digest = check.get("actualDigest")
            status = check.get("status")
            if key in conflicts:
                errors[path].append(
                    _semantic(
                        ("checks", index, "expectedDigest"),
                        f"cannot select an expected digest for conflicting source {key!r}",
                    )
                )
                failed = True
            elif expected_digest is None:
                errors[path].append(
                    _semantic(("checks", index), f"unexpected integrity check {key!r}")
                )
                incomplete = True
            elif declared_expected != expected_digest:
                errors[path].append(
                    _semantic(
                        ("checks", index, "expectedDigest"),
                        f"must equal referenced digest {expected_digest}",
                    )
                )
                failed = True

            if status == "match" and actual_digest != declared_expected:
                errors[path].append(
                    _semantic(
                        ("checks", index, "actualDigest"),
                        "match requires actualDigest to equal expectedDigest",
                    )
                )
                failed = True
            elif status == "mismatch":
                if actual_digest is None or actual_digest == declared_expected:
                    errors[path].append(
                        _semantic(
                            ("checks", index, "actualDigest"),
                            "mismatch requires a non-null digest unequal to expectedDigest",
                        )
                    )
                failed = True
            elif status == "missing":
                if actual_digest is not None:
                    errors[path].append(
                        _semantic(
                            ("checks", index, "actualDigest"),
                            "missing requires a null actualDigest",
                        )
                    )
                incomplete = True

        duplicates = sorted(key for key, count in Counter(keys).items() if count > 1)
        if duplicates:
            errors[path].append(
                _semantic(("checks",), f"duplicate integrity checks: {duplicates!r}")
            )
            incomplete = True
        missing = sorted(set(occurrences) - set(keys))
        if missing:
            errors[path].append(
                _semantic(("checks",), f"required integrity checks are missing: {missing!r}")
            )
            incomplete = True

        computed_status = (
            "mismatched"
            if conflicts
            else "incomplete"
            if incomplete
            else "mismatched"
            if failed
            else "matched"
        )
        eligible = computed_status == "matched"
        if integrity.get("status") != computed_status:
            errors[path].append(
                _semantic(
                    ("status",),
                    f"must be {computed_status!r} for computed checks",
                )
            )
        if (integrity.get("qualificationDisposition") == "eligible") != eligible:
            errors[path].append(
                _semantic(
                    ("qualificationDisposition",),
                    f"must be {'eligible' if eligible else 'rejected'}",
                )
            )
    return errors
