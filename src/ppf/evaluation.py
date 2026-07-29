"""Semantic validation for the evaluation-workflow sidecar."""

from __future__ import annotations

from collections import Counter
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


def closure_digest(closure: dict[str, Json]) -> str:
    """Return the normative RFC 8785 SHA-256 digest for an input closure."""
    import hashlib

    return "sha256:" + hashlib.sha256(rfc8785.dumps(closure)).hexdigest()


def _add_expected(
    expected: dict[tuple[str, str], str],
    component: str,
    reference: Json,
) -> None:
    if not isinstance(reference, dict):
        return
    identifier = reference.get("id")
    digest = reference.get("digest")
    if isinstance(identifier, str) and isinstance(digest, str):
        expected[(component, identifier)] = digest


def _expected_checks(
    binding: dict[str, Json],
    assembly: dict[str, Json],
    documents: dict[str, dict[str, Json]],
) -> dict[tuple[str, str], str]:
    expected: dict[tuple[str, str], str] = {}
    closure = binding.get("closure", {})
    if isinstance(closure, dict):
        for field, component in _CLOSURE_COMPONENTS.items():
            _add_expected(expected, component, closure.get(field))

    _add_expected(expected, "assembler", assembly.get("assemblerRef"))
    for reference in assembly.get("rawArtifactRefs", []):
        _add_expected(expected, "raw-artifact", reference)

    for fragment_binding in assembly.get("fragmentBindings", []):
        if not isinstance(fragment_binding, dict):
            continue
        envelope_ref = fragment_binding.get("producerEnvelopeRef", {})
        envelope = documents.get(envelope_ref.get("id"))
        if not isinstance(envelope, dict):
            continue
        _add_expected(expected, "producer", envelope.get("producerRef"))
        for execution in envelope.get("executions", []):
            if not isinstance(execution, dict):
                continue
            _add_expected(expected, "invocation", execution.get("invocationRef"))
            for reference in execution.get("rawArtifactRefs", []):
                _add_expected(expected, "raw-artifact", reference)
    return expected


def validate_evaluation_semantics(
    loaded: list[tuple[Path, bytes, dict[str, Json]]],
) -> dict[Path, list[ValidationError]]:
    """Validate digest closure and fail-closed qualification integrity."""
    errors = {path: [] for path, _, _ in loaded}
    documents: dict[str, dict[str, Json]] = {}
    paths: dict[str, Path] = {}
    for path, _, document in loaded:
        identifier = _document_id(document)
        if identifier is not None:
            documents[identifier] = document
            paths[identifier] = path

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

    for path, _, integrity in loaded:
        if integrity.get("documentType") != "qualification-integrity":
            continue
        binding_id = integrity.get("inputBindingRef", {}).get("id")
        assembly_id = integrity.get("runAssemblyRef", {}).get("id")
        binding = documents.get(binding_id)
        assembly = documents.get(assembly_id)
        if not isinstance(binding, dict) or not isinstance(assembly, dict):
            continue

        expected = _expected_checks(binding, assembly, documents)
        checks = integrity.get("checks", [])
        keys: list[tuple[str, str]] = []
        incomplete = False
        failed = False
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
            if expected_digest is None:
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
        missing = sorted(set(expected) - set(keys))
        if missing:
            errors[path].append(
                _semantic(("checks",), f"required integrity checks are missing: {missing!r}")
            )
            incomplete = True

        computed_status = "incomplete" if incomplete else "mismatched" if failed else "matched"
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
