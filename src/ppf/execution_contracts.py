"""Semantic validation for execution and repair sidecar documents."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import rfc8785

from .core import ValidationError, _document_id, _semantic

Json = Any


def invocation_id(case_ref: str, assessor_ref: str) -> str:
    """Return the stable identity for one case/assessor pairing."""
    payload = {"assessorRef": assessor_ref, "caseRef": case_ref}
    return "invoke-" + hashlib.sha256(rfc8785.dumps(payload)).hexdigest()


def semantic_projection_digest(document: dict[str, Json]) -> str:
    """Digest a semantic projection without its self-declared digest."""
    projected = {key: value for key, value in document.items() if key != "projectionDigest"}
    return "sha256:" + hashlib.sha256(rfc8785.dumps(projected)).hexdigest()


def _duplicates(values: list[str]) -> set[str]:
    seen: set[str] = set()
    return {value for value in values if value in seen or seen.add(value)}


def _invocation_errors(
    document: dict[str, Json],
    documents: dict[str, dict[str, Json]],
) -> list[ValidationError]:
    errors: list[ValidationError] = []
    invocations = document.get("invocations", [])
    pairs: list[tuple[str, str]] = []
    ids: list[str] = []
    sequences: list[int] = []
    for index, invocation in enumerate(invocations):
        if not isinstance(invocation, dict):
            continue
        case_ref = invocation.get("caseRef")
        assessor_ref = invocation.get("assessorRef")
        if not isinstance(case_ref, str) or not isinstance(assessor_ref, str):
            continue
        pair = (case_ref, assessor_ref)
        if pair in pairs:
            errors.append(
                _semantic(
                    ("invocations", index),
                    f"duplicate case/assessor pairing {pair!r}",
                )
            )
        pairs.append(pair)
        expected_id = invocation_id(case_ref, assessor_ref)
        if invocation.get("invocationId") != expected_id:
            errors.append(
                _semantic(
                    ("invocations", index, "invocationId"),
                    f"must equal deterministic invocation id {expected_id!r}",
                )
            )
        ids.append(str(invocation.get("invocationId")))
        sequences.append(int(invocation.get("sequence", 0)))

    duplicate_ids = sorted(_duplicates(ids))
    if duplicate_ids:
        errors.append(_semantic(("invocations",), f"duplicate invocation ids: {duplicate_ids!r}"))
    expected_sequences = list(range(10, 10 * (len(sequences) + 1), 10))
    if sequences != expected_sequences:
        errors.append(
            _semantic(
                ("invocations",),
                f"sequences must be the ordered series {expected_sequences!r}",
            )
        )

    plan = documents.get(document.get("planRef", {}).get("id"))
    if isinstance(plan, dict):
        cases = {
            case.get("id"): case
            for case in plan.get("cases", [])
            if isinstance(case, dict) and isinstance(case.get("id"), str)
        }
        for index, invocation in enumerate(invocations):
            if not isinstance(invocation, dict):
                continue
            case = cases.get(invocation.get("caseRef"))
            if case is None:
                errors.append(
                    _semantic(
                        ("invocations", index, "caseRef"),
                        f"unknown evaluation case {invocation.get('caseRef')!r}",
                    )
                )
            elif invocation.get("stageRef") != case.get("stage"):
                errors.append(
                    _semantic(
                        ("invocations", index, "stageRef"),
                        "must equal the linked evaluation case stage",
                    )
                )

    profile = documents.get(document.get("assessorProfileRef", {}).get("id"))
    if isinstance(profile, dict):
        assessors = {
            assessor.get("id"): assessor
            for assessor in profile.get("assessors", [])
            if isinstance(assessor, dict)
        }
        for index, invocation in enumerate(invocations):
            if not isinstance(invocation, dict):
                continue
            assessor = assessors.get(invocation.get("assessorRef"))
            if assessor is None:
                errors.append(
                    _semantic(
                        ("invocations", index, "assessorRef"),
                        f"unknown assessor {invocation.get('assessorRef')!r}",
                    )
                )
                continue
            for invocation_field, assessor_field in (
                ("assessorKind", "kind"),
                ("executableRef", "executableRef"),
            ):
                if invocation.get(invocation_field) != assessor.get(assessor_field):
                    errors.append(
                        _semantic(
                            ("invocations", index, invocation_field),
                            f"must equal assessor {assessor_field}",
                        )
                    )
    return errors


def _tool_environment_errors(document: dict[str, Json]) -> list[ValidationError]:
    errors: list[ValidationError] = []
    distributions = document.get("distributions", [])
    distribution_ids = [
        item.get("id") for item in distributions if isinstance(item, dict)
    ]
    duplicate_distributions = sorted(_duplicates(distribution_ids))
    if duplicate_distributions:
        errors.append(
            _semantic(
                ("distributions",),
                f"duplicate distribution ids: {duplicate_distributions!r}",
            )
        )
    known = set(distribution_ids)
    for index, distribution in enumerate(distributions):
        if not isinstance(distribution, dict):
            continue
        dependencies = distribution.get("dependencyRefs", [])
        duplicates = sorted(_duplicates(dependencies))
        if duplicates:
            errors.append(
                _semantic(
                    ("distributions", index, "dependencyRefs"),
                    f"duplicate dependency references: {duplicates!r}",
                )
            )
        for offset, dependency in enumerate(dependencies):
            if dependency not in known:
                errors.append(
                    _semantic(
                        ("distributions", index, "dependencyRefs", offset),
                        f"unknown distribution {dependency!r}",
                    )
                )

    entrypoints = document.get("entrypoints", [])
    entrypoint_ids = [item.get("id") for item in entrypoints if isinstance(item, dict)]
    duplicate_entrypoints = sorted(_duplicates(entrypoint_ids))
    if duplicate_entrypoints:
        errors.append(
            _semantic(
                ("entrypoints",),
                f"duplicate entrypoint ids: {duplicate_entrypoints!r}",
            )
        )
    entrypoint_index = {
        item.get("id"): item for item in entrypoints if isinstance(item, dict)
    }
    for index, entrypoint in enumerate(entrypoints):
        if not isinstance(entrypoint, dict):
            continue
        if entrypoint.get("distributionRef") not in known:
            errors.append(
                _semantic(
                    ("entrypoints", index, "distributionRef"),
                    f"unknown distribution {entrypoint.get('distributionRef')!r}",
                )
            )
        module = entrypoint.get("module")
        relative = entrypoint.get("relativeExecutable")
        if (module is None) == (relative is None):
            errors.append(
                _semantic(
                    ("entrypoints", index),
                    "exactly one of module or relativeExecutable must be non-null",
                )
            )

    ansible = document.get("ansible")
    if isinstance(ansible, dict):
        for field in ("runnerDistributionRef", "coreDistributionRef"):
            if ansible.get(field) not in known:
                errors.append(
                    _semantic(
                        ("ansible", field),
                        f"unknown distribution {ansible.get(field)!r}",
                    )
                )
        if ansible.get("playbookEntrypointRef") not in entrypoint_index:
            errors.append(
                _semantic(
                    ("ansible", "playbookEntrypointRef"),
                    "unknown playbook entrypoint",
                )
            )
    return errors


def _repair_errors(document: dict[str, Json]) -> list[ValidationError]:
    errors: list[ValidationError] = []
    permitted = document.get("permittedPaths", [])
    forbidden = document.get("forbiddenPaths", [])
    overlap = sorted(set(permitted) & set(forbidden))
    if overlap:
        errors.append(
            _semantic(
                ("forbiddenPaths",),
                f"paths cannot be both permitted and forbidden: {overlap!r}",
            )
        )
    if document.get("decision") == "repair" and document.get("remainingCycles", 0) < 1:
        errors.append(
            _semantic(
                ("remainingCycles",),
                "repair requires at least one remaining cycle",
            )
        )
    return errors


def _environment_profile_errors(document: dict[str, Json]) -> list[ValidationError]:
    forbidden = {
        "ANSIBLE_CONFIG",
        "ANSIBLE_COLLECTIONS_PATH",
        "ANSIBLE_COLLECTIONS_PATHS",
        "ANSIBLE_INVENTORY_PLUGINS",
        "ANSIBLE_LIBRARY",
        "ANSIBLE_LOOKUP_PLUGINS",
        "ANSIBLE_ROLES_PATH",
        "PYTHONHOME",
        "PYTHONPATH",
    }
    present = sorted(forbidden & set(document.get("variables", {})))
    if not present:
        return []
    return [
        _semantic(
            ("variables",),
            f"tool and plugin search-path injection is forbidden: {present!r}",
        )
    ]


def validate_execution_semantics(
    loaded: list[tuple[Path, bytes, dict[str, Json]]],
) -> dict[Path, list[ValidationError]]:
    """Validate execution sidecar identities, relationships, and derived fields."""
    errors = {path: [] for path, _, _ in loaded}
    documents = {
        identifier: document
        for _, _, document in loaded
        if (identifier := _document_id(document)) is not None
    }
    for path, _, document in loaded:
        document_type = document.get("documentType")
        if document_type == "evaluation-invocation-set":
            errors[path].extend(_invocation_errors(document, documents))
        elif document_type == "tool-environment-manifest":
            errors[path].extend(_tool_environment_errors(document))
        elif document_type == "artifact-manifest":
            names = [
                item.get("logicalName")
                for item in document.get("artifacts", [])
                if isinstance(item, dict)
            ]
            duplicates = sorted(_duplicates(names))
            if duplicates:
                errors[path].append(
                    _semantic(("artifacts",), f"duplicate logical names: {duplicates!r}")
                )
        elif document_type == "evaluation-semantic-projection":
            actual = semantic_projection_digest(document)
            if document.get("projectionDigest") != actual:
                errors[path].append(
                    _semantic(
                        ("projectionDigest",),
                        f"must equal canonical semantic projection digest {actual}",
                    )
                )
        elif document_type == "repair-decision":
            errors[path].extend(_repair_errors(document))
        elif document_type == "environment-profile":
            errors[path].extend(_environment_profile_errors(document))
    return errors
