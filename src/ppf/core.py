"""Validate Python Policy PPF documents without third-party dependencies."""

from __future__ import annotations

import hashlib
import re
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

Json = Any
PathParts = tuple[str | int, ...]

AUTHORITY_CLASSES = {
    "canonical-specification",
    "versioned-rationale",
    "project-policy",
    "advisory-reference",
    "diagnostic-documentation",
}
DOCUMENT_IDS = {
    "counterexample": "counterexampleId",
    "evaluation-input-manifest": "manifestId",
    "evaluation-plan": "planId",
    "evaluation-run": "runId",
    "evaluation-run-fragment": "fragmentId",
    "generation-policy-profile": "profileId",
    "qualification-report": "reportId",
    "regression-fixture": ("fixture", "id"),
    "stage-registry": "registryId",
    "toolchain-lock": "lockId",
    "evaluation-evidence-catalog": "catalogId",
    "evaluation-input-binding": "bindingId",
    "evaluation-producer-envelope": "envelopeId",
    "evaluation-run-assembly": "assemblyId",
    "evaluation-workflow": "workflowId",
    "evidence-admission-derivation": "derivationId",
    "qualification-integrity": "integrityId",
    "shaping-policy": "policyId",
    "shaping-profile-registry": "registryId",
    "shaping-implementation-binding": "bindingId",
    "shaping-decision-record": "decisionId",
    "capability-provider-registry": "registryId",
    "dependency-wiring-plan": "planId",
    "capability-assembly-record": "recordId",
    "qualification-fixture-projection": "projectionId",
    "schema-conformance-policy": "policyId",
    "projection-conformance-report": "reportId",
    "generated-fixture-run": "runId",
}
RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


@dataclass(frozen=True)
class ValidationError:
    """Stable structural, semantic, or input validation error."""

    path: PathParts
    message: str
    kind: str

    def as_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "path": _format_path(self.path),
            "message": self.message,
        }


def _format_path(path: PathParts) -> str:
    if not path:
        return "/"
    escaped = (str(part).replace("~", "~0").replace("/", "~1") for part in path)
    return "/" + "/".join(escaped)


def _valid_datetime(value: str) -> bool:
    if not RFC3339.fullmatch(value):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _semantic(path: PathParts, message: str) -> ValidationError:
    return ValidationError(path, message, "semantic")


def _unique_ids(
    values: list[Json],
    path: PathParts,
    field: str = "id",
) -> tuple[dict[str, dict[str, Json]], list[ValidationError]]:
    index: dict[str, dict[str, Json]] = {}
    errors: list[ValidationError] = []
    for offset, value in enumerate(values):
        if not isinstance(value, dict) or not isinstance(value.get(field), str):
            continue
        identifier = value[field]
        if identifier in index:
            errors.append(_semantic((*path, offset, field), f"duplicate id {identifier!r}"))
        else:
            index[identifier] = value
    return index, errors


def _nonzero_digests(value: Json, path: PathParts = ()) -> list[ValidationError]:
    errors: list[ValidationError] = []
    if isinstance(value, dict):
        for name, item in value.items():
            child_path = (*path, name)
            if (
                name.lower().endswith("digest")
                and isinstance(item, str)
                and item.startswith("sha256:")
                and set(item.removeprefix("sha256:")) == {"0"}
            ):
                errors.append(_semantic(child_path, "placeholder all-zero digest is forbidden"))
            errors.extend(_nonzero_digests(item, child_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            errors.extend(_nonzero_digests(item, (*path, index)))
    return errors


def _parse_datetime(value: Json) -> datetime | None:
    if not isinstance(value, str) or not _valid_datetime(value):
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _profile_semantics(document: dict[str, Json]) -> list[ValidationError]:
    errors: list[ValidationError] = []
    authorities, duplicate_errors = _unique_ids(
        document.get("authoritySources", []), ("authoritySources",)
    )
    errors.extend(duplicate_errors)
    claims, duplicate_errors = _unique_ids(document.get("claims", []), ("claims",))
    errors.extend(duplicate_errors)
    gates, duplicate_errors = _unique_ids(document.get("gates", []), ("gates",))
    errors.extend(duplicate_errors)

    precedence = document.get("authorityPrecedence", [])
    if set(precedence) != AUTHORITY_CLASSES or len(precedence) != len(AUTHORITY_CLASSES):
        errors.append(
            _semantic(
                ("authorityPrecedence",),
                "must contain every authority class exactly once",
            )
        )

    authority_classes = {
        identifier: source.get("authorityClass") for identifier, source in authorities.items()
    }
    for index, claim in enumerate(document.get("claims", [])):
        claim_id = claim.get("id")
        refs = claim.get("authorityRefs", [])
        for ref_index, reference in enumerate(refs):
            if reference not in authorities:
                errors.append(
                    _semantic(
                        ("claims", index, "authorityRefs", ref_index),
                        f"unknown authority source {reference!r}",
                    )
                )
        if not any(
            authority_classes.get(reference) in {"canonical-specification", "project-policy"}
            for reference in refs
        ):
            errors.append(
                _semantic(
                    ("claims", index, "authorityRefs"),
                    "a policy claim requires canonical or project-policy authority",
                )
            )
        obligation = claim.get("obligation", {})
        if obligation.get("level") == "conditional" and obligation.get("conditionRef") is None:
            errors.append(
                _semantic(
                    ("claims", index, "obligation", "conditionRef"),
                    "conditional policy requires a conditionRef",
                )
            )
        for assessment_index, assessment in enumerate(claim.get("assessedBy", [])):
            gate_ref = assessment.get("gateRef")
            if gate_ref not in gates:
                errors.append(
                    _semantic(
                        ("claims", index, "assessedBy", assessment_index, "gateRef"),
                        f"unknown gate {gate_ref!r}",
                    )
                )
            elif claim_id not in gates[gate_ref].get("assessedClaimRefs", []):
                errors.append(
                    _semantic(
                        ("claims", index, "assessedBy", assessment_index, "gateRef"),
                        "gate does not declare this claim in assessedClaimRefs",
                    )
                )

    for index, gate in enumerate(document.get("gates", [])):
        if not gate.get("command"):
            errors.append(_semantic(("gates", index, "command"), "command must not be empty"))
        assessed_refs = gate.get("assessedClaimRefs", [])
        if not assessed_refs:
            errors.append(
                _semantic(
                    ("gates", index, "assessedClaimRefs"),
                    "gate must assess at least one claim",
                )
            )
        for ref_index, reference in enumerate(assessed_refs):
            if reference not in claims:
                errors.append(
                    _semantic(
                        ("gates", index, "assessedClaimRefs", ref_index),
                        f"unknown claim {reference!r}",
                    )
                )
    return errors


def _plan_semantics(document: dict[str, Json]) -> list[ValidationError]:
    cases = document.get("cases", [])
    _, errors = _unique_ids(cases, ("cases",))
    for index, case in enumerate(cases):
        claim_ref = case.get("claimRef")
        fixture_claims = case.get("fixture", {}).get("claimRefs", [])
        if claim_ref not in fixture_claims:
            errors.append(
                _semantic(
                    ("cases", index, "fixture", "claimRefs"),
                    "fixture must reference the evaluation case claim",
                )
            )
        if not case.get("oracleRefs"):
            errors.append(
                _semantic(("cases", index, "oracleRefs"), "at least one oracle is required")
            )
    return errors


def _run_semantics(document: dict[str, Json]) -> list[ValidationError]:
    errors: list[ValidationError] = []
    executions, duplicate_errors = _unique_ids(document.get("executions", []), ("executions",))
    errors.extend(duplicate_errors)
    observations, duplicate_errors = _unique_ids(
        document.get("observations", []), ("observations",)
    )
    errors.extend(duplicate_errors)
    oracle_results, duplicate_errors = _unique_ids(
        document.get("oracleResults", []), ("oracleResults",)
    )
    errors.extend(duplicate_errors)
    _fragments, duplicate_errors = _unique_ids(
        document.get("fragments", []), ("fragments",), "fragmentId"
    )
    errors.extend(duplicate_errors)

    started = _parse_datetime(document.get("startedAt"))
    completed = _parse_datetime(document.get("completedAt"))
    if started is not None and completed is not None and completed < started:
        errors.append(_semantic(("completedAt",), "completedAt must not precede startedAt"))

    for index, observation in enumerate(document.get("observations", [])):
        if observation.get("executionRef") not in executions:
            errors.append(
                _semantic(
                    ("observations", index, "executionRef"),
                    f"unknown execution {observation.get('executionRef')!r}",
                )
            )
        if observation.get("status") == "skipped" and not observation.get("skipReason"):
            errors.append(
                _semantic(
                    ("observations", index, "skipReason"),
                    "skipped observation requires a skipReason",
                )
            )

    for index, result in enumerate(document.get("oracleResults", [])):
        for ref_index, reference in enumerate(result.get("observationRefs", [])):
            if reference not in observations:
                errors.append(
                    _semantic(
                        ("oracleResults", index, "observationRefs", ref_index),
                        f"unknown observation {reference!r}",
                    )
                )

    for index, fragment in enumerate(document.get("fragments", [])):
        for name, known in (
            ("executionRefs", executions),
            ("observationRefs", observations),
            ("oracleResultRefs", oracle_results),
        ):
            for ref_index, reference in enumerate(fragment.get(name, [])):
                if reference not in known:
                    errors.append(
                        _semantic(
                            ("fragments", index, name, ref_index),
                            f"unknown {name.removesuffix('Refs')} {reference!r}",
                        )
                    )
    return errors


def _report_semantics(document: dict[str, Json]) -> list[ValidationError]:
    errors: list[ValidationError] = []
    admissions, duplicate_errors = _unique_ids(document.get("admissions", []), ("admissions",))
    errors.extend(duplicate_errors)
    _verdicts, duplicate_errors = _unique_ids(document.get("itemVerdicts", []), ("itemVerdicts",))
    errors.extend(duplicate_errors)

    for index, admission in enumerate(document.get("admissions", [])):
        admitted = admission.get("admitted")
        rejection_reason = admission.get("rejectionReason")
        if admitted and rejection_reason is not None:
            errors.append(
                _semantic(
                    ("admissions", index, "rejectionReason"),
                    "admitted evidence cannot have a rejectionReason",
                )
            )
        if admitted and admission.get("assignedReliability") == "R0":
            errors.append(
                _semantic(
                    ("admissions", index, "assignedReliability"),
                    "R0 evidence cannot be admitted",
                )
            )
        if not admitted and not rejection_reason:
            errors.append(
                _semantic(
                    ("admissions", index, "rejectionReason"),
                    "rejected evidence requires a rejectionReason",
                )
            )

    counts = Counter()
    report_time = _parse_datetime(document.get("generatedAt"))
    for index, item in enumerate(document.get("itemVerdicts", [])):
        verdict = item.get("verdict")
        underlying = item.get("underlyingVerdict")
        waiver = item.get("waiver")
        counts[verdict] += 1
        admitted_refs = set(item.get("admittedEvidenceRefs", []))
        rejected_refs = set(item.get("rejectedEvidenceRefs", []))
        overlap = admitted_refs & rejected_refs
        if overlap:
            errors.append(
                _semantic(
                    ("itemVerdicts", index),
                    f"evidence cannot be both admitted and rejected: {sorted(overlap)!r}",
                )
            )
        for name, references in (
            ("admittedEvidenceRefs", admitted_refs),
            ("rejectedEvidenceRefs", rejected_refs),
        ):
            for reference in references:
                if reference not in admissions:
                    errors.append(
                        _semantic(
                            ("itemVerdicts", index, name),
                            f"unknown evidence admission {reference!r}",
                        )
                    )
        if verdict == "waived":
            if underlying != "fail":
                errors.append(
                    _semantic(
                        ("itemVerdicts", index, "underlyingVerdict"),
                        "waived verdict requires underlyingVerdict 'fail'",
                    )
                )
            if not isinstance(waiver, dict):
                errors.append(
                    _semantic(
                        ("itemVerdicts", index, "waiver"),
                        "waived verdict requires a waiver",
                    )
                )
            else:
                if item.get("itemRef") not in waiver.get("scope", []):
                    errors.append(
                        _semantic(
                            ("itemVerdicts", index, "waiver", "scope"),
                            "waiver scope must include the itemRef",
                        )
                    )
                expiry = _parse_datetime(waiver.get("expiresAt"))
                if report_time is not None and expiry is not None and expiry <= report_time:
                    errors.append(
                        _semantic(
                            ("itemVerdicts", index, "waiver", "expiresAt"),
                            "waiver must be active when the report is generated",
                        )
                    )
        elif underlying != verdict:
            errors.append(
                _semantic(
                    ("itemVerdicts", index, "underlyingVerdict"),
                    "underlyingVerdict must equal a non-waived verdict",
                )
            )
        if verdict == "pass" and item.get("missingEvidence"):
            errors.append(
                _semantic(
                    ("itemVerdicts", index, "missingEvidence"),
                    "pass cannot contain missing evidence",
                )
            )

    expected = {
        "passed": counts["pass"],
        "failed": counts["fail"],
        "inconclusive": counts["inconclusive"],
        "notApplicable": counts["not-applicable"],
        "waived": counts["waived"],
    }
    if document.get("summary") != expected:
        errors.append(_semantic(("summary",), f"summary must equal computed counts {expected!r}"))
    return errors


def _stage_semantics(document: dict[str, Json]) -> list[ValidationError]:
    stages, errors = _unique_ids(document.get("stages", []), ("stages",))
    for index, stage in enumerate(document.get("stages", [])):
        for dependency_index, dependency in enumerate(stage.get("dependsOn", [])):
            if dependency not in stages:
                errors.append(
                    _semantic(
                        ("stages", index, "dependsOn", dependency_index),
                        f"unknown stage {dependency!r}",
                    )
                )

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(identifier: str) -> None:
        if identifier in visiting:
            errors.append(_semantic(("stages",), f"stage dependency cycle at {identifier!r}"))
            return
        if identifier in visited or identifier not in stages:
            return
        visiting.add(identifier)
        for dependency in stages[identifier].get("dependsOn", []):
            visit(dependency)
        visiting.remove(identifier)
        visited.add(identifier)

    for identifier in stages:
        visit(identifier)
    for name, members in document.get("groups", {}).items():
        for index, member in enumerate(members):
            if member not in stages:
                errors.append(_semantic(("groups", name, index), f"unknown stage {member!r}"))
    return errors


def _toolchain_semantics(document: dict[str, Json]) -> list[ValidationError]:
    values = [document.get("python"), *document.get("tools", [])]
    _, errors = _unique_ids([item for item in values if isinstance(item, dict)], ("tools",))
    return errors


def validate_semantics(document: dict[str, Json]) -> list[ValidationError]:
    errors = _nonzero_digests(document)
    document_type = document.get("documentType")
    if document_type == "generation-policy-profile":
        errors.extend(_profile_semantics(document))
    elif document_type == "evaluation-plan":
        errors.extend(_plan_semantics(document))
    elif document_type == "evaluation-run":
        errors.extend(_run_semantics(document))
    elif document_type == "qualification-report":
        errors.extend(_report_semantics(document))
    elif document_type == "stage-registry":
        errors.extend(_stage_semantics(document))
    elif document_type == "toolchain-lock":
        errors.extend(_toolchain_semantics(document))
    elif document_type == "counterexample" and not document.get("replayInvocation"):
        errors.append(_semantic(("replayInvocation",), "counterexample must be replayable"))
    elif document_type == "regression-fixture" and not document.get("fixture", {}).get("claimRefs"):
        errors.append(
            _semantic(
                ("fixture", "claimRefs"),
                "regression fixture must reference at least one claim",
            )
        )
    return errors


def _document_id(document: dict[str, Json]) -> str | None:
    selector = DOCUMENT_IDS.get(document.get("documentType"))
    if isinstance(selector, str):
        value = document.get(selector)
        return value if isinstance(value, str) else None
    if isinstance(selector, tuple):
        value: Json = document
        for part in selector:
            if not isinstance(value, dict):
                return None
            value = value.get(part)
        return value if isinstance(value, str) else None
    return None


def _content_refs(value: Json, path: PathParts = ()) -> list[tuple[PathParts, dict[str, Json]]]:
    refs: list[tuple[PathParts, dict[str, Json]]] = []
    if isinstance(value, dict):
        if (
            isinstance(value.get("id"), str)
            and isinstance(value.get("digest"), str)
            and set(value).issubset({"id", "digest", "uri", "mediaType", "selected"})
        ):
            refs.append((path, value))
        for name, item in value.items():
            refs.extend(_content_refs(item, (*path, name)))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            refs.extend(_content_refs(item, (*path, index)))
    return refs


def _value_at(document: dict[str, Json], path: PathParts) -> Json:
    value: Json = document
    for part in path:
        if not isinstance(value, (dict, list)):
            return None
        if isinstance(part, int):
            if not isinstance(value, list) or part >= len(value):
                return None
            value = value[part]
        else:
            if not isinstance(value, dict):
                return None
            value = value.get(part)
    return value


def _internal_content_refs(
    document: dict[str, Json],
) -> list[tuple[PathParts, dict[str, Json]]]:
    """Return references whose target is another PPF document in the same bundle."""
    document_type = document.get("documentType")
    fixed: dict[str, tuple[PathParts, ...]] = {
        "evaluation-input-manifest": (
            ("plan",),
            ("profile",),
            ("toolchain",),
        ),
        "evaluation-plan": (("profileRef",), ("toolchainRef",)),
        "evaluation-run": (("inputManifest",),),
        "qualification-report": (("profileRef",), ("runRef",)),
        "regression-fixture": (("admittedByReportRef",), ("promotedFrom",)),
        "evaluation-evidence-catalog": (("profileRef",),),
        "evaluation-producer-envelope": (("inputBindingRef",),),
        "evaluation-run-assembly": (("inputBindingRef",), ("runRef",)),
        "evaluation-workflow": (("inputBindingRef",),),
        "evidence-admission-derivation": (
            ("catalogRef",),
            ("qualificationReportRef",),
        ),
        "qualification-integrity": (
            ("inputBindingRef",),
            ("qualificationReportRef",),
            ("runAssemblyRef",),
        ),
        "implementation-policy-extension": (("profileRef",),),
        "shaping-policy": (("registryRef",),),
        "shaping-implementation-binding": (
            ("policyRef",),
            ("registryRef",),
        ),
        "shaping-decision-record": (
            ("subjectRef",),
            ("policyRef",),
            ("registryRef",),
            ("bindingRef",),
        ),
        "capability-provider-registry": (("implementationBindingRef",),),
        "dependency-wiring-plan": (("providerRegistryRef",),),
        "capability-assembly-record": (
            ("implementationBindingRef",),
            ("providerRegistryRef",),
            ("wiringPlanRef",),
        ),
        "qualification-fixture-projection": (
            ("implementationBindingRef",),
            ("providerRegistryRef",),
            ("wiringPlanRef",),
        ),
        "schema-conformance-policy": (
            ("profileRef",),
            ("implementationPolicyRef",),
        ),
        "projection-conformance-report": (("policyRef",),),
        "generated-fixture-run": (("policyRef",),),
    }
    paths = list(fixed.get(str(document_type), ()))

    if document_type == "evaluation-input-binding":
        paths.extend(
            ("closure", name)
            for name in (
                "catalog",
                "inputManifest",
                "plan",
                "profile",
                "stageRegistry",
                "toolchain",
            )
        )
    elif document_type == "qualification-report":
        paths.extend(
            ("selectedOptionalProfiles", index)
            for index, _ in enumerate(document.get("selectedOptionalProfiles", []))
        )
    elif document_type == "evaluation-workflow":
        baseline = document.get("baseline")
        if isinstance(baseline, dict):
            paths.append(("baseline", "iteration", "runAssemblyRef"))
        paths.extend(
            ("implementationIterations", index, "runAssemblyRef")
            for index, _ in enumerate(document.get("implementationIterations", []))
        )
        if isinstance(document.get("qualificationIteration"), dict):
            paths.append(("qualificationIteration", "runAssemblyRef"))
    elif document_type == "evaluation-run-assembly":
        paths.extend(
            ("fragmentBindings", index, "producerEnvelopeRef")
            for index, _ in enumerate(document.get("fragmentBindings", []))
        )

    result: list[tuple[PathParts, dict[str, Json]]] = []
    for path in paths:
        value = _value_at(document, path)
        if isinstance(value, dict) and isinstance(value.get("id"), str):
            result.append((path, value))
    return result


def validate_bundle(
    loaded: list[tuple[Path, bytes, dict[str, Json]]],
) -> dict[Path, list[ValidationError]]:
    errors = {path: [] for path, _, _ in loaded}
    index: dict[str, tuple[Path, str, dict[str, Json]]] = {}
    for path, raw, document in loaded:
        identifier = _document_id(document)
        if identifier is None:
            continue
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        if identifier in index:
            errors[path].append(_semantic((), f"duplicate document id {identifier!r}"))
        else:
            index[identifier] = (path, digest, document)

    for path, _, document in loaded:
        internal_refs = {
            ref_path: reference for ref_path, reference in _internal_content_refs(document)
        }
        for ref_path, reference in _content_refs(document):
            target = index.get(reference["id"])
            if target is None and ref_path in internal_refs:
                errors[path].append(
                    _semantic(
                        ref_path,
                        f"required PPF document {reference['id']!r} is absent from bundle",
                    )
                )
            elif target is None and not reference.get("uri"):
                errors[path].append(
                    _semantic(
                        ref_path,
                        "unresolved external content reference requires a uri",
                    )
                )
            elif target is not None and reference["digest"] != target[1]:
                errors[path].append(
                    _semantic(
                        (*ref_path, "digest"),
                        f"digest does not match supplied document {reference['id']!r}",
                    )
                )

        if document.get("documentType") == "evaluation-plan":
            profile_target = index.get(document.get("profileRef", {}).get("id"))
            if profile_target is not None:
                claims = {claim.get("id") for claim in profile_target[2].get("claims", [])}
                for case_index, case in enumerate(document.get("cases", [])):
                    if case.get("claimRef") not in claims:
                        errors[path].append(
                            _semantic(
                                ("cases", case_index, "claimRef"),
                                "claim is absent from profile "
                                f"{profile_target[2].get('profileId')!r}",
                            )
                        )

            toolchain_target = index.get(document.get("toolchainRef", {}).get("id"))
            if profile_target is not None and toolchain_target is not None:
                tools = {
                    tool.get("id")
                    for tool in [
                        toolchain_target[2].get("python"),
                        *toolchain_target[2].get("tools", []),
                    ]
                    if isinstance(tool, dict)
                }
                for gate_index, gate in enumerate(profile_target[2].get("gates", [])):
                    if gate.get("toolRef") not in tools:
                        errors[profile_target[0]].append(
                            _semantic(
                                ("gates", gate_index, "toolRef"),
                                "tool is absent from toolchain "
                                f"{toolchain_target[2].get('lockId')!r}",
                            )
                        )
    return errors


def _expand_inputs(paths: list[Path]) -> list[Path]:
    expanded: set[Path] = set()
    for path in paths:
        if path.is_dir():
            expanded.update(path.rglob("*.json"))
        else:
            expanded.add(path)
    return sorted(expanded, key=str)


def main() -> int:
    """Delegate the legacy module entrypoint to the shared Cyclopts app."""
    from .cli import main as cli_main

    return cli_main()


if __name__ == "__main__":
    sys.exit(main())
