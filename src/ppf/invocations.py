"""Deterministic compilation of evaluation cases into execution invocations."""

from __future__ import annotations

from collections import defaultdict
from heapq import heapify, heappop, heappush
from typing import Any

from .execution_contracts import invocation_id

Json = Any


class InvocationCompilationError(ValueError):
    """Raised when plans cannot be deterministically compiled."""


def stable_stage_order(stage_registry: dict[str, Json]) -> list[str]:
    """Return Kahn topological order with declaration-index and lexical ties."""
    stages = stage_registry["stages"]
    index = {stage["id"]: offset for offset, stage in enumerate(stages)}
    if len(index) != len(stages):
        raise InvocationCompilationError("duplicate stage identifiers")
    incoming = {
        stage["id"]: set(stage.get("dependsOn", []))
        for stage in stages
    }
    outgoing: dict[str, set[str]] = defaultdict(set)
    for stage_id, dependencies in incoming.items():
        for dependency in dependencies:
            if dependency not in index:
                raise InvocationCompilationError(
                    f"stage {stage_id!r} has unknown dependency {dependency!r}"
                )
            outgoing[dependency].add(stage_id)
    ready = [(index[stage_id], stage_id) for stage_id, edges in incoming.items() if not edges]
    heapify(ready)
    ordered: list[str] = []
    while ready:
        _, stage_id = heappop(ready)
        ordered.append(stage_id)
        for dependent in sorted(outgoing[stage_id]):
            incoming[dependent].remove(stage_id)
            if not incoming[dependent]:
                heappush(ready, (index[dependent], dependent))
    if len(ordered) != len(stages):
        raise InvocationCompilationError("stage dependency graph contains a cycle")
    return ordered


def compile_invocation_set(
    *,
    invocation_set_id: str,
    plan: dict[str, Json],
    plan_ref: dict[str, Json],
    stage_registry: dict[str, Json],
    stage_registry_ref: dict[str, Json],
    assessor_profile: dict[str, Json],
    assessor_profile_ref: dict[str, Json],
    repository_ref: dict[str, Json],
    environment_ref: str,
    sandbox_ref: str,
) -> dict[str, Json]:
    """Compile a stable, closed invocation-set sidecar."""
    stage_rank = {
        stage_id: rank
        for rank, stage_id in enumerate(stable_stage_order(stage_registry))
    }
    assessor_rank = {
        assessor["id"]: rank
        for rank, assessor in enumerate(assessor_profile["assessors"])
    }
    candidates: list[tuple[int, int, int, dict[str, Json], dict[str, Json]]] = []
    pairs: set[tuple[str, str]] = set()
    for case_index, case in enumerate(plan["cases"]):
        probe_ref = case["probe"]["probeRef"]
        matched = [
            assessor
            for assessor in assessor_profile["assessors"]
            if probe_ref in assessor["probeRefs"]
        ]
        if not matched:
            raise InvocationCompilationError(
                f"no assessor is declared for probe {probe_ref!r}"
            )
        for assessor in matched:
            pair = (case["id"], assessor["id"])
            if pair in pairs:
                raise InvocationCompilationError(
                    f"duplicate case/assessor pairing {pair!r}"
                )
            pairs.add(pair)
            candidates.append(
                (
                    stage_rank[case["stage"]],
                    case_index,
                    assessor_rank[assessor["id"]],
                    case,
                    assessor,
                )
            )
    candidates.sort(key=lambda item: item[:3])
    invocations: list[dict[str, Json]] = []
    generated_ids: set[str] = set()
    for ordinal, (_, _, _, case, assessor) in enumerate(candidates, start=1):
        generated_id = invocation_id(case["id"], assessor["id"])
        if generated_id in generated_ids:
            raise InvocationCompilationError(
                f"invocation identity collision {generated_id!r}"
            )
        generated_ids.add(generated_id)
        configuration = case["probe"].get("configuration", {})
        argv = configuration.get("argv")
        if not isinstance(argv, list) or not argv:
            raise InvocationCompilationError(
                f"case {case['id']!r} probe configuration requires argv"
            )
        invocations.append(
            {
                "invocationId": generated_id,
                "sequence": ordinal * 10,
                "caseRef": case["id"],
                "stageRef": case["stage"],
                "assessorRef": assessor["id"],
                "assessorKind": assessor["kind"],
                "executableRef": assessor["executableRef"],
                "argv": argv,
                "workingDirectoryRef": configuration.get(
                    "workingDirectoryRef", "repository-root"
                ),
                "environmentRef": environment_ref,
                "sandboxRef": sandbox_ref,
                "adapterConfig": configuration.get("adapterConfig", {}),
            }
        )
    return {
        "documentType": "evaluation-invocation-set",
        "schemaVersion": "0.1.0",
        "invocationSetId": invocation_set_id,
        "planRef": plan_ref,
        "stageRegistryRef": stage_registry_ref,
        "assessorProfileRef": assessor_profile_ref,
        "repositoryRef": repository_ref,
        "invocations": invocations,
    }
