from __future__ import annotations

from ppf.catalog import SchemaCatalog
from ppf.workflow import WorkflowService

DIGEST = "sha256:" + ("1" * 64)


def _ref(identifier: str) -> dict[str, str]:
    return {"id": identifier, "digest": DIGEST}


def _iteration(kind: str, verdict: str, identifier: str) -> dict:
    return {
        "iterationId": identifier,
        "kind": kind,
        "status": "completed",
        "inputs": {
            name: _ref(
                name.replace("M", "-m")
                .replace("R", "-r")
                .replace("P", "-p")
                .replace("S", "-s")
            )
            for name in (
                "inputManifest",
                "profile",
                "plan",
                "catalog",
                "stageRegistry",
                "worktree",
                "environment",
                "toolchain",
                "invocationSet",
                "sandboxProfile",
                "adapterSet",
            )
        },
        "inputClosureDigest": DIGEST,
        "runAssemblyRef": _ref(f"assembly-{identifier}"),
        "rawArtifactRefs": [_ref(f"raw-{identifier}")],
        "judgment": {"verdict": verdict, "rationale": f"{verdict} evidence"},
        "startedAt": "2026-07-29T12:00:00Z",
        "completedAt": "2026-07-29T12:01:00Z",
    }


def test_coordinator_follows_authoritative_implementation_workflow() -> None:
    service = WorkflowService()
    workflow = service.plan(
        workflow_id="workflow-ho-01",
        mode="implement-and-qualify",
        input_binding_ref=_ref("binding"),
        at="2026-07-29T11:59:00Z",
    )
    assert service.next_action(workflow) == "baseline"
    workflow = service.record_baseline(
        workflow,
        iteration=_iteration("baseline", "pass", "baseline"),
        decision="proceed-to-implementation",
    )
    workflow = service.record_implementation(
        workflow,
        iteration=_iteration("implementation", "pass", "targeted"),
    )
    workflow = service.complete(
        workflow,
        iteration=_iteration("qualification", "pass", "qualification"),
    )
    assert workflow["currentState"] == "qualified"
    assert not list(
        SchemaCatalog.load().validator("evaluation-workflow").iter_errors(workflow)
    )
