from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from ppf.catalog import SchemaCatalog
from ppf.contracts import ContractValidationError
from ppf.workflow import WorkflowError, WorkflowService
from ppf.workflow_cli import app

DIGEST = "sha256:" + ("1" * 64)
FIXTURES = (
    Path(__file__).resolve().parents[1]
    / ".codex"
    / "skills"
    / "python-policy-ppf"
    / "tests"
    / "fixtures"
)


def _ref(identifier: str) -> dict[str, str]:
    return {"id": identifier, "digest": DIGEST}


def _iteration(kind: str, verdict: str, identifier: str) -> dict:
    return {
        "iterationId": identifier,
        "kind": kind,
        "status": "completed",
        "inputs": {
            name: _ref(
                name.replace("M", "-m").replace("R", "-r").replace("P", "-p").replace("S", "-s")
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
    assert not list(SchemaCatalog.load().validator("evaluation-workflow").iter_errors(workflow))


def test_implementation_cannot_complete_without_recorded_iteration() -> None:
    service = WorkflowService()
    workflow = service.plan(
        workflow_id="workflow-ho-01",
        mode="implement-and-qualify",
        input_binding_ref=_ref("binding"),
        at="2026-07-29T11:59:00Z",
    )
    workflow = service.record_baseline(
        workflow,
        iteration=_iteration("baseline", "pass", "baseline"),
        decision="proceed-to-implementation",
    )
    with pytest.raises(WorkflowError, match="recorded implementation iteration"):
        service.complete(
            workflow,
            iteration=_iteration("qualification", "pass", "qualification"),
        )


def _write_binding(path: Path) -> None:
    binding = json.loads((FIXTURES / "valid-input-binding.json").read_bytes())
    binding["bindingId"] = "binding-ho-01"
    path.write_text(json.dumps(binding), encoding="utf-8")


def _plan_public_workflow(tmp_path: Path) -> Path:
    binding = tmp_path / "binding.json"
    _write_binding(binding)
    workflow = tmp_path / "workflow.json"
    assert (
        app(
            [
                "workflow",
                "plan",
                str(binding),
                "--workflow-id",
                "workflow-ho-01",
                "--mode",
                "implement-and-qualify",
                "--at",
                "2026-07-29T11:59:00Z",
                "--output",
                str(workflow),
            ]
        )
        == 0
    )
    return workflow


def test_public_coordinator_rejects_passing_baseline_stop(tmp_path: Path) -> None:
    workflow = _plan_public_workflow(tmp_path)
    original = workflow.read_bytes()
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(_iteration("baseline", "pass", "baseline")),
        encoding="utf-8",
    )
    with pytest.raises(ContractValidationError):
        app(
            [
                "implement",
                "baseline",
                str(workflow),
                str(baseline),
                "--decision",
                "stop",
                "--output",
                str(workflow),
            ]
        )
    assert workflow.read_bytes() == original


def test_public_coordinator_rejects_qualification_without_baseline(
    tmp_path: Path,
) -> None:
    workflow = _plan_public_workflow(tmp_path)
    original = workflow.read_bytes()
    qualification = tmp_path / "qualification.json"
    qualification.write_text(
        json.dumps(_iteration("qualification", "pass", "qualification")),
        encoding="utf-8",
    )
    with pytest.raises(ContractValidationError):
        app(
            [
                "implement",
                "complete",
                str(workflow),
                str(qualification),
                "--output",
                str(workflow),
            ]
        )
    assert workflow.read_bytes() == original


def test_workflow_same_path_publication_does_not_use_path_write_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow = _plan_public_workflow(tmp_path)
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(_iteration("baseline", "pass", "baseline")),
        encoding="utf-8",
    )

    def forbidden_write_bytes(_path: Path, _content: bytes) -> int:
        raise AssertionError("workflow publication must use atomic replacement")

    monkeypatch.setattr(Path, "write_bytes", forbidden_write_bytes)
    assert (
        app(
            [
                "implement",
                "baseline",
                str(workflow),
                str(baseline),
                "--decision",
                "proceed-to-implementation",
                "--output",
                str(workflow),
            ]
        )
        == 0
    )


def test_public_coordinator_runs_complete_ho_01_repair_loop(
    tmp_path: Path,
) -> None:
    binding = tmp_path / "binding.json"
    _write_binding(binding)
    workflow = tmp_path / "workflow.json"
    assert (
        app(
            [
                "workflow",
                "plan",
                str(binding),
                "--workflow-id",
                "workflow-ho-01",
                "--mode",
                "implement-and-qualify",
                "--at",
                "2026-07-29T11:59:00Z",
                "--output",
                str(workflow),
            ]
        )
        == 0
    )
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(_iteration("baseline", "pass", "baseline")),
        encoding="utf-8",
    )
    assert (
        app(
            [
                "implement",
                "baseline",
                str(workflow),
                str(baseline),
                "--decision",
                "proceed-to-implementation",
                "--output",
                str(workflow),
            ]
        )
        == 0
    )

    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["git", "-C", str(repository), "init", "-q"], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.name", "Test"],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "config",
            "user.email",
            "test@example.invalid",
        ],
        check=True,
    )
    subject = repository / "value.py"
    subject.write_text("value = 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repository), "add", "value.py"], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-qm", "base"],
        check=True,
    )
    base_commit = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    base_tree = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD^{tree}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subject.write_text("value = 2\n", encoding="utf-8")
    patch_bytes = subprocess.run(
        ["git", "-C", str(repository), "diff", "--binary", "--full-index"],
        check=True,
        capture_output=True,
    ).stdout
    subject.write_text("value = 1\n", encoding="utf-8")
    patch = tmp_path / "repair.patch"
    patch.write_bytes(patch_bytes)
    decision = tmp_path / "decision.json"
    decision.write_text(
        json.dumps(
            {
                "documentType": "repair-decision",
                "schemaVersion": "0.1.0",
                "decisionId": "repair-ho-01",
                "decision": "repair",
                "baseCommit": base_commit,
                "baseTree": base_tree,
                "patchRef": {
                    "id": "patch-ho-01",
                    "digest": "sha256:" + hashlib.sha256(patch_bytes).hexdigest(),
                },
                "failedItems": ["HO-01"],
                "counterexampleRefs": [],
                "permittedPaths": ["value.py"],
                "forbiddenPaths": ["policy/", "schemas/"],
                "remainingCycles": 1,
                "nextSelector": {"items": ["HO-01"], "stages": ["typing"]},
            }
        ),
        encoding="utf-8",
    )
    repair_record = tmp_path / "repair-record.json"
    assert (
        app(
            [
                "implement",
                "repair",
                str(repository),
                str(decision),
                str(patch),
                "--workflow-id",
                "workflow-ho-01",
                "--applied-at",
                "2026-07-29T12:02:00Z",
                "--output",
                str(repair_record),
            ]
        )
        == 0
    )

    targeted = tmp_path / "targeted.json"
    targeted.write_text(
        json.dumps(_iteration("implementation", "pass", "targeted")),
        encoding="utf-8",
    )
    assert (
        app(
            [
                "implement",
                "iteration",
                str(workflow),
                str(targeted),
                "--output",
                str(workflow),
            ]
        )
        == 0
    )
    qualification = tmp_path / "qualification.json"
    qualification.write_text(
        json.dumps(_iteration("qualification", "pass", "qualification")),
        encoding="utf-8",
    )
    assert (
        app(
            [
                "implement",
                "complete",
                str(workflow),
                str(qualification),
                "--output",
                str(workflow),
            ]
        )
        == 0
    )
    completed = json.loads(workflow.read_bytes())
    assert completed["currentState"] == "qualified"
    assert len(completed["implementationIterations"]) == 1
    assert repair_record.is_file()
