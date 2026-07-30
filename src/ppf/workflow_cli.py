"""Minimal Cyclopts coordinator for authoritative workflow and repair services."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from cyclopts import App

from .artifacts import pretty_json_bytes
from .cli_common import content_ref, render_json
from .repair import RepairService
from .workflow import WorkflowService

Json = Any

app = App(
    name="python-ppf",
    help="Coordinate PPF workflow transitions and bounded implementation repair.",
    result_action="return_value",
)
workflow_app = App(name="workflow")
implement_app = App(name="implement")
app.command(workflow_app, name="workflow")
app.command(implement_app, name="implement")


def _read(path: Path) -> dict[str, Json]:
    return json.loads(path.read_bytes())


def _write(path: Path, document: dict[str, Json]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pretty_json_bytes(document))


@workflow_app.command(name="plan")
def plan_workflow(
    input_binding: Path,
    *,
    workflow_id: str,
    mode: str,
    at: str,
    output: Path,
) -> int:
    """Bind inputs and create the first declared workflow transition."""
    binding = _read(input_binding)
    result = WorkflowService().plan(
        workflow_id=workflow_id,
        mode=mode,
        input_binding_ref=content_ref(binding["bindingId"], binding),
        at=at,
    )
    _write(output, result)
    render_json({"workflow": str(output), "currentState": result["currentState"]})
    return 0


@workflow_app.command(name="next")
def next_workflow(workflow: Path) -> int:
    """Return the next operation without assigning workflow state."""
    document = _read(workflow)
    render_json({"next": WorkflowService().next_action(document)})
    return 0


@workflow_app.command
def resume(workflow: Path) -> int:
    """Return resumable workflow state and its next operation."""
    document = _read(workflow)
    render_json(
        {
            "workflowId": document["workflowId"],
            "currentState": document["currentState"],
            "next": WorkflowService().next_action(document),
        }
    )
    return 0


@implement_app.command
def baseline(
    workflow: Path,
    iteration: Path,
    *,
    decision: str,
    output: Path,
) -> int:
    """Record a judged baseline and its declared routing decision."""
    result = WorkflowService().record_baseline(
        _read(workflow),
        iteration=_read(iteration),
        decision=decision,
    )
    _write(output, result)
    render_json({"workflow": str(output), "currentState": result["currentState"]})
    return 0


@implement_app.command
def repair(
    repository_root: Path,
    decision: Path,
    patch: Path,
    *,
    workflow_id: str,
    applied_at: str,
    output: Path,
) -> int:
    """Apply and atomically promote one post-verified repair tree."""
    decision_raw = decision.read_bytes()
    decision_document = json.loads(decision_raw)
    decision_ref = {
        "id": decision_document["decisionId"],
        "digest": "sha256:" + hashlib.sha256(decision_raw).hexdigest(),
        "uri": decision.as_uri(),
    }
    record = RepairService().apply(
        repository=repository_root,
        workflow_id=workflow_id,
        decision=decision_document,
        decision_ref=decision_ref,
        patch=patch.read_bytes(),
        applied_at=applied_at,
    )
    _write(output, record)
    render_json(
        {
            "repairRecord": str(output),
            "resultCommit": record["resultCommit"],
            "promotedRef": record["promotedRef"],
        }
    )
    return 0


@implement_app.command
def complete(
    workflow: Path,
    qualification_iteration: Path,
    *,
    output: Path,
) -> int:
    """Record full qualification and enter the authoritative terminal state."""
    result = WorkflowService().complete(
        _read(workflow),
        iteration=_read(qualification_iteration),
    )
    _write(output, result)
    render_json({"workflow": str(output), "currentState": result["currentState"]})
    return 0 if result["currentState"] == "qualified" else 1


def main() -> int:
    return app()
