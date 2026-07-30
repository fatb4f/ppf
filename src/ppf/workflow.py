"""Application-owned transitions for the authoritative workflow extension."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

Json = Any


class WorkflowError(ValueError):
    """Raised when a requested transition is not declared by the contract."""


def _transition(
    workflow: dict[str, Json],
    *,
    to: str,
    cause: str,
    at: str,
) -> None:
    source = workflow["currentState"]
    workflow["transitions"].append(
        {
            "transitionId": f"transition-{len(workflow['transitions']) + 1}",
            "from": source,
            "to": to,
            "cause": cause,
            "at": at,
        }
    )
    workflow["currentState"] = to


class WorkflowService:
    """Request and record only transitions declared by the 0.2 workflow schema."""

    def plan(
        self,
        *,
        workflow_id: str,
        mode: str,
        input_binding_ref: dict[str, Json],
        at: str,
    ) -> dict[str, Json]:
        return {
            "documentType": "evaluation-workflow",
            "schemaVersion": "0.2.0",
            "workflowId": workflow_id,
            "mode": mode,
            "inputBindingRef": input_binding_ref,
            "currentState": "inputs-bound",
            "baseline": None,
            "implementationIterations": [],
            "qualificationIteration": None,
            "transitions": [
                {
                    "transitionId": "transition-1",
                    "from": "planned",
                    "to": "inputs-bound",
                    "cause": "inputs-locked",
                    "at": at,
                }
            ],
        }

    def next_action(self, workflow: dict[str, Json]) -> str:
        state = workflow["currentState"]
        if state == "inputs-bound":
            return (
                "full-qualification"
                if workflow["mode"] == "qualification-only"
                else "baseline"
            )
        if state == "baseline-judged":
            baseline = workflow["baseline"]
            return {
                "proceed-to-implementation": "implementation",
                "proceed-to-full-qualification": "full-qualification",
                "stop": "stop",
            }[baseline["decision"]]
        if state == "implementation-running":
            return "implementation-or-complete"
        if state == "full-qualification-running":
            return "qualification-judgment"
        if state in {"qualified", "rejected", "stopped"}:
            return "terminal"
        return "await-current-operation"

    def record_baseline(
        self,
        workflow: dict[str, Json],
        *,
        iteration: dict[str, Json],
        decision: str,
    ) -> dict[str, Json]:
        if workflow["currentState"] != "inputs-bound":
            raise WorkflowError("baseline requires inputs-bound state")
        result = deepcopy(workflow)
        _transition(
            result,
            to="baseline-running",
            cause="baseline-started",
            at=iteration["startedAt"],
        )
        verdict = iteration["judgment"]["verdict"]
        _transition(
            result,
            to="baseline-judged",
            cause={
                "pass": "baseline-passed",
                "fail": "baseline-failed",
                "inconclusive": "baseline-inconclusive",
            }[verdict],
            at=iteration["completedAt"],
        )
        result["baseline"] = {"iteration": iteration, "decision": decision}
        if decision == "proceed-to-implementation":
            _transition(
                result,
                to="implementation-running",
                cause="implementation-authorized",
                at=iteration["completedAt"],
            )
        elif decision == "proceed-to-full-qualification":
            _transition(
                result,
                to="full-qualification-running",
                cause="qualification-authorized",
                at=iteration["completedAt"],
            )
        else:
            _transition(
                result,
                to="stopped",
                cause=f"baseline-{'failed' if verdict == 'fail' else 'inconclusive'}",
                at=iteration["completedAt"],
            )
        return result

    def record_implementation(
        self,
        workflow: dict[str, Json],
        *,
        iteration: dict[str, Json],
    ) -> dict[str, Json]:
        if workflow["currentState"] != "implementation-running":
            raise WorkflowError("implementation iteration requires implementation-running")
        result = deepcopy(workflow)
        if result["implementationIterations"]:
            _transition(
                result,
                to="implementation-running",
                cause="next-implementation-iteration",
                at=iteration["startedAt"],
            )
        result["implementationIterations"].append(iteration)
        return result

    def complete(
        self,
        workflow: dict[str, Json],
        *,
        iteration: dict[str, Json],
    ) -> dict[str, Json]:
        result = deepcopy(workflow)
        if result["currentState"] == "implementation-running":
            _transition(
                result,
                to="full-qualification-running",
                cause="implementation-completed",
                at=iteration["startedAt"],
            )
        elif result["currentState"] == "inputs-bound":
            _transition(
                result,
                to="full-qualification-running",
                cause="qualification-only-started",
                at=iteration["startedAt"],
            )
        if result["currentState"] != "full-qualification-running":
            raise WorkflowError("qualification requires full-qualification-running")
        result["qualificationIteration"] = iteration
        verdict = iteration["judgment"]["verdict"]
        cause = (
            "qualification-passed"
            if verdict == "pass"
            else "qualification-failed"
            if verdict == "fail"
            else "qualification-inconclusive"
        )
        _transition(
            result,
            to="qualified" if verdict == "pass" else "rejected",
            cause=cause,
            at=iteration["completedAt"],
        )
        return result
