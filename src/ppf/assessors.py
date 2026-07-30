"""Tool-specific normalization adapters with no qualification authority."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol

from .execution import RawExecutionResult

Json = Any


@dataclass(frozen=True)
class NormalizationContext:
    """Case metadata needed to construct official observations."""

    case: dict[str, Json]
    execution_id: str
    stdout_ref: dict[str, Json]
    stderr_ref: dict[str, Json]


class Assessor(Protocol):
    kind: str

    def normalize(
        self,
        result: RawExecutionResult,
        context: NormalizationContext,
    ) -> list[dict[str, Json]]: ...


def _status(result: RawExecutionResult) -> str:
    if result.status == "timed-out":
        return "timed-out"
    if result.exit_code == 0:
        return "passed"
    return "failed"


def _stable_event_value(value: Json) -> Json:
    if isinstance(value, dict):
        return {
            key: _stable_event_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            if isinstance(key, str)
            and not key.startswith("_ansible_")
            and key not in {"uuid", "created", "start", "end", "delta"}
        }
    if isinstance(value, list):
        return [_stable_event_value(item) for item in value]
    return value


class ProcessAssessor:
    """Normalize generic CLI, pytest, ty, and runtime process facts."""

    def __init__(self, kind: str) -> None:
        self.kind = kind

    def normalize(
        self,
        result: RawExecutionResult,
        context: NormalizationContext,
    ) -> list[dict[str, Json]]:
        case = context.case
        return [
            {
                "id": f"obs-{result.invocation_id}",
                "caseRef": case["id"],
                "itemRef": case["claimRef"],
                "subjectRef": case["subject"]["id"],
                "fixtureRef": case["fixture"]["id"],
                "probeRef": case["probe"]["probeRef"],
                "executionRef": context.execution_id,
                "source": self.kind,
                "status": _status(result),
                "normalizedCode": f"{self.kind.upper()}-EXIT",
                "payload": {
                    "exitCode": result.exit_code,
                    "signal": result.signal,
                    "stdoutRef": context.stdout_ref,
                    "stderrRef": context.stderr_ref,
                },
                "semanticPayload": {
                    "exitCode": result.exit_code,
                    "signal": result.signal,
                },
                "location": None,
                "applicabilityPredicateRef": None,
                "skipReason": None,
                "counterexampleRef": None,
            }
        ]


class AnsibleAssessor(ProcessAssessor):
    """Normalize the locked Ansible Runner JSON event stream."""

    def __init__(self) -> None:
        super().__init__("ansible")

    def normalize(
        self,
        result: RawExecutionResult,
        context: NormalizationContext,
    ) -> list[dict[str, Json]]:
        base = super().normalize(result, context)[0]
        events: list[dict[str, Json]] = []
        malformed = False
        for line in result.stdout.splitlines():
            try:
                event = json.loads(line)
            except (UnicodeError, json.JSONDecodeError):
                malformed = True
                continue
            if isinstance(event, dict):
                event_data = event.get("event_data", {})
                events.append(
                    {
                        "event": event.get("event"),
                        "host": event_data.get("host"),
                        "task": event_data.get("task"),
                        "res": _stable_event_value(event_data.get("res")),
                    }
                )
        events.sort(
            key=lambda item: (
                str(item["event"]),
                str(item["host"]),
                str(item["task"]),
                json.dumps(item["res"], sort_keys=True),
            )
        )
        base["normalizedCode"] = (
            "ANSIBLE-EVENT-STREAM-ERROR" if malformed else "ANSIBLE-EVENTS"
        )
        if malformed:
            base["status"] = "error"
        base["payload"]["events"] = events
        base["semanticPayload"] = {
            "exitCode": result.exit_code,
            "events": events,
            "malformed": malformed,
        }
        return [base]


def default_assessor_registry() -> dict[str, Assessor]:
    """Return the P0 adapter registry."""
    return {
        "cyclopts": ProcessAssessor("cyclopts"),
        "pytest": ProcessAssessor("pytest"),
        "ty": ProcessAssessor("ty"),
        "runtime": ProcessAssessor("runtime"),
        "ansible": AnsibleAssessor(),
    }
