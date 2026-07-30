from __future__ import annotations

from pathlib import Path

from ppf.artifacts import ContentAddressedArtifactStore
from ppf.assessment import AssessmentRequest, AssessmentService
from ppf.assessors import default_assessor_registry
from ppf.execution import (
    PreparedInvocation,
    RawExecutionResult,
    SandboxCapabilities,
    SupportDecision,
)
from ppf.tool_environment import ResolvedEntrypoint

DIGEST = "sha256:" + ("1" * 64)


class FixedClock:
    def __init__(self) -> None:
        self.elapsed = 0.0

    def now(self) -> str:
        return "2026-07-29T12:00:00Z"

    def monotonic(self) -> float:
        self.elapsed += 0.01
        return self.elapsed


class FakeVerifier:
    def __init__(self, root: Path) -> None:
        self.root = root

    def verify(self, manifest: dict, environment_root: Path) -> dict:
        return {
            "pytest-tool": ResolvedEntrypoint(
                entrypoint_id="pytest-tool",
                argv_prefix=("/verified/python", "-I", "-m", "pytest"),
                environment_root=self.root,
            )
        }


class FakeSandbox:
    def __init__(self, supported: bool) -> None:
        self.supported = supported
        self.executed: list[PreparedInvocation] = []

    def capabilities(self) -> SandboxCapabilities:
        return SandboxCapabilities(*(self.supported for _ in range(7)))

    def evaluate_support(self, profile: dict) -> SupportDecision:
        return SupportDecision(self.supported, () if self.supported else ("network-disabled",))

    def execute(self, invocation: PreparedInvocation, profile: dict, *, clock: FixedClock):
        self.executed.append(invocation)
        return RawExecutionResult(
            invocation_id=invocation.invocation_id,
            launch_state="launched",
            status="completed",
            exit_code=1,
            signal=None,
            started_at=clock.now(),
            completed_at=clock.now(),
            duration_ms=12,
            stdout=b"failed test evidence\n",
            stderr=b"",
        )


def _request(root: Path) -> AssessmentRequest:
    reference = {"id": "binding", "digest": DIGEST}
    return AssessmentRequest(
        repository_root=root,
        tool_environment_root=root,
        input_manifest_digest=DIGEST,
        input_binding_ref=reference,
        input_binding_digest=DIGEST,
        invocation_set={
            "invocations": [
                {
                    "invocationId": "invoke-" + ("1" * 64),
                    "caseRef": "case",
                    "stageRef": "behavioral",
                    "assessorRef": "pytest-assessor",
                    "assessorKind": "pytest",
                    "executableRef": "pytest-tool",
                    "argv": ["pytest-tool", "-q"],
                    "workingDirectoryRef": "repository-root",
                }
            ]
        },
        plan={
            "cases": [
                {
                    "id": "case",
                    "claimRef": "HO-01",
                    "subject": {"id": "decorator"},
                    "fixture": {"id": "ordinary"},
                    "probe": {"probeRef": "pytest-probe"},
                }
            ]
        },
        assessor_profile={
            "assessors": [
                {
                    "id": "pytest-assessor",
                    "kind": "pytest",
                    "executableRef": "pytest-tool",
                    "adapterRef": {
                        "id": "adapter",
                        "digest": DIGEST,
                        "uri": "https://example.invalid/adapter",
                    },
                    "normalizerRef": {
                        "id": "normalizer",
                        "digest": DIGEST,
                        "uri": "https://example.invalid/normalizer",
                    },
                }
            ]
        },
        environment_profile={"variables": {}},
        sandbox_profile={"profile": {"timeoutSeconds": 10}},
        tool_environment_manifest={},
    )


def test_unsupported_preflight_emits_attempt_without_execution(tmp_path: Path) -> None:
    sandbox = FakeSandbox(False)
    result = AssessmentService().run(
        _request(tmp_path),
        assessor_registry=default_assessor_registry(),
        sandbox=sandbox,
        clock=FixedClock(),
        artifact_store=ContentAddressedArtifactStore(tmp_path / "artifacts"),
        verifier=FakeVerifier(tmp_path),
    )
    assert not result.operational_success
    assert len(result.attempts) == 1
    assert not result.envelopes
    assert not sandbox.executed


def test_captured_assessor_failure_is_operationally_successful(tmp_path: Path) -> None:
    sandbox = FakeSandbox(True)
    result = AssessmentService().run(
        _request(tmp_path),
        assessor_registry=default_assessor_registry(),
        sandbox=sandbox,
        clock=FixedClock(),
        artifact_store=ContentAddressedArtifactStore(tmp_path / "artifacts"),
        verifier=FakeVerifier(tmp_path),
    )
    assert result.operational_success
    assert result.observations[0]["status"] == "failed"
    assert len(result.envelopes) == 1
    assert len(sandbox.executed) == 1
