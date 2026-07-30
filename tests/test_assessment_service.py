from __future__ import annotations

from pathlib import Path

import pytest

from ppf.artifacts import (
    ContentAddressedArtifactStore,
    artifact_manifest,
    canonical_json_bytes,
    pretty_json_bytes,
    repository_tree_ref,
)
from ppf.assessment import AssessmentRequest, AssessmentService
from ppf.assessors import default_assessor_registry
from ppf.execution import (
    PreparedInvocation,
    RawExecutionResult,
    SandboxCapabilities,
    SupportDecision,
)
from ppf.invocations import invocation_id
from ppf.qualify_cli import _verified_assessment
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


class FailingArtifactStore(ContentAddressedArtifactStore):
    def put(self, *args, **kwargs):
        raise OSError("disk full")


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
                    "invocationId": invocation_id("case", "pytest-assessor"),
                    "sequence": 10,
                    "caseRef": "case",
                    "stageRef": "behavioral-examples",
                    "assessorRef": "pytest-assessor",
                    "assessorKind": "pytest",
                    "executableRef": "pytest-tool",
                    "argv": ["pytest-tool", "-q"],
                    "workingDirectoryRef": "repository-root",
                    "environmentRef": "environment",
                    "sandboxRef": "sandbox",
                    "adapterConfig": {},
                }
            ],
            "documentType": "evaluation-invocation-set",
            "schemaVersion": "0.1.0",
            "invocationSetId": "invocations-test",
            "planRef": {"id": "plan", "digest": DIGEST},
            "stageRegistryRef": {"id": "stages", "digest": DIGEST},
            "assessorProfileRef": {"id": "assessors", "digest": DIGEST},
            "repositoryRef": repository_tree_ref(root),
        },
        plan={
            "documentType": "evaluation-plan",
            "schemaVersion": "0.2.0",
            "planId": "plan",
            "cases": [
                {
                    "id": "case",
                    "claimRef": "HO-01",
                    "stage": "behavioral-examples",
                    "subject": {"id": "decorator"},
                    "fixture": {"id": "ordinary"},
                    "probe": {
                        "probeRef": "pytest-probe",
                        "configuration": {"argv": ["pytest-tool", "-q"]},
                    },
                }
            ],
        },
        assessor_profile={
            "documentType": "assessor-profile",
            "schemaVersion": "0.1.0",
            "profileId": "assessors",
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
                    "probeRefs": ["pytest-probe"],
                }
            ],
        },
        environment_profile={
            "documentType": "environment-profile",
            "environmentId": "environment",
            "variables": {},
        },
        sandbox_profile={
            "documentType": "sandbox-profile",
            "sandboxId": "sandbox",
            "profile": {"timeoutSeconds": 10},
        },
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


def test_declared_binding_mismatch_prevents_execution(tmp_path: Path) -> None:
    request = _request(tmp_path)
    request.invocation_set["invocations"][0]["environmentRef"] = "unrelated"
    sandbox = FakeSandbox(True)
    result = AssessmentService().run(
        request,
        assessor_registry=default_assessor_registry(),
        sandbox=sandbox,
        clock=FixedClock(),
        artifact_store=ContentAddressedArtifactStore(tmp_path / "artifacts"),
        verifier=FakeVerifier(tmp_path),
    )
    assert not result.operational_success
    assert result.attempts[0]["diagnostics"][0]["code"] == ("environment-binding-mismatch")
    assert not sandbox.executed


def test_repository_drift_prevents_execution(tmp_path: Path) -> None:
    request = _request(tmp_path)
    (tmp_path / "untracked.txt").write_text("changed", encoding="utf-8")
    sandbox = FakeSandbox(True)
    result = AssessmentService().run(
        request,
        assessor_registry=default_assessor_registry(),
        sandbox=sandbox,
        clock=FixedClock(),
        artifact_store=ContentAddressedArtifactStore(tmp_path / "artifacts"),
        verifier=FakeVerifier(tmp_path),
    )
    assert not result.operational_success
    assert result.attempts[0]["status"] == "integrity-failed"
    assert not sandbox.executed


def test_artifact_failure_is_contained_per_invocation(tmp_path: Path) -> None:
    sandbox = FakeSandbox(True)
    result = AssessmentService().run(
        _request(tmp_path),
        assessor_registry=default_assessor_registry(),
        sandbox=sandbox,
        clock=FixedClock(),
        artifact_store=FailingArtifactStore(tmp_path / "artifacts"),
        verifier=FakeVerifier(tmp_path),
    )
    assert not result.operational_success
    assert not result.envelopes
    assert result.attempts[0]["status"] == "artifact-failed"
    assert result.attempts[0]["phase"] == "artifact-persistence"


def test_missing_assessor_implementation_is_operational_failure(
    tmp_path: Path,
) -> None:
    sandbox = FakeSandbox(True)
    result = AssessmentService().run(
        _request(tmp_path),
        assessor_registry={},
        sandbox=sandbox,
        clock=FixedClock(),
        artifact_store=ContentAddressedArtifactStore(tmp_path / "artifacts"),
        verifier=FakeVerifier(tmp_path),
    )
    assert not result.operational_success
    assert result.attempts[0]["diagnostics"][0]["code"] == ("implementation-unavailable")
    assert not sandbox.executed


def test_qualification_reads_verified_manifest_objects_not_mutable_index(
    tmp_path: Path,
) -> None:
    assessment_root = tmp_path / "assessment"
    store = ContentAddressedArtifactStore(assessment_root)
    request = _request(tmp_path)
    result = AssessmentService().run(
        request,
        assessor_registry=default_assessor_registry(),
        sandbox=FakeSandbox(True),
        clock=FixedClock(),
        artifact_store=store,
        verifier=FakeVerifier(tmp_path),
    )
    invocation_artifact = store.put(
        "invocations-test.json",
        canonical_json_bytes(request.invocation_set),
        role="execution-metadata",
        media_type="application/json",
    )
    manifest = artifact_manifest(
        manifest_id="manifest-assessment-run",
        run_ref={"id": "assessment-run", "digest": DIGEST},
        created_at="2026-07-29T12:00:00Z",
        artifacts=[*result.artifacts, invocation_artifact],
    )
    (assessment_root / "manifest-assessment-run.json").write_bytes(pretty_json_bytes(manifest))
    index = assessment_root / "assessment-index.json"
    index.write_text('{"envelopes": [{"observations": [{"status": "passed"}]}]}')
    documents = {
        "binding": {
            "documentType": "evaluation-input-binding",
            "bindingId": "binding",
        },
        "manifest": {
            "documentType": "evaluation-input-manifest",
            "manifestId": "manifest",
        },
        "plan": request.plan,
        "stages": {
            "documentType": "stage-registry",
            "registryId": "stages",
            "stages": [{"id": "behavioral-examples", "kind": "behavioral"}],
        },
        "assessors": request.assessor_profile,
        "environment": request.environment_profile,
        "sandbox": request.sandbox_profile,
    }
    references = {
        "binding": {"id": "binding", "digest": DIGEST},
        "manifest": {"id": "manifest", "digest": DIGEST},
        "plan": {"id": "plan", "digest": DIGEST},
        "stages": {"id": "stages", "digest": DIGEST},
        "assessors": {"id": "assessors", "digest": DIGEST},
    }
    envelopes, observations, attempts = _verified_assessment(
        index,
        documents,
        references,
    )
    assert len(envelopes) == 1
    assert observations[0]["status"] == "failed"
    assert not attempts

    envelope_entry = next(
        item for item in manifest["artifacts"] if item["role"] == "producer-envelope"
    )
    object_path = (
        assessment_root
        / "objects"
        / "sha256"
        / envelope_entry["contentRef"]["digest"].removeprefix("sha256:")
    )
    object_path.write_bytes(object_path.read_bytes().replace(b'"failed"', b'"passed"'))
    with pytest.raises(ValueError, match="integrity failure"):
        _verified_assessment(index, documents, references)
