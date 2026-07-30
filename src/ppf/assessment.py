"""Assessment application service: validate, preflight, execute, and emit facts."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .artifacts import ContentAddressedArtifactStore, StoredArtifact
from .assessors import Assessor, NormalizationContext
from .execution import (
    Clock,
    PreparedInvocation,
    RawExecutionResult,
    SandboxBackend,
    SandboxPreparationError,
)
from .tool_environment import (
    ResolvedEntrypoint,
    ToolEnvironmentError,
    ToolEnvironmentVerifier,
)

Json = Any


class SystemClock:
    """Wall and monotonic clock used outside deterministic tests."""

    def now(self) -> str:
        return datetime.now(UTC).isoformat().replace("+00:00", "Z")

    def monotonic(self) -> float:
        return time.monotonic()


@dataclass(frozen=True)
class AssessmentRequest:
    repository_root: Path
    tool_environment_root: Path
    input_manifest_digest: str
    input_binding_ref: dict[str, Json]
    input_binding_digest: str
    invocation_set: dict[str, Json]
    plan: dict[str, Json]
    assessor_profile: dict[str, Json]
    environment_profile: dict[str, Json]
    sandbox_profile: dict[str, Json]
    tool_environment_manifest: dict[str, Json]


@dataclass(frozen=True)
class AssessmentResult:
    operational_success: bool
    envelopes: tuple[dict[str, Json], ...]
    attempts: tuple[dict[str, Json], ...]
    observations: tuple[dict[str, Json], ...]
    artifacts: tuple[StoredArtifact, ...]


def _content_ref(artifact: StoredArtifact) -> dict[str, Json]:
    return artifact.as_manifest_entry()["contentRef"]


def _document_ref(identifier: str, document: dict[str, Json]) -> dict[str, Json]:
    import rfc8785

    content = rfc8785.dumps(document)
    return {
        "id": identifier,
        "digest": "sha256:" + hashlib.sha256(content).hexdigest(),
        "uri": f"embedded:{identifier}",
    }


class AssessmentService:
    """Run eligible invocations while preserving authority boundaries."""

    def run(
        self,
        request: AssessmentRequest,
        *,
        assessor_registry: dict[str, Assessor],
        sandbox: SandboxBackend,
        clock: Clock,
        artifact_store: ContentAddressedArtifactStore,
        verifier: ToolEnvironmentVerifier,
    ) -> AssessmentResult:
        environment_error: str | None = None
        try:
            resolved = verifier.verify(
                request.tool_environment_manifest,
                request.tool_environment_root,
            )
        except ToolEnvironmentError as error:
            resolved = {}
            environment_error = str(error)
        cases = {case["id"]: case for case in request.plan["cases"]}
        assessors = {
            assessor["id"]: assessor
            for assessor in request.assessor_profile["assessors"]
        }
        envelopes: list[dict[str, Json]] = []
        attempts: list[dict[str, Json]] = []
        observations: list[dict[str, Json]] = []
        artifacts: list[StoredArtifact] = []
        operational_success = True

        for invocation in request.invocation_set["invocations"]:
            descriptor = assessors[invocation["assessorRef"]]
            entrypoint = resolved.get(invocation["executableRef"])
            support = sandbox.evaluate_support(request.sandbox_profile["profile"])
            diagnostic: tuple[str, str] | None = None
            status = "unsupported"
            phase = "sandbox-preflight"
            if environment_error is not None:
                diagnostic = ("tool-environment-integrity", environment_error)
                status = "integrity-failed"
                phase = "tool-environment-preflight"
            elif entrypoint is None:
                diagnostic = (
                    "tool-unavailable",
                    f"locked entrypoint {invocation['executableRef']!r} is unavailable",
                )
                status = "tool-unavailable"
                phase = "tool-preflight"
            elif not support.supported:
                diagnostic = (
                    "required-capability-unavailable",
                    f"missing sandbox capabilities: {support.missing!r}",
                )
            if diagnostic is not None:
                operational_success = False
                attempt = self._attempt(
                    invocation,
                    status=status,
                    phase=phase,
                    code=diagnostic[0],
                    message=diagnostic[1],
                    clock=clock,
                )
                attempt_bytes = __import__("rfc8785").dumps(attempt)
                artifact = artifact_store.put(
                    f"{invocation['invocationId']}.attempt.json",
                    attempt_bytes,
                    role="operational-attempt",
                    media_type="application/json",
                )
                artifacts.append(artifact)
                attempts.append(attempt)
                continue

            assert isinstance(entrypoint, ResolvedEntrypoint)
            declared_argv = invocation["argv"]
            if declared_argv[0] != descriptor["executableRef"]:
                operational_success = False
                attempt = self._attempt(
                    invocation,
                    status="preparation-failed",
                    phase="assessor-prepare",
                    code="entrypoint-mismatch",
                    message="argv[0] must equal the locked executable reference",
                    clock=clock,
                )
                artifact = artifact_store.put(
                    f"{invocation['invocationId']}.attempt.json",
                    __import__("rfc8785").dumps(attempt),
                    role="operational-attempt",
                    media_type="application/json",
                )
                artifacts.append(artifact)
                attempts.append(attempt)
                continue
            prepared = PreparedInvocation(
                invocation_id=invocation["invocationId"],
                argv=(*entrypoint.argv_prefix, *declared_argv[1:]),
                working_directory=request.repository_root,
                repository_root=request.repository_root,
                tool_environment_root=entrypoint.environment_root,
                environment=request.environment_profile["variables"],
            )
            try:
                result = sandbox.execute(
                    prepared,
                    request.sandbox_profile["profile"],
                    clock=clock,
                )
            except (OSError, SandboxPreparationError) as error:
                operational_success = False
                attempt = self._attempt(
                    invocation,
                    status="preparation-failed",
                    phase="sandbox-launch",
                    code="sandbox-launch-failed",
                    message=str(error),
                    clock=clock,
                )
                artifact = artifact_store.put(
                    f"{invocation['invocationId']}.attempt.json",
                    __import__("rfc8785").dumps(attempt),
                    role="operational-attempt",
                    media_type="application/json",
                )
                artifacts.append(artifact)
                attempts.append(attempt)
                continue
            emitted = self._emit_launched(
                request,
                invocation,
                descriptor,
                cases[invocation["caseRef"]],
                result,
                assessor_registry[invocation["assessorKind"]],
                artifact_store,
            )
            envelopes.append(emitted[0])
            observations.extend(emitted[1])
            artifacts.extend(emitted[2])
        return AssessmentResult(
            operational_success=operational_success,
            envelopes=tuple(envelopes),
            attempts=tuple(attempts),
            observations=tuple(observations),
            artifacts=tuple(artifacts),
        )

    @staticmethod
    def _attempt(
        invocation: dict[str, Json],
        *,
        status: str,
        phase: str,
        code: str,
        message: str,
        clock: Clock,
    ) -> dict[str, Json]:
        invocation_ref = _document_ref(invocation["invocationId"], invocation)
        return {
            "documentType": "operational-attempt",
            "schemaVersion": "0.1.0",
            "attemptId": f"attempt-{invocation['invocationId']}",
            "invocationRef": invocation_ref,
            "status": status,
            "phase": phase,
            "diagnostics": [{"code": code, "message": message, "details": {}}],
            "recordedAt": clock.now(),
        }

    @staticmethod
    def _emit_launched(
        request: AssessmentRequest,
        invocation: dict[str, Json],
        descriptor: dict[str, Json],
        case: dict[str, Json],
        result: RawExecutionResult,
        assessor: Assessor,
        store: ContentAddressedArtifactStore,
    ) -> tuple[dict[str, Json], list[dict[str, Json]], list[StoredArtifact]]:
        stdout = store.put(
            f"{invocation['invocationId']}.stdout",
            result.stdout,
            role="stdout",
            media_type="application/octet-stream",
        )
        stderr = store.put(
            f"{invocation['invocationId']}.stderr",
            result.stderr,
            role="stderr",
            media_type="application/octet-stream",
        )
        execution_id = f"exec-{invocation['invocationId']}"
        normalized = assessor.normalize(
            result,
            NormalizationContext(
                case=case,
                execution_id=execution_id,
                stdout_ref=_content_ref(stdout),
                stderr_ref=_content_ref(stderr),
            ),
        )
        record = {
            "id": execution_id,
            "stageRef": invocation["stageRef"],
            "caseRefs": [case["id"]],
            "adapterRef": descriptor["adapterRef"],
            "normalizerRef": descriptor["normalizerRef"],
            "inputManifestDigest": request.input_manifest_digest,
            "invocation": {
                "argv": invocation["argv"],
                "workingDirectoryRef": invocation["workingDirectoryRef"],
            },
            "result": {
                "status": result.status,
                "exitCode": result.exit_code,
                "signal": result.signal,
                "durationMs": result.duration_ms,
            },
            "rawArtifactRefs": [_content_ref(stdout), _content_ref(stderr)],
            "limitations": [],
        }
        fragment_id = f"fragment-{invocation['invocationId']}"
        envelope = {
            "documentType": "evaluation-producer-envelope",
            "schemaVersion": "0.2.0",
            "envelopeId": f"envelope-{invocation['invocationId']}",
            "producerRef": descriptor["adapterRef"],
            "inputBindingRef": request.input_binding_ref,
            "inputBindingDigest": request.input_binding_digest,
            "fragment": {
                "documentType": "evaluation-run-fragment",
                "schemaVersion": "0.2.0",
                "fragmentId": fragment_id,
                "stageRef": invocation["stageRef"],
                "inputManifestDigest": request.input_manifest_digest,
                "executionRefs": [execution_id],
                "observationRefs": [item["id"] for item in normalized],
                "oracleResultRefs": [],
                "artifactRefs": [_content_ref(stdout), _content_ref(stderr)],
            },
            "executions": [
                {
                    "record": record,
                    "invocationRef": _document_ref(
                        invocation["invocationId"], invocation
                    ),
                    "rawArtifactRefs": [_content_ref(stdout), _content_ref(stderr)],
                }
            ],
            "observations": [
                {key: value for key, value in item.items() if key != "semanticPayload"}
                for item in normalized
            ],
            "oracleResults": [],
            "limitations": [],
        }
        return envelope, normalized, [stdout, stderr]
