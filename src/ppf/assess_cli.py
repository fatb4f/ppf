"""Cyclopts command adapter for evidence-producing assessment."""

from __future__ import annotations

import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Annotated, Any

from cyclopts import App, Parameter

from .artifacts import (
    ContentAddressedArtifactStore,
    artifact_manifest,
    canonical_json_bytes,
    materialize_repository_snapshot,
    pretty_json_bytes,
    repository_tree_ref,
)
from .assessment import AssessmentRequest, AssessmentService, SystemClock
from .assessors import default_assessor_registry
from .cli_common import (
    by_type,
    content_ref,
    exact_bundle_refs,
    load_valid_bundle,
    render_json,
)
from .execution import BubblewrapSandbox
from .invocations import compile_invocation_set
from .json_input import strict_json_loads
from .tool_environment import ToolEnvironmentError, ToolEnvironmentVerifier

Json = Any

app = App(
    name="ppf-assess",
    help="Compile and execute locked PPF assessment invocations.",
    result_action="return_value",
)


def _compile(
    documents: dict[str, dict[str, Json]],
    repository_root: Path,
    references: dict[str, dict[str, Json]],
) -> dict[str, Json]:
    plan = by_type(documents, "evaluation-plan")
    stages = by_type(documents, "stage-registry")
    assessors = by_type(documents, "assessor-profile")
    environment = by_type(documents, "environment-profile")
    sandbox = by_type(documents, "sandbox-profile")
    return compile_invocation_set(
        invocation_set_id=f"invocations-{plan['planId']}",
        plan=plan,
        plan_ref=references[plan["planId"]],
        stage_registry=stages,
        stage_registry_ref=references[stages["registryId"]],
        assessor_profile=assessors,
        assessor_profile_ref=references[assessors["profileId"]],
        repository_ref=repository_tree_ref(repository_root),
        environment_ref=environment["environmentId"],
        sandbox_ref=sandbox["sandboxId"],
    )


@app.command
def plan(
    document: Annotated[list[Path], Parameter(help="Validated PPF input bundle.")],
    *,
    repository_root: Path,
) -> int:
    """Compile and print the deterministic invocation set."""
    bundle = load_valid_bundle(document, repository_root=repository_root)
    render_json(
        _compile(
            bundle.documents,
            repository_root,
            exact_bundle_refs(bundle),
        )
    )
    return 0


@app.command
def check(
    document: Annotated[list[Path], Parameter(help="Validated PPF input bundle.")],
    *,
    repository_root: Path,
    tool_environment_root: Path,
) -> int:
    """Verify the locked tool environment and sandbox capabilities."""
    documents = load_valid_bundle(document, repository_root=repository_root).documents
    manifest = by_type(documents, "tool-environment-manifest")
    ToolEnvironmentVerifier().verify(manifest, tool_environment_root)
    sandbox = by_type(documents, "sandbox-profile")
    support = BubblewrapSandbox().evaluate_support(sandbox["profile"])
    render_json({"valid": support.supported, "missing": list(support.missing)})
    return 0 if support.supported else 1


@app.command
def run(
    document: Annotated[list[Path], Parameter(help="Validated PPF input bundle.")],
    *,
    repository_root: Path,
    output_dir: Path,
    tool_environment_root: Path,
) -> int:
    """Execute eligible invocations and write evidence artifacts."""
    bundle = load_valid_bundle(document, repository_root=repository_root)
    documents = bundle.documents
    references = exact_bundle_refs(bundle)
    plan_document = by_type(documents, "evaluation-plan")
    invocation_set = next(
        (
            item
            for item in documents.values()
            if item.get("documentType") == "evaluation-invocation-set"
        ),
        None,
    ) or _compile(documents, repository_root, references)
    binding = by_type(documents, "evaluation-input-binding")
    manifest = by_type(documents, "evaluation-input-manifest")
    request = AssessmentRequest(
        repository_root=repository_root.resolve(),
        tool_environment_root=tool_environment_root.resolve(),
        input_manifest_digest=references[manifest["manifestId"]]["digest"],
        input_binding_ref=references[binding["bindingId"]],
        input_binding_digest=references[binding["bindingId"]]["digest"],
        invocation_set=invocation_set,
        plan=plan_document,
        assessor_profile=by_type(documents, "assessor-profile"),
        environment_profile=by_type(documents, "environment-profile"),
        sandbox_profile=by_type(documents, "sandbox-profile"),
        tool_environment_manifest=by_type(documents, "tool-environment-manifest"),
    )
    verifier = ToolEnvironmentVerifier()
    with tempfile.TemporaryDirectory(prefix="ppf-assessment-") as temporary:
        temporary_root = Path(temporary)
        materialized_root = temporary_root / "tools"
        repository_snapshot = temporary_root / "repository"
        preflight_errors: list[str] = []
        try:
            verifier.materialize(
                request.tool_environment_manifest,
                request.tool_environment_root,
                materialized_root,
            )
        except ToolEnvironmentError as error:
            preflight_errors.append(f"tool snapshot materialization failed: {error}")
            materialized_root = request.tool_environment_root
        try:
            materialize_repository_snapshot(
                request.repository_root,
                repository_snapshot,
                expected_ref=invocation_set["repositoryRef"],
            )
        except (OSError, ValueError) as error:
            preflight_errors.append(f"repository snapshot materialization failed: {error}")
            repository_snapshot = request.repository_root
        store = ContentAddressedArtifactStore(output_dir)
        result = AssessmentService().run(
            replace(
                request,
                repository_root=repository_snapshot,
                tool_environment_root=materialized_root,
                preflight_error="; ".join(preflight_errors) or None,
            ),
            assessor_registry=default_assessor_registry(),
            sandbox=BubblewrapSandbox(),
            clock=SystemClock(),
            artifact_store=store,
            verifier=verifier,
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    stored_artifacts = list(result.artifacts)
    stored_artifacts.append(
        store.put(
            f"{invocation_set['invocationSetId']}.json",
            canonical_json_bytes(invocation_set),
            role="execution-metadata",
            media_type="application/json",
        )
    )
    for envelope in result.envelopes:
        envelope_bytes = canonical_json_bytes(envelope)
        (output_dir / f"{envelope['envelopeId']}.json").write_bytes(envelope_bytes)
    for attempt in result.attempts:
        (output_dir / f"{attempt['attemptId']}.json").write_bytes(pretty_json_bytes(attempt))
    run_identity = {
        "runId": "assessment-run",
        "invocationSetRef": references.get(invocation_set["invocationSetId"])
        or content_ref(invocation_set["invocationSetId"], invocation_set),
    }
    manifest_document = artifact_manifest(
        manifest_id="manifest-assessment-run",
        run_ref=content_ref(
            "assessment-run",
            run_identity,
            uri="embedded:assessment-run",
        ),
        created_at=SystemClock().now(),
        artifacts=stored_artifacts,
    )
    manifest_path = output_dir / "manifest-assessment-run.json"
    manifest_path.write_bytes(pretty_json_bytes(manifest_document))
    index = {
        "operationalSuccess": result.operational_success,
        "artifactManifest": str(manifest_path),
        "envelopeRefs": [
            item["contentRef"]
            for item in manifest_document["artifacts"]
            if item["role"] == "producer-envelope"
        ],
        "attemptRefs": [
            item["contentRef"]
            for item in manifest_document["artifacts"]
            if item["role"] == "operational-attempt"
        ],
    }
    (output_dir / "assessment-index.json").write_bytes(pretty_json_bytes(index))
    render_json(
        {
            "operationalSuccess": result.operational_success,
            "envelopes": len(result.envelopes),
            "attempts": len(result.attempts),
            "index": str(output_dir / "assessment-index.json"),
            "artifactManifest": str(manifest_path),
        }
    )
    return 0 if result.operational_success else 1


@app.command
def replay(counterexample: Path) -> int:
    """Print the digest-bound replay invocation from a counterexample."""
    payload = strict_json_loads(counterexample.read_bytes())
    render_json({"replayInvocation": payload["replayInvocation"]})
    return 0


@app.command
def inspect(output_dir: Path) -> int:
    """Summarize a prior assessment output directory."""
    payload = strict_json_loads((output_dir / "assessment-index.json").read_bytes())
    render_json(
        {
            "operationalSuccess": payload["operationalSuccess"],
            "envelopes": len(payload["envelopeRefs"]),
            "attempts": len(payload["attemptRefs"]),
        }
    )
    return 0


def main() -> int:
    return app()
