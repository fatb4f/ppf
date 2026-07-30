"""Cyclopts command adapter for oracle evaluation and evidence admission."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Annotated, Any

from cyclopts import App, Parameter

from .artifacts import (
    ContentAddressedArtifactStore,
    artifact_manifest,
    canonical_json_bytes,
    pretty_json_bytes,
    semantic_projection,
    sha256_bytes,
)
from .catalog import SchemaCatalog
from .cli_common import (
    by_type,
    content_ref,
    exact_bundle_refs,
    load_valid_bundle,
    render_json,
)
from .core import validate_semantics
from .invocations import compile_invocation_set
from .qualification import QualificationRequest, QualificationService

Json = Any

app = App(
    name="ppf-qualify",
    help="Apply PPF oracles, evidence admission, and qualification judgment.",
    result_action="return_value",
)


def _matching_ref(
    actual: dict[str, Json],
    expected: dict[str, Json],
) -> bool:
    return actual.get("id") == expected.get("id") and actual.get("digest") == expected.get("digest")


def _verified_assessment(
    assessment_index: Path,
    documents: dict[str, dict[str, Json]],
    references: dict[str, dict[str, Json]],
) -> tuple[
    list[dict[str, Json]],
    tuple[dict[str, Json], ...],
    tuple[dict[str, Json], ...],
]:
    """Load only manifest-addressed, digest-verified assessment artifacts."""
    manifest_path = assessment_index.parent / "manifest-assessment-run.json"
    manifest = json.loads(manifest_path.read_bytes())
    catalog = SchemaCatalog.load()
    errors = list(catalog.validator("artifact-manifest").iter_errors(manifest))
    if errors or validate_semantics(manifest):
        raise ValueError("invalid assessment artifact manifest")
    verified: dict[str, tuple[dict[str, Json], bytes]] = {}
    for entry in manifest["artifacts"]:
        reference = entry["contentRef"]
        if reference["id"] in verified:
            raise ValueError(f"duplicate assessment artifact id {reference['id']!r}")
        digest = reference["digest"]
        if reference.get("uri") != f"artifact:{digest}":
            raise ValueError(f"non-addressed assessment artifact {reference['id']!r}")
        raw = (
            manifest_path.parent / "objects" / "sha256" / digest.removeprefix("sha256:")
        ).read_bytes()
        if sha256_bytes(raw) != digest or len(raw) != entry["size"]:
            raise ValueError(f"assessment artifact integrity failure: {reference['id']!r}")
        verified[reference["id"]] = (entry, raw)

    metadata = [
        json.loads(raw) for entry, raw in verified.values() if entry["role"] == "execution-metadata"
    ]
    if len(metadata) != 1 or metadata[0].get("documentType") != "evaluation-invocation-set":
        raise ValueError("assessment manifest requires one invocation-set artifact")
    invocation_set = metadata[0]
    if list(catalog.validator("evaluation-invocation-set").iter_errors(invocation_set)):
        raise ValueError("invalid assessment invocation set")
    plan = by_type(documents, "evaluation-plan")
    stages = by_type(documents, "stage-registry")
    assessors = by_type(documents, "assessor-profile")
    environment = by_type(documents, "environment-profile")
    sandbox = by_type(documents, "sandbox-profile")
    expected_invocation_set = compile_invocation_set(
        invocation_set_id=invocation_set["invocationSetId"],
        plan=plan,
        plan_ref=references[plan["planId"]],
        stage_registry=stages,
        stage_registry_ref=references[stages["registryId"]],
        assessor_profile=assessors,
        assessor_profile_ref=references[assessors["profileId"]],
        repository_ref=invocation_set["repositoryRef"],
        environment_ref=environment["environmentId"],
        sandbox_ref=sandbox["sandboxId"],
    )
    if expected_invocation_set != invocation_set:
        raise ValueError("assessment invocation set differs from bound inputs")
    invocations = {
        invocation["invocationId"]: invocation for invocation in invocation_set["invocations"]
    }

    binding = by_type(documents, "evaluation-input-binding")
    manifest_input = by_type(documents, "evaluation-input-manifest")
    binding_ref = references[binding["bindingId"]]
    manifest_digest = references[manifest_input["manifestId"]]["digest"]
    raw_refs = {
        identifier: entry["contentRef"]
        for identifier, (entry, _) in verified.items()
        if entry["role"] in {"stdout", "stderr", "events", "native-report"}
    }
    envelopes: list[dict[str, Json]] = []
    for entry, raw in verified.values():
        if entry["role"] != "producer-envelope":
            continue
        envelope = json.loads(raw)
        envelope_errors = list(
            catalog.validator("evaluation-producer-envelope").iter_errors(envelope)
        )
        if envelope_errors:
            raise ValueError(
                f"invalid producer envelope {envelope.get('envelopeId')!r}: "
                + "; ".join(error.message for error in envelope_errors)
            )
        if validate_semantics(envelope):
            raise ValueError(f"invalid producer envelope closure {envelope['envelopeId']!r}")
        if not _matching_ref(envelope["inputBindingRef"], binding_ref):
            raise ValueError("producer envelope input binding mismatch")
        if envelope["inputBindingDigest"] != binding_ref["digest"]:
            raise ValueError("producer envelope input binding digest mismatch")
        executions = {item["record"]["id"]: item for item in envelope["executions"]}
        observations = {item["id"]: item for item in envelope["observations"]}
        fragment = envelope["fragment"]
        if set(fragment["executionRefs"]) != set(executions):
            raise ValueError("producer envelope execution closure mismatch")
        if set(fragment["observationRefs"]) != set(observations):
            raise ValueError("producer envelope observation closure mismatch")
        if fragment["inputManifestDigest"] != manifest_digest:
            raise ValueError("producer envelope input manifest mismatch")
        for execution in executions.values():
            invocation_id = execution["invocationRef"]["id"]
            invocation = invocations.get(invocation_id)
            if invocation is None:
                raise ValueError(f"unknown invocation reference {invocation_id!r}")
            expected = content_ref(
                invocation_id,
                invocation,
                uri=f"embedded:{invocation_id}",
            )
            if not _matching_ref(execution["invocationRef"], expected):
                raise ValueError(f"invocation digest mismatch {invocation_id!r}")
            record = execution["record"]
            if record["inputManifestDigest"] != manifest_digest:
                raise ValueError("execution input manifest mismatch")
            if record["invocation"]["workingDirectoryRef"] != invocation["workingDirectoryRef"]:
                raise ValueError("execution working-directory binding mismatch")
            if set(record["invocation"].get("inputArtifactRefs", [])) != {
                invocation["environmentRef"],
                invocation["sandboxRef"],
            }:
                raise ValueError("execution environment or sandbox binding mismatch")
            if {
                (reference["id"], reference["digest"]) for reference in record["rawArtifactRefs"]
            } != {
                (reference["id"], reference["digest"]) for reference in execution["rawArtifactRefs"]
            }:
                raise ValueError("execution raw artifact closure mismatch")
            for reference in execution["rawArtifactRefs"]:
                if not _matching_ref(
                    reference,
                    raw_refs.get(reference["id"], {}),
                ):
                    raise ValueError(f"unverified raw artifact {reference['id']!r}")
        for reference in fragment["artifactRefs"]:
            if not _matching_ref(reference, raw_refs.get(reference["id"], {})):
                raise ValueError(f"unverified fragment artifact {reference['id']!r}")
        envelopes.append(envelope)

    attempts: list[dict[str, Json]] = []
    for entry, raw in verified.values():
        if entry["role"] != "operational-attempt":
            continue
        attempt = json.loads(raw)
        if list(catalog.validator("operational-attempt").iter_errors(attempt)):
            raise ValueError(f"invalid operational attempt {attempt.get('attemptId')!r}")
        invocation = invocations.get(attempt["invocationRef"]["id"])
        if invocation is None:
            raise ValueError("operational attempt has unknown invocation")
        expected = content_ref(
            invocation["invocationId"],
            invocation,
            uri=f"embedded:{invocation['invocationId']}",
        )
        if not _matching_ref(attempt["invocationRef"], expected):
            raise ValueError("operational attempt invocation digest mismatch")
        attempts.append(attempt)
    return (
        envelopes,
        tuple(observation for envelope in envelopes for observation in envelope["observations"]),
        tuple(attempts),
    )


def _execute(
    documents: dict[str, dict[str, Json]],
    assessment_index: Path,
    references: dict[str, dict[str, Json]],
) -> tuple[dict[str, Json], str, dict[str, Json]]:
    envelopes, observations, attempts = _verified_assessment(
        assessment_index,
        documents,
        references,
    )
    plan = by_type(documents, "evaluation-plan")
    profile = by_type(documents, "generation-policy-profile")
    run = next(
        (
            document
            for document in documents.values()
            if document.get("documentType") == "evaluation-run"
        ),
        {
            "documentType": "evaluation-run",
            "schemaVersion": "0.2.0",
            "runId": "qualification-run",
        },
    )
    run_ref = references.get(run["runId"]) or content_ref(
        run["runId"], run, uri=f"embedded:{run['runId']}"
    )
    result = QualificationService().run(
        QualificationRequest(
            run_ref=run_ref,
            profile_ref=references[profile["profileId"]],
            profile=profile,
            plan=plan,
            evidence_catalog=by_type(documents, "evaluation-evidence-catalog"),
            observations=observations,
            attempts=attempts,
        )
    )
    normalizer_source = Path(__file__).with_name("artifacts.py").read_bytes()
    projection = semantic_projection(
        projection_id=f"projection-{run['runId']}",
        input_closure_digest=by_type(documents, "evaluation-input-binding")["closureDigest"],
        normalizer_ref={
            "id": "ppf-semantic-normalizer",
            "digest": "sha256:" + hashlib.sha256(normalizer_source).hexdigest(),
            "uri": "python:ppf.artifacts.semantic_projection",
        },
        invocation_refs=[
            execution["invocationRef"]["id"]
            for envelope in envelopes
            for execution in envelope["executions"]
        ],
        observations=list(observations),
        oracle_results=list(result.oracle_results),
        admissions=result.report["admissions"],
        item_verdicts=result.report["itemVerdicts"],
        regression_refs=[],
    )
    return result.report, result.verdict, projection


@app.command
def run(
    document: Annotated[list[Path], Parameter(help="Validated PPF input bundle.")],
    *,
    repository_root: Path,
    assessment_index: Path,
    output_dir: Path,
) -> int:
    """Qualify a complete assessment result."""
    documents = load_valid_bundle(document, repository_root=repository_root)
    report, verdict, projection = _execute(
        documents,
        assessment_index,
        exact_bundle_refs(document),
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    store = ContentAddressedArtifactStore(output_dir)
    report_path = output_dir / f"{report['reportId']}.json"
    projection_path = output_dir / f"{projection['projectionId']}.json"
    report_bytes = canonical_json_bytes(report)
    projection_bytes = canonical_json_bytes(projection)
    report_path.write_bytes(report_bytes)
    projection_path.write_bytes(projection_bytes)
    stored = [
        store.put(
            report_path.name,
            report_bytes,
            role="qualification-report",
            media_type="application/json",
        ),
        store.put(
            projection_path.name,
            projection_bytes,
            role="semantic-projection",
            media_type="application/json",
        ),
    ]
    manifest = artifact_manifest(
        manifest_id="manifest-qualification-run",
        run_ref=report["runRef"],
        created_at=report["generatedAt"],
        artifacts=stored,
    )
    manifest_path = output_dir / "manifest-qualification-run.json"
    manifest_path.write_bytes(pretty_json_bytes(manifest))
    render_json(
        {
            "verdict": verdict,
            "report": str(report_path),
            "semanticProjection": str(projection_path),
            "artifactManifest": str(manifest_path),
        }
    )
    return 0 if verdict == "pass" else 1 if verdict == "fail" else 2


@app.command
def item(report: Path, item_ref: str) -> int:
    """Print one item verdict from a qualification report."""
    document = json.loads(report.read_bytes())
    matches = [verdict for verdict in document["itemVerdicts"] if verdict["itemRef"] == item_ref]
    if not matches:
        render_json({"valid": False, "error": f"unknown item {item_ref!r}"})
        return 2
    render_json({"valid": True, "itemVerdicts": matches})
    return 0


@app.command
def report(path: Path) -> int:
    """Print a stable qualification-report summary."""
    document = json.loads(path.read_bytes())
    render_json({"reportId": document["reportId"], "summary": document["summary"]})
    return 0


@app.command
def explain(path: Path, item_ref: str) -> int:
    """Explain admissions and missing evidence for an item."""
    document = json.loads(path.read_bytes())
    verdicts = [item for item in document["itemVerdicts"] if item["itemRef"] == item_ref]
    admission_ids = {
        reference
        for verdict in verdicts
        for reference in (verdict["admittedEvidenceRefs"] + verdict["rejectedEvidenceRefs"])
    }
    admissions = [item for item in document["admissions"] if item["id"] in admission_ids]
    render_json({"itemVerdicts": verdicts, "admissions": admissions})
    return 0 if verdicts else 2


def main() -> int:
    return app()
