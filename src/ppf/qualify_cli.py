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
)
from .cli_common import (
    by_type,
    content_ref,
    exact_bundle_refs,
    load_valid_bundle,
    render_json,
)
from .qualification import QualificationRequest, QualificationService

Json = Any

app = App(
    name="ppf-qualify",
    help="Apply PPF oracles, evidence admission, and qualification judgment.",
    result_action="return_value",
)


def _execute(
    documents: dict[str, dict[str, Json]],
    assessment_index: Path,
    references: dict[str, dict[str, Json]],
) -> tuple[dict[str, Json], str, dict[str, Json]]:
    assessment = json.loads(assessment_index.read_bytes())
    observations = tuple(
        observation
        for envelope in assessment["envelopes"]
        for observation in envelope["observations"]
    )
    attempts = tuple(assessment["attempts"])
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
        input_closure_digest=by_type(
            documents, "evaluation-input-binding"
        )["closureDigest"],
        normalizer_ref={
            "id": "ppf-semantic-normalizer",
            "digest": "sha256:" + hashlib.sha256(normalizer_source).hexdigest(),
            "uri": "python:ppf.artifacts.semantic_projection",
        },
        invocation_refs=[
            execution["invocationRef"]["id"]
            for envelope in assessment["envelopes"]
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
    matches = [
        verdict for verdict in document["itemVerdicts"] if verdict["itemRef"] == item_ref
    ]
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
    verdicts = [
        item for item in document["itemVerdicts"] if item["itemRef"] == item_ref
    ]
    admission_ids = {
        reference
        for verdict in verdicts
        for reference in (
            verdict["admittedEvidenceRefs"] + verdict["rejectedEvidenceRefs"]
        )
    }
    admissions = [
        item for item in document["admissions"] if item["id"] in admission_ids
    ]
    render_json({"itemVerdicts": verdicts, "admissions": admissions})
    return 0 if verdicts else 2


def main() -> int:
    return app()
