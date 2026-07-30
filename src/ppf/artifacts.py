"""Immutable raw artifacts and canonical semantic result projections."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import rfc8785

from .execution_contracts import semantic_projection_digest

Json = Any


def sha256_bytes(content: bytes) -> str:
    """Return the authoritative raw-byte artifact identity."""
    return "sha256:" + hashlib.sha256(content).hexdigest()


@dataclass(frozen=True)
class StoredArtifact:
    """One content-addressed artifact and its presentation metadata."""

    logical_name: str
    role: str
    media_type: str
    size: int
    digest: str
    path: Path

    def as_manifest_entry(self) -> dict[str, Json]:
        return {
            "logicalName": self.logical_name,
            "role": self.role,
            "mediaType": self.media_type,
            "size": self.size,
            "contentRef": {
                "id": self.logical_name,
                "digest": self.digest,
                "uri": f"artifact:{self.digest}",
                "mediaType": self.media_type,
            },
        }


class ContentAddressedArtifactStore:
    """Persist exact bytes under a SHA-256 object namespace."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.objects = root / "objects" / "sha256"

    def put(
        self,
        logical_name: str,
        content: bytes,
        *,
        role: str,
        media_type: str,
    ) -> StoredArtifact:
        digest = sha256_bytes(content)
        target = self.objects / digest.removeprefix("sha256:")
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if target.read_bytes() != content:
                raise OSError(f"artifact digest collision for {digest}")
        else:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=".ppf-artifact-",
                dir=target.parent,
            )
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary_name, target)
            finally:
                if os.path.exists(temporary_name):
                    os.unlink(temporary_name)
        return StoredArtifact(
            logical_name=logical_name,
            role=role,
            media_type=media_type,
            size=len(content),
            digest=digest,
            path=target,
        )


def artifact_manifest(
    *,
    manifest_id: str,
    run_ref: dict[str, Json],
    created_at: str,
    artifacts: list[StoredArtifact],
) -> dict[str, Json]:
    """Build a run-specific manifest; raw execution values may vary."""
    return {
        "documentType": "artifact-manifest",
        "schemaVersion": "0.1.0",
        "manifestId": manifest_id,
        "runRef": run_ref,
        "createdAt": created_at,
        "artifacts": [
            artifact.as_manifest_entry()
            for artifact in sorted(artifacts, key=lambda item: item.logical_name)
        ],
    }


def semantic_projection(
    *,
    projection_id: str,
    input_closure_digest: str,
    normalizer_ref: dict[str, Json],
    invocation_refs: list[str],
    observations: list[dict[str, Json]],
    oracle_results: list[dict[str, Json]],
    admissions: list[dict[str, Json]],
    item_verdicts: list[dict[str, Json]],
    regression_refs: list[dict[str, Json]],
) -> dict[str, Json]:
    """Remove run-specific fields and create a canonically ordered projection."""
    stable_observations = []
    for observation in observations:
        stable_observations.append(
            {
                "caseRef": observation["caseRef"],
                "subjectRef": observation["subjectRef"],
                "probeRef": observation["probeRef"],
                "source": observation["source"],
                "status": observation["status"],
                "normalizedCode": observation["normalizedCode"],
                "payload": observation.get("semanticPayload"),
            }
        )
    stable_observations.sort(
        key=lambda item: (
            item["caseRef"],
            item["subjectRef"],
            item["probeRef"],
            item["source"],
            item["normalizedCode"],
            rfc8785.dumps(item["payload"]),
        )
    )
    projection = {
        "documentType": "evaluation-semantic-projection",
        "schemaVersion": "0.1.0",
        "projectionId": projection_id,
        "inputClosureDigest": input_closure_digest,
        "normalizerRef": normalizer_ref,
        "invocationRefs": sorted(invocation_refs),
        "observations": stable_observations,
        "oracleResults": sorted(oracle_results, key=lambda item: item["id"]),
        "admissions": sorted(admissions, key=lambda item: item["id"]),
        "itemVerdicts": sorted(item_verdicts, key=lambda item: item["id"]),
        "regressionRefs": sorted(regression_refs, key=lambda item: item["id"]),
    }
    projection["projectionDigest"] = semantic_projection_digest(projection)
    return projection


def canonical_json_bytes(document: dict[str, Json]) -> bytes:
    """Serialize control artifacts using RFC 8785 canonical JSON."""
    return rfc8785.dumps(document)


def pretty_json_bytes(document: dict[str, Json]) -> bytes:
    """Serialize user-facing artifacts deterministically."""
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()


def repository_tree_ref(root: Path) -> dict[str, Json]:
    """Lock the exact Git index paths and working-tree bytes used for assessment."""
    completed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-s", "-z"],
        capture_output=True,
        check=True,
    )
    fields = completed.stdout.split(b"\0")
    rows: list[dict[str, Json]] = []
    for field in fields:
        if not field:
            continue
        metadata, raw_path = field.split(b"\t", 1)
        mode, _, stage = metadata.decode("ascii").split()
        path = raw_path.decode("utf-8")
        if stage != "0":
            raise ValueError(f"unmerged repository index entry {path!r}")
        content = (root / path).read_bytes()
        rows.append(
            {
                "path": path,
                "mode": mode,
                "digest": sha256_bytes(content),
            }
        )
    rows.sort(key=lambda item: item["path"])
    digest = sha256_bytes(rfc8785.dumps(rows))
    return {"id": "repository-root", "digest": digest, "uri": f"repository:{digest}"}
