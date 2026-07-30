"""Immutable raw artifacts and canonical semantic result projections."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import rfc8785

from .execution_contracts import semantic_projection_digest

Json = Any


def atomic_write_bytes(path: Path, content: bytes) -> None:
    """Atomically replace one file with complete bytes from the same directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


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

    def stable_payload(value: Json) -> Json:
        if isinstance(value, dict):
            volatile = {
                "artifactRef",
                "completedAt",
                "created",
                "createdAt",
                "durationMs",
                "end",
                "location",
                "rawArtifactRefs",
                "startedAt",
                "start",
                "stderrRef",
                "stdoutRef",
                "timestamp",
                "uri",
                "uuid",
            }
            return {
                key: stable_payload(item)
                for key, item in sorted(value.items())
                if key not in volatile
            }
        if isinstance(value, list):
            return [stable_payload(item) for item in value]
        return value

    stable_observations = []
    for observation in observations:
        payload = observation.get("semanticPayload")
        if payload is None:
            payload = observation.get("payload")
        stable_observations.append(
            {
                "caseRef": observation["caseRef"],
                "subjectRef": observation["subjectRef"],
                "probeRef": observation["probeRef"],
                "source": observation["source"],
                "status": observation["status"],
                "normalizedCode": observation["normalizedCode"],
                "payload": stable_payload(payload),
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


def _repository_rows(root: Path) -> list[dict[str, Json]]:
    """Describe every non-Git member exposed by a repository snapshot."""
    root = root.resolve(strict=True)
    rows: list[dict[str, Json]] = []
    for directory, directory_names, file_names in os.walk(
        root,
        topdown=True,
        followlinks=False,
    ):
        current = Path(directory)
        if current == root:
            directory_names[:] = [name for name in directory_names if name != ".git"]
        symlink_directories = [name for name in directory_names if (current / name).is_symlink()]
        directory_names[:] = [name for name in directory_names if name not in symlink_directories]
        for name in sorted([*symlink_directories, *file_names]):
            candidate = current / name
            relative = candidate.relative_to(root).as_posix()
            metadata = candidate.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                kind = "symlink"
                content = os.readlink(candidate).encode("utf-8", errors="surrogateescape")
            elif stat.S_ISREG(metadata.st_mode):
                kind = "file"
                content = candidate.read_bytes()
            else:
                raise ValueError(f"unsupported repository member {relative!r}")
            rows.append(
                {
                    "path": relative,
                    "kind": kind,
                    "mode": metadata.st_mode & 0o777,
                    "digest": sha256_bytes(content),
                }
            )
    rows.sort(key=lambda item: item["path"])
    return rows


def repository_tree_ref(root: Path) -> dict[str, Json]:
    """Lock every file and symlink that an assessor can see in its snapshot."""
    rows = _repository_rows(root)
    digest = sha256_bytes(rfc8785.dumps(rows))
    return {"id": "repository-root", "digest": digest, "uri": f"repository:{digest}"}


def materialize_repository_snapshot(
    source_root: Path,
    destination_root: Path,
    *,
    expected_ref: dict[str, Json],
) -> dict[str, Json]:
    """Copy and verify the exact repository closure into a disposable root."""
    source = source_root.resolve(strict=True)
    before = repository_tree_ref(source)
    if before != expected_ref:
        raise ValueError("repository tree differs from invocation repositoryRef")
    shutil.copytree(
        source,
        destination_root,
        symlinks=True,
        ignore=shutil.ignore_patterns(".git"),
    )
    snapshot_ref = repository_tree_ref(destination_root)
    if snapshot_ref != expected_ref:
        raise ValueError("repository changed during snapshot materialization")
    after = repository_tree_ref(source)
    if after != before:
        raise ValueError("repository changed during snapshot materialization")
    return snapshot_ref
