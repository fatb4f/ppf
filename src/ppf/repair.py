"""Bounded repair in disposable Git worktrees with verified tree promotion."""

from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import rfc8785

from .catalog import SchemaCatalog
from .core import validate_semantics

Json = Any
_FORBIDDEN_MODES = {"120000", "160000"}
_REGULAR_MODES = {"100644", "100755"}


class RepairError(RuntimeError):
    """Raised before an unverified repaired tree can be promoted."""


@dataclass(frozen=True)
class _DiffEntry:
    old_mode: str
    new_mode: str
    status: str
    path: str


@dataclass(frozen=True)
class PreparedRepair:
    """A validated repair record and its pending CAS promotion."""

    record: dict[str, Json]
    repository: Path
    repair_ref: str
    result_commit: str
    expected_ref: str
    decision_id: str


def _git(
    repository: Path,
    arguments: list[str],
    *,
    input_bytes: bytes | None = None,
    environment: dict[str, str] | None = None,
) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        input=input_bytes,
        capture_output=True,
        check=False,
        env=environment,
    )
    if completed.returncode:
        raise RepairError(
            completed.stderr.decode("utf-8", errors="replace").strip()
            or f"git command failed: {arguments!r}"
        )
    return completed.stdout


def _safe_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] == ".git":
        raise RepairError(f"unsafe changed path {value!r}")
    return path


def _matches(path: str, rule: str) -> bool:
    normalized = rule.rstrip("/")
    return path == normalized or (rule.endswith("/") and path.startswith(rule))


def _parse_raw_diff(content: bytes) -> list[_DiffEntry]:
    fields = content.split(b"\0")
    entries: list[_DiffEntry] = []
    index = 0
    while index < len(fields) and fields[index]:
        header = fields[index].decode("ascii")
        index += 1
        parts = header.split()
        if len(parts) != 5 or not parts[0].startswith(":"):
            raise RepairError("malformed raw Git diff")
        path = fields[index].decode("utf-8", errors="strict")
        index += 1
        status = parts[4]
        if status.startswith(("R", "C")):
            raise RepairError("rename and copy records are forbidden")
        entries.append(
            _DiffEntry(
                old_mode=parts[0][1:],
                new_mode=parts[1],
                status=status,
                path=path,
            )
        )
    return entries


def _verify_diff(
    worktree: Path,
    entries: list[_DiffEntry],
    *,
    permitted: list[str],
    forbidden: list[str],
) -> list[str]:
    if not entries:
        raise RepairError("repair patch produced no tree changes")
    changed: list[str] = []
    submodules = {
        line.split(maxsplit=3)[3]
        for line in _git(worktree, ["ls-files", "--stage"]).decode().splitlines()
        if line.startswith("160000 ")
    }
    for entry in entries:
        path = _safe_path(entry.path).as_posix()
        if not any(_matches(path, rule) for rule in permitted):
            raise RepairError(f"changed path is not permitted: {path!r}")
        if any(_matches(path, rule) for rule in forbidden):
            raise RepairError(f"changed path is forbidden: {path!r}")
        if entry.old_mode in _FORBIDDEN_MODES or entry.new_mode in _FORBIDDEN_MODES:
            raise RepairError(f"symlink or submodule transition is forbidden: {path!r}")
        if entry.old_mode != "000000" and entry.new_mode != "000000":
            if entry.old_mode != entry.new_mode:
                raise RepairError(f"file mode changes are forbidden: {path!r}")
        elif entry.old_mode == "000000" and entry.new_mode not in {"100644"}:
            raise RepairError(f"new files must be regular non-executable files: {path!r}")
        elif entry.new_mode == "000000" and entry.old_mode not in _REGULAR_MODES:
            raise RepairError(f"unsupported deleted file type: {path!r}")
        if any(path == submodule or path.startswith(f"{submodule}/") for submodule in submodules):
            raise RepairError(f"submodule boundary is forbidden: {path!r}")
        candidate = worktree / path
        current = candidate.parent
        while current != worktree:
            if current.is_symlink():
                raise RepairError(f"path crosses a symlink: {path!r}")
            current = current.parent
        if candidate.exists() and candidate.is_symlink():
            raise RepairError(f"symlink output is forbidden: {path!r}")
        changed.append(path)
    return sorted(changed)


class RepairService:
    """Apply, inspect, record, and atomically promote one bounded patch."""

    def prepare(
        self,
        *,
        repository: Path,
        workflow_id: str,
        decision: dict[str, Json],
        decision_ref: dict[str, Json],
        patch: bytes,
        applied_at: str,
    ) -> PreparedRepair:
        if decision["decision"] != "repair" or decision["remainingCycles"] < 1:
            raise RepairError("repair is not authorized or its budget is exhausted")
        patch_digest = "sha256:" + hashlib.sha256(patch).hexdigest()
        if patch_digest != decision["patchRef"]["digest"]:
            raise RepairError("requested patch digest differs from the repair decision")
        repository = repository.resolve(strict=True)
        base_commit = (
            _git(repository, ["rev-parse", "--verify", f"{decision['baseCommit']}^{{commit}}"])
            .decode()
            .strip()
        )
        if base_commit != decision["baseCommit"]:
            raise RepairError("base commit identity mismatch")
        base_tree = _git(repository, ["rev-parse", f"{base_commit}^{{tree}}"]).decode().strip()
        if base_tree != decision["baseTree"]:
            raise RepairError("base tree identity mismatch")

        object_format = _git(repository, ["rev-parse", "--show-object-format"]).decode().strip()
        object_lengths = {"sha1": 40, "sha256": 64}
        if object_format not in object_lengths:
            raise RepairError(f"unsupported Git object format {object_format!r}")
        zero_oid = "0" * object_lengths[object_format]
        repair_ref = f"refs/ppf/repairs/{workflow_id}"
        existing = subprocess.run(
            ["git", "-C", str(repository), "rev-parse", "--verify", repair_ref],
            capture_output=True,
            check=False,
        )
        expected_ref = existing.stdout.decode().strip() if existing.returncode == 0 else zero_oid
        if expected_ref != zero_oid and expected_ref != base_commit:
            raise RepairError("repair ref does not match the decision base commit")

        with tempfile.TemporaryDirectory(prefix="ppf-repair-") as temporary:
            worktree = Path(temporary) / "worktree"
            _git(
                repository,
                ["worktree", "add", "--detach", "--no-checkout", str(worktree), base_commit],
            )
            try:
                _git(worktree, ["checkout", "--detach", base_commit])
                _git(
                    worktree,
                    ["apply", "--index", "--binary", "--whitespace=error-all", "-"],
                    input_bytes=patch,
                )
                status = _git(worktree, ["status", "--porcelain=v2", "-z"])
                if b"? " in status or b"! " in status:
                    raise RepairError("repair produced untracked or ignored changes")
                raw_diff = _git(
                    worktree,
                    ["diff", "--cached", "--raw", "-z", "--no-renames", "HEAD"],
                )
                entries = _parse_raw_diff(raw_diff)
                changed_paths = _verify_diff(
                    worktree,
                    entries,
                    permitted=decision["permittedPaths"],
                    forbidden=decision["forbiddenPaths"],
                )
                canonical_diff = _git(
                    worktree,
                    [
                        "diff",
                        "--cached",
                        "--binary",
                        "--full-index",
                        "--no-renames",
                        "HEAD",
                    ],
                )
                canonical_diff_digest = "sha256:" + hashlib.sha256(canonical_diff).hexdigest()
                result_tree = _git(worktree, ["write-tree"]).decode().strip()
                environment = {
                    **os.environ,
                    "GIT_AUTHOR_NAME": "PPF Repair Actor",
                    "GIT_AUTHOR_EMAIL": "ppf-repair@invalid",
                    "GIT_COMMITTER_NAME": "PPF Repair Actor",
                    "GIT_COMMITTER_EMAIL": "ppf-repair@invalid",
                    "GIT_AUTHOR_DATE": applied_at,
                    "GIT_COMMITTER_DATE": applied_at,
                }
                result_commit = (
                    _git(
                        worktree,
                        ["commit-tree", result_tree, "-p", base_commit],
                        input_bytes=f"PPF repair {decision['decisionId']}\n".encode(),
                        environment=environment,
                    )
                    .decode()
                    .strip()
                )
                record = {
                    "documentType": "repair-application-record",
                    "schemaVersion": "0.1.0",
                    "recordId": f"record-{decision['decisionId']}",
                    "decisionRef": decision_ref,
                    "baseCommit": base_commit,
                    "baseTree": base_tree,
                    "requestedPatchDigest": patch_digest,
                    "canonicalDiffDigest": canonical_diff_digest,
                    "resultTree": result_tree,
                    "resultCommit": result_commit,
                    "changedPaths": changed_paths,
                    "promotedRef": repair_ref,
                    "appliedAt": applied_at,
                }
                # Recompute every value represented in the record before promotion.
                if _git(worktree, ["write-tree"]).decode().strip() != record["resultTree"]:
                    raise RepairError("result tree changed during repair verification")
                if (
                    "sha256:" + hashlib.sha256(canonical_diff).hexdigest()
                    != record["canonicalDiffDigest"]
                ):
                    raise RepairError("canonical repair diff changed during verification")
                rfc8785.dumps(record)
                structural_errors = list(
                    SchemaCatalog.load().validator("repair-application-record").iter_errors(record)
                )
                semantic_errors = validate_semantics(record)
                if structural_errors or semantic_errors:
                    details = [
                        *(error.message for error in structural_errors),
                        *(error.message for error in semantic_errors),
                    ]
                    raise RepairError("invalid repair application record: " + "; ".join(details))
                return PreparedRepair(
                    record=record,
                    repository=repository,
                    repair_ref=repair_ref,
                    result_commit=result_commit,
                    expected_ref=expected_ref,
                    decision_id=decision["decisionId"],
                )
            finally:
                subprocess.run(
                    ["git", "-C", str(repository), "worktree", "remove", "--force", str(worktree)],
                    capture_output=True,
                    check=False,
                )

    def promote(self, prepared: PreparedRepair) -> dict[str, Json]:
        """CAS-promote a repair whose complete record is already valid."""
        _git(
            prepared.repository,
            [
                "update-ref",
                "-m",
                f"PPF repair {prepared.decision_id}",
                prepared.repair_ref,
                prepared.result_commit,
                prepared.expected_ref,
            ],
        )
        return prepared.record

    def apply(
        self,
        *,
        repository: Path,
        workflow_id: str,
        decision: dict[str, Json],
        decision_ref: dict[str, Json],
        patch: bytes,
        applied_at: str,
    ) -> dict[str, Json]:
        """Compatibility API for callers without an external record store."""
        prepared = self.prepare(
            repository=repository,
            workflow_id=workflow_id,
            decision=decision,
            decision_ref=decision_ref,
            patch=patch,
            applied_at=applied_at,
        )
        return self.promote(prepared)
