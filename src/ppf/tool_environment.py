"""Verification and resolution of complete locked tool environments."""

from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import rfc8785

Json = Any


class ToolEnvironmentError(RuntimeError):
    """Raised when an execution environment differs from its manifest."""


def _safe_relative(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ToolEnvironmentError(f"unsafe environment path {value!r}")
    return path


def _file_manifest_digest(root: Path, paths: list[str]) -> str:
    rows: list[dict[str, Json]] = []
    for value in sorted(paths):
        relative = _safe_relative(value)
        candidate = root.joinpath(*relative.parts)
        try:
            stat = candidate.lstat()
        except OSError as error:
            raise ToolEnvironmentError(f"cannot inspect {value!r}: {error}") from error
        if candidate.is_symlink():
            target = os.readlink(candidate)
            resolved = candidate.resolve()
            if not resolved.is_relative_to(root.resolve()):
                raise ToolEnvironmentError(f"environment symlink escapes root: {value!r}")
            content = target.encode()
            kind = "symlink"
        elif candidate.is_file():
            content = candidate.read_bytes()
            kind = "file"
        else:
            raise ToolEnvironmentError(f"environment member is not a file: {value!r}")
        rows.append(
            {
                "path": relative.as_posix(),
                "kind": kind,
                "mode": stat.st_mode & 0o777,
                "digest": "sha256:" + hashlib.sha256(content).hexdigest(),
            }
        )
    return "sha256:" + hashlib.sha256(rfc8785.dumps(rows)).hexdigest()


def _actual_files(root: Path) -> set[str]:
    return {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if (path.is_file() or path.is_symlink())
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
    }


@dataclass(frozen=True)
class ResolvedEntrypoint:
    """An entrypoint proven to belong to the verified environment."""

    entrypoint_id: str
    argv_prefix: tuple[str, ...]
    environment_root: Path


class ToolEnvironmentVerifier:
    """Verify an exact installed tree and resolve only declared entrypoints."""

    def verify(
        self,
        manifest: dict[str, Json],
        environment_root: Path,
    ) -> dict[str, ResolvedEntrypoint]:
        root = environment_root.resolve(strict=True)
        declared_files = manifest["environmentFiles"]
        actual_files = _actual_files(root)
        if actual_files != set(declared_files):
            missing = sorted(set(declared_files) - actual_files)
            unexpected = sorted(actual_files - set(declared_files))
            raise ToolEnvironmentError(
                f"environment file closure mismatch: missing={missing!r}, "
                f"unexpected={unexpected!r}"
            )
        actual_environment_digest = _file_manifest_digest(root, declared_files)
        if actual_environment_digest != manifest["environmentDigest"]:
            raise ToolEnvironmentError("environment tree digest mismatch")

        runtime = manifest["runtime"]
        self._verify_content_ref(root, runtime["executableRef"])
        self._verify_content_ref(root, manifest["lockfileRef"])
        if _file_manifest_digest(root, runtime["stdlibFiles"]) != runtime["stdlibTreeDigest"]:
            raise ToolEnvironmentError("Python standard-library digest mismatch")
        for distribution in manifest["distributions"]:
            for artifact_ref in distribution["artifactRefs"]:
                self._verify_content_ref(root, artifact_ref)
            if (
                _file_manifest_digest(root, distribution["installedFiles"])
                != distribution["installedTreeDigest"]
            ):
                raise ToolEnvironmentError(
                    f"installed distribution tree mismatch: {distribution['id']}"
                )

        distributions = {item["id"] for item in manifest["distributions"]}
        resolved: dict[str, ResolvedEntrypoint] = {}
        python_uri = runtime["executableRef"].get("uri")
        if not isinstance(python_uri, str):
            raise ToolEnvironmentError("runtime executable requires a local URI")
        python = root.joinpath(*_safe_relative(python_uri).parts)
        if not python.is_file():
            raise ToolEnvironmentError("runtime executable is unavailable")
        for entrypoint in manifest["entrypoints"]:
            if entrypoint["distributionRef"] not in distributions:
                raise ToolEnvironmentError(
                    f"entrypoint has unknown distribution: {entrypoint['id']}"
                )
            if entrypoint["module"] is not None:
                python_inside = "/" + _safe_relative(python_uri).as_posix()
                prefix = (python_inside, "-I", "-m", entrypoint["module"])
            else:
                executable = root.joinpath(
                    *_safe_relative(entrypoint["relativeExecutable"]).parts
                )
                if not executable.is_file():
                    raise ToolEnvironmentError(
                        f"entrypoint executable is unavailable: {entrypoint['id']}"
                    )
                prefix = (
                    "/" + _safe_relative(entrypoint["relativeExecutable"]).as_posix(),
                )
            resolved[entrypoint["id"]] = ResolvedEntrypoint(
                entrypoint_id=entrypoint["id"],
                argv_prefix=prefix,
                environment_root=root,
            )
        ansible = manifest.get("ansible")
        if isinstance(ansible, dict):
            self._verify_content_ref(root, ansible["configurationRef"])
            for field in ("collectionRefs", "pluginRefs", "inventoryPluginRefs"):
                for reference in ansible[field]:
                    self._verify_content_ref(root, reference)
        return resolved

    def materialize(
        self,
        manifest: dict[str, Json],
        source_root: Path,
        destination_root: Path,
    ) -> dict[str, ResolvedEntrypoint]:
        """Copy a verified closure into a disposable, independently verified root."""
        source = source_root.resolve(strict=True)
        before = _file_manifest_digest(source, manifest["environmentFiles"])
        if before != manifest["environmentDigest"]:
            raise ToolEnvironmentError("source environment tree digest mismatch")
        destination_root.mkdir(parents=True, exist_ok=False)
        for value in manifest["environmentFiles"]:
            relative = _safe_relative(value)
            source_file = source.joinpath(*relative.parts)
            destination_file = destination_root.joinpath(*relative.parts)
            destination_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_file, destination_file, follow_symlinks=False)
        after = _file_manifest_digest(source, manifest["environmentFiles"])
        if after != before:
            raise ToolEnvironmentError("source environment changed during materialization")
        return self.verify(manifest, destination_root)

    @staticmethod
    def _verify_content_ref(root: Path, reference: dict[str, Json]) -> None:
        uri = reference.get("uri")
        if not isinstance(uri, str):
            raise ToolEnvironmentError(
                f"locked content {reference.get('id')!r} requires a local URI"
            )
        candidate = root.joinpath(*_safe_relative(uri).parts)
        if not candidate.is_file():
            raise ToolEnvironmentError(f"locked content is unavailable: {uri!r}")
        digest = "sha256:" + hashlib.sha256(candidate.read_bytes()).hexdigest()
        if digest != reference["digest"]:
            raise ToolEnvironmentError(f"locked content digest mismatch: {uri!r}")
