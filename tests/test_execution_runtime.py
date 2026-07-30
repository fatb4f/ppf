from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from ppf.artifacts import (
    materialize_repository_snapshot,
    repository_tree_ref,
    semantic_projection,
)
from ppf.execution import (
    BubblewrapSandbox,
    PreparedInvocation,
    SandboxPreparationError,
    _writable_mount,
)
from ppf.invocations import (
    InvocationCompilationError,
    compile_invocation_set,
    stable_stage_order,
)
from ppf.repair import RepairError, RepairService
from ppf.tool_environment import (
    ToolEnvironmentError,
    ToolEnvironmentVerifier,
    _file_manifest_digest,
)

DIGEST = "sha256:" + ("1" * 64)


def _ref(identifier: str) -> dict[str, str]:
    return {"id": identifier, "digest": DIGEST, "uri": f"https://example.invalid/{identifier}"}


def test_stable_topological_order_uses_declaration_index_for_ready_stages() -> None:
    registry = {
        "stages": [
            {"id": "beta", "kind": "behavioral"},
            {"id": "alpha", "kind": "typing"},
            {"id": "final", "kind": "qualification", "dependsOn": ["alpha", "beta"]},
        ]
    }
    assert stable_stage_order(registry) == ["beta", "alpha", "final"]


def test_invocation_compilation_is_total_and_rejects_duplicate_pairings() -> None:
    stages = {"stages": [{"id": "typing", "kind": "typing"}]}
    case = {
        "id": "case-ho-01",
        "claimRef": "HO-01",
        "stage": "typing",
        "probe": {"probeRef": "ty-probe", "configuration": {"argv": ["ty-tool", "check"]}},
    }
    plan = {"cases": [case]}
    assessor = {
        "id": "ty-assessor",
        "kind": "ty",
        "executableRef": "ty-tool",
        "adapterRef": _ref("adapter"),
        "normalizerRef": _ref("normalizer"),
        "probeRefs": ["ty-probe"],
    }
    profile = {"assessors": [assessor]}
    result = compile_invocation_set(
        invocation_set_id="invocations-ho-01",
        plan=plan,
        plan_ref=_ref("plan"),
        stage_registry=stages,
        stage_registry_ref=_ref("stages"),
        assessor_profile=profile,
        assessor_profile_ref=_ref("assessors"),
        repository_ref=_ref("repository"),
        environment_ref="environment",
        sandbox_ref="sandbox",
    )
    assert [item["sequence"] for item in result["invocations"]] == [10]
    assert result["invocations"][0]["invocationId"].startswith("invoke-")

    with pytest.raises(InvocationCompilationError, match="duplicate case/assessor"):
        compile_invocation_set(
            invocation_set_id="invocations-ho-01",
            plan=plan,
            plan_ref=_ref("plan"),
            stage_registry=stages,
            stage_registry_ref=_ref("stages"),
            assessor_profile={"assessors": [assessor, assessor]},
            assessor_profile_ref=_ref("assessors"),
            repository_ref=_ref("repository"),
            environment_ref="environment",
            sandbox_ref="sandbox",
        )


def _raw_ref(identifier: str, path: str, content: bytes) -> dict[str, str]:
    return {
        "id": identifier,
        "digest": "sha256:" + hashlib.sha256(content).hexdigest(),
        "uri": path,
    }


def test_tool_environment_verifies_complete_tree_and_rejects_drift(tmp_path: Path) -> None:
    (tmp_path / "bin").mkdir()
    (tmp_path / "lib").mkdir()
    (tmp_path / "artifacts").mkdir()
    (tmp_path / "bin/python").write_bytes(b"python")
    (tmp_path / "bin/python").chmod(0o755)
    (tmp_path / "lib/stdlib.py").write_bytes(b"stdlib")
    (tmp_path / "lib/package.py").write_bytes(b"package")
    (tmp_path / "uv.lock").write_bytes(b"lock")
    (tmp_path / "artifacts/package.whl").write_bytes(b"wheel")
    files = [
        "artifacts/package.whl",
        "bin/python",
        "lib/package.py",
        "lib/stdlib.py",
        "uv.lock",
    ]
    manifest = {
        "runtime": {
            "implementation": "cpython",
            "version": "3.14",
            "executableRef": _raw_ref("python", "bin/python", b"python"),
            "stdlibTreeDigest": _file_manifest_digest(tmp_path, ["lib/stdlib.py"]),
            "stdlibFiles": ["lib/stdlib.py"],
        },
        "lockfileRef": _raw_ref("lock", "uv.lock", b"lock"),
        "environmentDigest": _file_manifest_digest(tmp_path, files),
        "environmentFiles": files,
        "distributions": [
            {
                "id": "package",
                "name": "package",
                "version": "1",
                "artifactRefs": [_raw_ref("package-wheel", "artifacts/package.whl", b"wheel")],
                "installedTreeDigest": _file_manifest_digest(tmp_path, ["lib/package.py"]),
                "installedFiles": ["lib/package.py"],
                "dependencyRefs": [],
            }
        ],
        "entrypoints": [
            {
                "id": "package-tool",
                "name": "package",
                "distributionRef": "package",
                "module": "package",
                "callable": None,
                "relativeExecutable": None,
            }
        ],
        "ansible": None,
    }
    resolved = ToolEnvironmentVerifier().verify(manifest, tmp_path)
    assert resolved["package-tool"].argv_prefix == (
        "/bin/python",
        "-I",
        "-m",
        "package",
    )

    (tmp_path / "unexpected.py").write_bytes(b"drift")
    with pytest.raises(ToolEnvironmentError, match="file closure mismatch"):
        ToolEnvironmentVerifier().verify(manifest, tmp_path)


def test_semantic_projection_ignores_run_specific_raw_values() -> None:
    common = {
        "caseRef": "case",
        "subjectRef": "subject",
        "probeRef": "probe",
        "source": "pytest",
        "status": "passed",
        "normalizedCode": "PYTEST-EXIT",
        "semanticPayload": {"exitCode": 0},
    }
    first = semantic_projection(
        projection_id="projection",
        input_closure_digest=DIGEST,
        normalizer_ref=_ref("normalizer"),
        invocation_refs=["invoke"],
        observations=[{**common, "payload": {"duration": 1, "pid": 10}}],
        oracle_results=[],
        admissions=[],
        item_verdicts=[],
        regression_refs=[],
    )
    second = semantic_projection(
        projection_id="projection",
        input_closure_digest=DIGEST,
        normalizer_ref=_ref("normalizer"),
        invocation_refs=["invoke"],
        observations=[{**common, "payload": {"duration": 9, "pid": 99}}],
        oracle_results=[],
        admissions=[],
        item_verdicts=[],
        regression_refs=[],
    )
    assert first == second


def test_semantic_projection_derives_meaningful_official_payload() -> None:
    common = {
        "caseRef": "case",
        "subjectRef": "subject",
        "probeRef": "probe",
        "source": "pytest",
        "status": "failed",
        "normalizedCode": "PYTEST-EXIT",
    }
    projections = [
        semantic_projection(
            projection_id="projection",
            input_closure_digest=DIGEST,
            normalizer_ref=_ref("normalizer"),
            invocation_refs=["invoke"],
            observations=[
                {
                    **common,
                    "payload": {
                        "exitCode": exit_code,
                        "stdoutRef": _ref(f"stdout-{exit_code}"),
                        "stderrRef": _ref(f"stderr-{exit_code}"),
                    },
                }
            ],
            oracle_results=[],
            admissions=[],
            item_verdicts=[],
            regression_refs=[],
        )
        for exit_code in (1, 2)
    ]
    assert projections[0]["observations"][0]["payload"] == {"exitCode": 1}
    assert projections[1]["observations"][0]["payload"] == {"exitCode": 2}
    assert projections[0]["projectionDigest"] != projections[1]["projectionDigest"]


class _Clock:
    def __init__(self) -> None:
        self.tick = 0.0

    def now(self) -> str:
        return "2026-07-29T12:00:00Z"

    def monotonic(self) -> float:
        self.tick += 0.01
        return self.tick


def test_bubblewrap_executes_from_locked_root_with_read_only_repository(
    tmp_path: Path,
) -> None:
    required = [
        Path("/usr/bin/true"),
        Path("/usr/lib/libc.so.6"),
        Path("/usr/lib64/ld-linux-x86-64.so.2"),
        Path("/usr/bin/bwrap"),
    ]
    if not all(path.is_file() for path in required):
        pytest.skip("Linux Bubblewrap integration prerequisites are unavailable")
    rootfs = tmp_path / "rootfs"
    repository = tmp_path / "repository"
    for directory in ("bin", "usr/lib", "lib64", "proc", "dev", "workspace"):
        (rootfs / directory).mkdir(parents=True, exist_ok=True)
    repository.mkdir()
    shutil.copy2("/usr/bin/true", rootfs / "bin/true")
    shutil.copy2("/usr/lib/libc.so.6", rootfs / "usr/lib/libc.so.6")
    shutil.copy2(
        "/usr/lib64/ld-linux-x86-64.so.2",
        rootfs / "lib64/ld-linux-x86-64.so.2",
    )
    result = BubblewrapSandbox().execute(
        PreparedInvocation(
            invocation_id="invoke-" + ("1" * 64),
            argv=("/bin/true",),
            working_directory=repository,
            repository_root=repository,
            tool_environment_root=rootfs,
            environment={},
        ),
        {
            "network": "disabled",
            "timeoutSeconds": 5,
            "memoryLimitBytes": None,
            "writablePaths": [],
        },
        clock=_Clock(),
    )
    assert result.exit_code == 0
    assert result.status == "completed"


@pytest.mark.parametrize(
    "value",
    ["../escaped", "/absolute", "nested/../escaped", "nested//path", "bad\x00path"],
)
def test_writable_mount_rejects_non_normalized_or_escaping_paths(
    tmp_path: Path,
    value: str,
) -> None:
    with pytest.raises(SandboxPreparationError, match="writable"):
        _writable_mount(tmp_path, value)
    assert not (tmp_path.parent / "escaped").exists()


def test_writable_mount_rejects_escaping_symlink(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside"
    outside.mkdir(exist_ok=True)
    (tmp_path / "link").symlink_to(outside, target_is_directory=True)
    with pytest.raises(SandboxPreparationError, match="escapes repository"):
        _writable_mount(tmp_path, "link/result")


def test_repository_snapshot_covers_untracked_and_ignored_files(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    snapshot = tmp_path / "snapshot"
    repository.mkdir()
    (repository / ".git").mkdir()
    (repository / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
    (repository / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    (repository / "untracked.txt").write_text("first\n", encoding="utf-8")
    (repository / "ignored.txt").write_text("ignored\n", encoding="utf-8")
    first = repository_tree_ref(repository)
    (repository / "untracked.txt").write_text("second\n", encoding="utf-8")
    assert repository_tree_ref(repository) != first
    expected = repository_tree_ref(repository)
    materialize_repository_snapshot(
        repository,
        snapshot,
        expected_ref=expected,
    )
    assert repository_tree_ref(snapshot) == expected
    assert (snapshot / "ignored.txt").read_text(encoding="utf-8") == "ignored\n"
    assert not (snapshot / ".git").exists()


def _run(repository: Path, *arguments: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
    ).stdout


def test_repair_promotes_verified_tree_without_mutating_checkout(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _run(repository, "init", "-q")
    _run(repository, "config", "user.name", "Test")
    _run(repository, "config", "user.email", "test@example.invalid")
    (repository / "src").mkdir()
    subject = repository / "src/value.py"
    subject.write_text("value = 1\n", encoding="utf-8")
    _run(repository, "add", "src/value.py")
    _run(repository, "commit", "-qm", "base")
    base_commit = _run(repository, "rev-parse", "HEAD").decode().strip()
    base_tree = _run(repository, "rev-parse", "HEAD^{tree}").decode().strip()
    subject.write_text("value = 2\n", encoding="utf-8")
    patch = _run(repository, "diff", "--binary", "--full-index")
    subject.write_text("value = 1\n", encoding="utf-8")
    patch_digest = "sha256:" + hashlib.sha256(patch).hexdigest()
    decision = {
        "decisionId": "repair-ho-01",
        "decision": "repair",
        "baseCommit": base_commit,
        "baseTree": base_tree,
        "patchRef": {"id": "patch", "digest": patch_digest, "uri": "artifact:patch"},
        "failedItems": ["HO-01"],
        "counterexampleRefs": [],
        "permittedPaths": ["src/value.py"],
        "forbiddenPaths": ["policy/", "schemas/"],
        "remainingCycles": 1,
        "nextSelector": {"items": ["HO-01"], "stages": ["typing"]},
    }
    record = RepairService().apply(
        repository=repository,
        workflow_id="workflow-ho-01",
        decision=decision,
        decision_ref=_ref("repair-ho-01"),
        patch=patch,
        applied_at="2026-07-29T12:00:00+00:00",
    )
    assert subject.read_text(encoding="utf-8") == "value = 1\n"
    assert (
        _run(
            repository,
            "show",
            f"{record['promotedRef']}:src/value.py",
        )
        == b"value = 2\n"
    )
    assert record["changedPaths"] == ["src/value.py"]

    forbidden = {**decision, "decisionId": "repair-forbidden", "permittedPaths": ["tests/"]}
    with pytest.raises(RepairError, match="not permitted"):
        RepairService().apply(
            repository=repository,
            workflow_id="workflow-forbidden",
            decision=forbidden,
            decision_ref=_ref("repair-forbidden"),
            patch=patch,
            applied_at="2026-07-29T12:00:00+00:00",
        )

    invalid_decision = {**decision, "decisionId": "repair-invalid-time"}
    with pytest.raises(RepairError, match="invalid repair application record"):
        RepairService().apply(
            repository=repository,
            workflow_id="workflow-invalid-time",
            decision=invalid_decision,
            decision_ref=_ref("repair-invalid-time"),
            patch=patch,
            applied_at="Thu, 07 Apr 2005 22:13:13 +0200",
        )
    invalid_ref = subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "show-ref",
            "--verify",
            "--quiet",
            "refs/ppf/repairs/workflow-invalid-time",
        ],
        check=False,
    )
    assert invalid_ref.returncode != 0


def test_repair_uses_sha256_zero_object_id(tmp_path: Path) -> None:
    repository = tmp_path / "repository-sha256"
    initialized = subprocess.run(
        ["git", "init", "-q", "--object-format=sha256", str(repository)],
        capture_output=True,
        check=False,
    )
    if initialized.returncode:
        pytest.skip("Git does not support SHA-256 repositories")
    _run(repository, "config", "user.name", "Test")
    _run(repository, "config", "user.email", "test@example.invalid")
    subject = repository / "value.py"
    subject.write_text("value = 1\n", encoding="utf-8")
    _run(repository, "add", "value.py")
    _run(repository, "commit", "-qm", "base")
    base_commit = _run(repository, "rev-parse", "HEAD").decode().strip()
    base_tree = _run(repository, "rev-parse", "HEAD^{tree}").decode().strip()
    subject.write_text("value = 2\n", encoding="utf-8")
    patch = _run(repository, "diff", "--binary", "--full-index")
    subject.write_text("value = 1\n", encoding="utf-8")
    decision = {
        "decisionId": "repair-sha256",
        "decision": "repair",
        "baseCommit": base_commit,
        "baseTree": base_tree,
        "patchRef": {
            "id": "patch",
            "digest": "sha256:" + hashlib.sha256(patch).hexdigest(),
            "uri": "artifact:patch",
        },
        "failedItems": ["HO-01"],
        "counterexampleRefs": [],
        "permittedPaths": ["value.py"],
        "forbiddenPaths": [],
        "remainingCycles": 1,
        "nextSelector": {"items": ["HO-01"], "stages": ["typing"]},
    }
    record = RepairService().apply(
        repository=repository,
        workflow_id="workflow-sha256",
        decision=decision,
        decision_ref=_ref("repair-sha256"),
        patch=patch,
        applied_at="2026-07-29T12:00:00+00:00",
    )
    assert len(record["resultCommit"]) == 64
