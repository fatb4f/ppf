"""Injectable process execution and Linux Bubblewrap isolation."""

from __future__ import annotations

import os
import resource
import signal
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol


@dataclass(frozen=True)
class SandboxCapabilities:
    """Constraints an execution backend can enforce."""

    network_disabled: bool
    repository_read_only: bool
    pid_namespace: bool
    user_namespace: bool
    timeout: bool
    rlimits: bool
    cgroup_v2: bool


@dataclass(frozen=True)
class SupportDecision:
    """Preflight result for a requested sandbox profile."""

    supported: bool
    missing: tuple[str, ...] = ()


@dataclass(frozen=True)
class PreparedInvocation:
    """A shell-free invocation with verified absolute boundaries."""

    invocation_id: str
    argv: tuple[str, ...]
    working_directory: Path
    repository_root: Path
    tool_environment_root: Path
    environment: Mapping[str, str]


@dataclass(frozen=True)
class RawExecutionResult:
    """Uninterpreted process facts and exact output bytes."""

    invocation_id: str
    launch_state: str
    status: str
    exit_code: int | None
    signal: int | None
    started_at: str
    completed_at: str
    duration_ms: int
    stdout: bytes
    stderr: bytes


class Clock(Protocol):
    def now(self) -> str: ...

    def monotonic(self) -> float: ...


class SandboxPreparationError(RuntimeError):
    """The backend could not establish the sandbox or launch its target."""


class SandboxBackend(Protocol):
    def capabilities(self) -> SandboxCapabilities: ...

    def evaluate_support(self, profile: dict[str, object]) -> SupportDecision: ...

    def execute(
        self,
        invocation: PreparedInvocation,
        profile: dict[str, object],
        *,
        clock: Clock,
    ) -> RawExecutionResult: ...


def _writable_mount(
    repository_root: Path,
    value: object,
) -> tuple[Path, PurePosixPath]:
    """Resolve one declared writable mount without permitting boundary escape."""
    if not isinstance(value, str) or not value or "\x00" in value:
        raise SandboxPreparationError(f"unsafe writable path {value!r}")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or relative == PurePosixPath(".")
        or relative.as_posix() != value
        or ".." in relative.parts
        or any(part in ("", ".") for part in relative.parts)
    ):
        raise SandboxPreparationError(f"unsafe writable path {value!r}")
    root = repository_root.resolve(strict=True)
    candidate = root.joinpath(*relative.parts)
    resolved = candidate.resolve(strict=False)
    if not resolved.is_relative_to(root):
        raise SandboxPreparationError(f"writable path escapes repository: {value!r}")
    target = PurePosixPath("/workspace").joinpath(*relative.parts)
    if not target.is_relative_to(PurePosixPath("/workspace")):
        raise SandboxPreparationError(f"writable target escapes workspace: {value!r}")
    return resolved, target


def _limit_process(profile: dict[str, object]) -> Callable[[], None]:
    def apply() -> None:
        file_size = profile.get("fileSizeLimitBytes")
        if isinstance(file_size, int):
            resource.setrlimit(resource.RLIMIT_FSIZE, (file_size, file_size))
        processes = profile.get("processLimit")
        if isinstance(processes, int):
            resource.setrlimit(resource.RLIMIT_NPROC, (processes, processes))
        memory = profile.get("memoryLimitBytes")
        if isinstance(memory, int):
            resource.setrlimit(resource.RLIMIT_AS, (memory, memory))

    return apply


class BubblewrapSandbox:
    """Linux namespace backend with parent timeout and declared mounts only."""

    def __init__(
        self,
        executable: Path = Path("/usr/bin/bwrap"),
        *,
        cgroup_v2: bool = False,
    ) -> None:
        self.executable = executable
        self._cgroup_v2 = cgroup_v2

    def capabilities(self) -> SandboxCapabilities:
        available = self.executable.is_file() and os.access(self.executable, os.X_OK)
        return SandboxCapabilities(
            network_disabled=available,
            repository_read_only=available,
            pid_namespace=available,
            user_namespace=available,
            timeout=True,
            rlimits=True,
            cgroup_v2=available and self._cgroup_v2,
        )

    def evaluate_support(self, profile: dict[str, object]) -> SupportDecision:
        capabilities = self.capabilities()
        required = {
            "network-disabled": profile.get("network") == "disabled"
            and capabilities.network_disabled,
            "repository-read-only": capabilities.repository_read_only,
            "pid-namespace": capabilities.pid_namespace,
            "user-namespace": capabilities.user_namespace,
            "timeout": isinstance(profile.get("timeoutSeconds"), int) and capabilities.timeout,
            "memory-enforcement": profile.get("memoryLimitBytes") is None or capabilities.cgroup_v2,
        }
        missing = tuple(name for name, supported in required.items() if not supported)
        return SupportDecision(not missing, missing)

    def execute(
        self,
        invocation: PreparedInvocation,
        profile: dict[str, object],
        *,
        clock: Clock,
    ) -> RawExecutionResult:
        support = self.evaluate_support(profile)
        if not support.supported:
            raise RuntimeError(f"unsupported sandbox capabilities: {support.missing!r}")
        arguments = [
            str(self.executable),
            "--die-with-parent",
            "--new-session",
            "--unshare-pid",
            "--unshare-user",
            "--unshare-net",
            "--clearenv",
            "--ro-bind",
            str(invocation.tool_environment_root),
            "/",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--ro-bind",
            str(invocation.repository_root),
            "/workspace",
        ]
        writable_paths = profile.get("writablePaths", [])
        if not isinstance(writable_paths, list):
            raise TypeError("writablePaths must be a list")
        for writable in writable_paths:
            path, target = _writable_mount(invocation.repository_root, writable)
            path.mkdir(parents=True, exist_ok=True)
            if path.resolve(strict=True) != path:
                raise SandboxPreparationError(
                    f"writable path changed during preparation: {writable!r}"
                )
            arguments.extend(["--bind", str(path), str(target)])
        try:
            relative_working_directory = invocation.working_directory.relative_to(
                invocation.repository_root
            )
        except ValueError as error:
            raise RuntimeError("working directory escapes repository root") from error
        arguments.extend(["--chdir", str(Path("/workspace") / relative_working_directory)])
        for name, value in sorted(invocation.environment.items()):
            arguments.extend(["--setenv", name, value])
        arguments.extend(["--", *invocation.argv])

        started_at = clock.now()
        started = clock.monotonic()
        timeout_seconds = profile["timeoutSeconds"]
        if not isinstance(timeout_seconds, int):
            raise TypeError("timeoutSeconds must be an integer")
        try:
            completed = subprocess.run(
                arguments,
                check=False,
                capture_output=True,
                timeout=timeout_seconds,
                preexec_fn=_limit_process(profile),
            )
            if completed.returncode != 0 and completed.stderr.lstrip().startswith(b"bwrap:"):
                raise SandboxPreparationError(
                    completed.stderr.decode("utf-8", errors="replace").strip()
                )
            status = "completed" if completed.returncode >= 0 else "failed"
            exit_code = completed.returncode if completed.returncode >= 0 else None
            termination_signal = -completed.returncode if completed.returncode < 0 else None
            stdout = completed.stdout
            stderr = completed.stderr
        except subprocess.TimeoutExpired as error:
            status = "timed-out"
            exit_code = None
            termination_signal = signal.SIGKILL
            stdout = error.stdout or b""
            stderr = error.stderr or b""
        completed_at = clock.now()
        duration_ms = max(0, round((clock.monotonic() - started) * 1000))
        return RawExecutionResult(
            invocation_id=invocation.invocation_id,
            launch_state="launched",
            status=status,
            exit_code=exit_code,
            signal=termination_signal,
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=duration_ms,
            stdout=stdout,
            stderr=stderr,
        )
