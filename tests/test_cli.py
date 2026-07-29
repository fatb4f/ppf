from __future__ import annotations

import json
from pathlib import Path

import pytest
from cyclopts.exceptions import MissingArgumentError, UnknownOptionError

from ppf import cli, core


def test_run_validation_preserves_json_and_success_exit_code() -> None:
    documents = [Path("profile.json"), Path("reports")]
    calls: list[list[Path]] = []
    output: list[str] = []

    def service(paths: list[Path]) -> dict[str, object]:
        calls.append(paths)
        return {"valid": True, "documents": []}

    assert cli.run_validation(documents, service=service, write=output.append) == 0
    assert calls == [documents]
    assert json.loads(output[0]) == {"valid": True, "documents": []}
    assert "\n" not in output[0]


def test_run_validation_preserves_failure_exit_code() -> None:
    output: list[str] = []

    def service(paths: list[Path]) -> dict[str, object]:
        return {"valid": False, "documents": [{"document": str(paths[0])}]}

    assert (
        cli.run_validation(
            [Path("invalid.json")],
            service=service,
            write=output.append,
        )
        == 1
    )
    assert json.loads(output[0])["valid"] is False
    assert "\n" in output[0]


def test_app_accepts_one_or_more_root_documents(monkeypatch: pytest.MonkeyPatch) -> None:
    received: list[Path] = []

    def run(documents: list[Path]) -> int:
        received.extend(documents)
        return 0

    monkeypatch.setattr(cli, "run_validation", run)
    assert cli.app(["first.json", "bundle"]) == 0
    assert received == [Path("first.json"), Path("bundle")]


def test_app_uses_cyclopts_argument_errors() -> None:
    with pytest.raises(MissingArgumentError):
        cli.app([], exit_on_error=False)
    with pytest.raises(UnknownOptionError):
        cli.app(["--schema", "schema.json", "document.json"], exit_on_error=False)


def test_core_main_delegates_to_shared_application(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "main", lambda: 17)
    assert core.main() == 17
