from __future__ import annotations

import json
from pathlib import Path

import pytest
from cyclopts.exceptions import MissingArgumentError, UnknownOptionError

from ppf import cli, core
from ppf.validation import ValidationContext, ValidationResult


def test_run_validation_preserves_json_and_success_exit_code() -> None:
    documents = [Path("profile.json"), Path("reports")]
    calls: list[list[Path]] = []
    output: list[str] = []

    def service(paths: list[Path], *, context: ValidationContext | None = None) -> ValidationResult:
        calls.append(paths)
        assert context is None
        return ValidationResult(())

    assert cli.run_validation(documents, service=service, write=output.append) == 0
    assert calls == [documents]
    assert json.loads(output[0]) == {"valid": True, "documents": []}
    assert "\n" not in output[0]


def test_run_validation_preserves_failure_exit_code() -> None:
    output: list[str] = []

    class InvalidResult(ValidationResult):
        @property
        def valid(self) -> bool:
            return False

        def as_dict(self) -> dict[str, object]:
            return {"valid": False, "documents": [{"document": "invalid.json"}]}

    def service(paths: list[Path], *, context: ValidationContext | None = None) -> ValidationResult:
        assert context is None
        return InvalidResult(())

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

    def run(documents: list[Path], *, repository_root: Path | None = None) -> int:
        received.extend(documents)
        assert repository_root is None
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


def test_catalog_forms_return_json() -> None:
    output: list[str] = []
    assert cli.run_catalog(write=output.append) == 0
    listing = json.loads(output.pop())
    assert listing["documents"]
    assert cli.run_catalog("schema-conformance-policy", write=output.append) == 0
    disclosed = json.loads(output.pop())
    assert disclosed["schema"]["properties"]["documentType"]["const"] == (
        "schema-conformance-policy"
    )


def test_catalog_unknown_type_returns_json_failure() -> None:
    output: list[str] = []
    assert cli.run_catalog("unknown-type", write=output.append) == 1
    assert json.loads(output[0]) == {
        "valid": False,
        "error": "unsupported documentType 'unknown-type'",
    }


def test_explicit_and_alias_commands_share_adapter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[Path], Path | None]] = []

    def run(documents: list[Path], *, repository_root: Path | None = None) -> int:
        calls.append((documents, repository_root))
        return 0

    monkeypatch.setattr(cli, "run_validation", run)
    assert cli.app(["validate", "--repository-root", ".", "document.json"]) == 0
    assert cli.app(["--repository-root", ".", "document.json"]) == 0
    assert calls == [
        ([Path("document.json")], Path(".")),
        ([Path("document.json")], Path(".")),
    ]


def test_catalog_named_path_is_available_via_relative_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    received: list[Path] = []

    def run(documents: list[Path], *, repository_root: Path | None = None) -> int:
        received.extend(documents)
        return 0

    monkeypatch.setattr(cli, "run_validation", run)
    assert cli.app(["./catalog"]) == 0
    assert received == [Path("catalog")]
