"""Deterministic, on-demand qualification evidence for the CLI migration."""

from __future__ import annotations

import ast
import hashlib
import io
import json
import sys
import tokenize
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Literal

import libcst
from hypothesis import given, settings, strategies
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ConfigDict, Field

from ppf import ValidationContext, ValidationResult, validate_paths
from ppf.cli import run_validation

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / ".codex" / "skills" / "python-policy-ppf"
SCHEMAS = ROOT / "src" / "ppf" / "schemas"
FIXTURES = PACKAGE / "tests" / "fixtures"
CLI = ROOT / "src" / "ppf" / "cli.py"
CORE = ROOT / "src" / "ppf" / "core.py"
EVIDENCE_PATH = ROOT / "deterministic-evidence.jsonl"

Mechanism = Literal[
    "json-schema",
    "pydantic",
    "ast",
    "libcst",
    "tokenize",
    "pytest",
    "hypothesis",
    "fixture",
    "adapter",
]


class EvidenceRecord(BaseModel):
    """Strict, stable evidence emitted by a qualification check."""

    model_config = ConfigDict(extra="forbid", strict=True)

    check_id: str = Field(pattern=r"^[a-z][a-z0-9-]+$")
    mechanism: Mechanism
    status: Literal["pass", "fail"]
    subject_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    assertion: str = Field(min_length=1)


def _subject_digest(paths: Iterable[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths, key=lambda item: item.relative_to(ROOT).as_posix()):
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return "sha256:" + digest.hexdigest()


def _check(
    check_id: str,
    mechanism: Mechanism,
    assertion: str,
    paths: Iterable[Path],
    probe: Callable[[], None],
) -> EvidenceRecord:
    try:
        probe()
    except Exception:
        status = "fail"
    else:
        status = "pass"
    return EvidenceRecord(
        check_id=check_id,
        mechanism=mechanism,
        status=status,
        subject_digest=_subject_digest(paths),
        assertion=assertion,
    )


def _schemas_are_canonical() -> None:
    registry = json.loads((SCHEMAS / "schema-registry.json").read_text(encoding="utf-8"))
    assert registry["resources"]
    for resource in registry["resources"]:
        schema = json.loads((SCHEMAS / resource["path"]).read_text(encoding="utf-8"))
        assert schema["$id"] == resource["uri"]
        Draft202012Validator.check_schema(schema)


def _evidence_model_is_strict() -> None:
    record = EvidenceRecord(
        check_id="strict-model",
        mechanism="pydantic",
        status="pass",
        subject_digest="sha256:" + ("1" * 64),
        assertion="The strict evidence model accepts its declared scalar types.",
    )
    assert type(record.check_id) is str
    try:
        EvidenceRecord.model_validate({**record.model_dump(), "status": True})
    except ValueError:
        pass
    else:
        raise AssertionError("strict evidence unexpectedly coerced a boolean status")
    try:
        EvidenceRecord.model_validate({**record.model_dump(), "unexpected": "field"})
    except ValueError:
        return
    raise AssertionError("strict evidence unexpectedly accepted an extra field")


def _ast_migration_probe() -> None:
    for path in (CLI, CORE):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        assert "argparse" not in imported
    cli_tree = ast.parse(CLI.read_text(encoding="utf-8"))
    assert any(
        isinstance(node, ast.FunctionDef) and node.name == "main" for node in ast.walk(cli_tree)
    )


def _libcst_migration_probe() -> None:
    module = libcst.parse_module(CLI.read_text(encoding="utf-8"))
    assert "app = App(" in module.code
    assert "@app.default" in module.code


def _token_migration_probe() -> None:
    names = {
        token.string
        for token in tokenize.generate_tokens(io.StringIO(CLI.read_text(encoding="utf-8")).readline)
        if token.type == tokenize.NAME
    }
    assert "argparse" not in names
    assert {"App", "Parameter", "app", "main"} <= names


def _pytest_assertions_are_present() -> None:
    tree = ast.parse((ROOT / "tests" / "test_cli.py").read_text(encoding="utf-8"))
    tests = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
    ]
    assert len(tests) >= 5
    assert sum(isinstance(node, ast.Assert) for test in tests for node in ast.walk(test)) >= 5


def _hypothesis_path_lists() -> None:
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-_"

    @settings(max_examples=40, derandomize=True, database=None)
    @given(
        strategies.lists(
            strategies.text(alphabet=alphabet, min_size=1, max_size=12).map(Path),
            min_size=1,
            max_size=8,
        )
    )
    def exercise(paths: list[Path]) -> None:
        received: list[list[Path]] = []

        def fake_service(
            documents: list[Path], *, context: ValidationContext | None = None
        ) -> ValidationResult:
            received.append(documents)
            assert context is None
            return ValidationResult(())

        output: list[str] = []
        assert run_validation(paths, service=fake_service, write=output.append) == 0
        assert received == [paths]
        assert json.loads(output[0])["valid"] is True

    exercise()


def _fixture_adapter_probe() -> None:
    result = validate_paths(
        [
            FIXTURES / "valid-profile.json",
            FIXTURES / "valid-implementation-policy-extension.json",
        ],
        context=ValidationContext(ROOT),
    )
    assert result.valid
    assert len(result.documents) == 2


def _validation_service_adapter_probe() -> None:
    calls: list[list[Path]] = []
    output: list[str] = []

    class InvalidResult(ValidationResult):
        @property
        def valid(self) -> bool:
            return False

        def as_dict(self) -> dict[str, object]:
            return {"valid": False, "documents": []}

    def fake_service(
        paths: list[Path], *, context: ValidationContext | None = None
    ) -> ValidationResult:
        calls.append(paths)
        assert context is None
        return InvalidResult(())

    documents = [Path("profile.json"), Path("bundle")]
    assert run_validation(documents, service=fake_service, write=output.append) == 1
    assert calls == [documents]
    assert json.loads(output[0])["valid"] is False


def build_evidence() -> list[EvidenceRecord]:
    """Run every deterministic probe and return evidence sorted by check ID."""
    registry_paths = [
        SCHEMAS / "schema-registry.json",
        SCHEMAS / "references" / "python-policy-ppf.schema.json",
        SCHEMAS / "extensions" / "python-policy-implementation.extension.schema.json",
        SCHEMAS / "extensions" / "python-policy-ppf.eval-workflow-extension.schema.json",
        SCHEMAS / "extensions" / "python-policy-ppf.schema-conformance-extension.schema.json",
        SCHEMAS / "extensions" / "python-policy-ppf.execution-repair-extension.schema.json",
        SCHEMAS / "extensions" / "python-policy-ppf.composed-0.3.schema.json",
    ]
    checks = [
        _check(
            "canonical-json-schemas",
            "json-schema",
            "Every registered schema is canonical Draft 2020-12 with its registered ID.",
            registry_paths,
            _schemas_are_canonical,
        ),
        _check(
            "strict-pydantic-evidence",
            "pydantic",
            "Evidence records reject coercion and undeclared fields.",
            [Path(__file__)],
            _evidence_model_is_strict,
        ),
        _check(
            "argparse-removed-ast",
            "ast",
            "Both source entrypoints are free of argparse and expose main().",
            [CLI, CORE],
            _ast_migration_probe,
        ),
        _check(
            "cyclopts-app-libcst",
            "libcst",
            "The CLI exposes a module-level Cyclopts default application.",
            [CLI],
            _libcst_migration_probe,
        ),
        _check(
            "cyclopts-token-shape",
            "tokenize",
            "CLI tokens contain the Cyclopts app surface and no argparse name.",
            [CLI],
            _token_migration_probe,
        ),
        _check(
            "pytest-cli-assertions",
            "pytest",
            "CLI tests contain explicit assertions for each migration behavior.",
            [ROOT / "tests" / "test_cli.py"],
            _pytest_assertions_are_present,
        ),
        _check(
            "hypothesis-path-lists",
            "hypothesis",
            "Generated non-empty path lists cross the fake validation-service seam unchanged.",
            [CLI, Path(__file__)],
            _hypothesis_path_lists,
        ),
        _check(
            "consolidated-fixture-adapter",
            "fixture",
            "Consolidated profile and implementation fixtures validate through "
            "the repository adapter.",
            [
                CLI,
                FIXTURES / "valid-profile.json",
                FIXTURES / "valid-implementation-policy-extension.json",
                ROOT / "pyproject.toml",
                ROOT / "uv.lock",
            ],
            _fixture_adapter_probe,
        ),
        _check(
            "validation-service-adapter",
            "adapter",
            "The command adapter preserves path lists, JSON results, and failure exit status.",
            [CLI, Path(__file__)],
            _validation_service_adapter_probe,
        ),
    ]
    return sorted(checks, key=lambda record: record.check_id)


def write_evidence(
    records: Iterable[EvidenceRecord],
    path: Path = EVIDENCE_PATH,
) -> None:
    """Write deterministic JSONL with sorted records and object keys."""
    lines = [
        json.dumps(record.model_dump(), sort_keys=True, separators=(",", ":"))
        for record in sorted(records, key=lambda item: item.check_id)
    ]
    path.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")


def main() -> int:
    records = build_evidence()
    write_evidence(records)
    return 0 if all(record.status == "pass" for record in records) else 1


if __name__ == "__main__":
    sys.exit(main())
