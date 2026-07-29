from __future__ import annotations

import copy
import json
from pathlib import Path

from ppf.evaluation import validate_evaluation_semantics

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / ".codex" / "skills" / "python-policy-ppf" / "tests" / "fixtures"
NAMES = [
    "valid-input-binding.json",
    "valid-run-assembly.json",
    "valid-producer-envelope.json",
    "valid-qualification-integrity.json",
]


def _loaded() -> list[tuple[Path, bytes, dict[str, object]]]:
    loaded = []
    for name in NAMES:
        path = FIXTURES / name
        raw = path.read_bytes()
        loaded.append((path, raw, json.loads(raw)))
    return loaded


def _integrity_errors(
    loaded: list[tuple[Path, bytes, dict[str, object]]],
) -> list[object]:
    errors = validate_evaluation_semantics(loaded)
    return errors[FIXTURES / "valid-qualification-integrity.json"]


def test_equal_expected_source_occurrences_are_normalized() -> None:
    loaded = _loaded()
    assembly = loaded[1][2]
    assembly["rawArtifactRefs"].append(copy.deepcopy(assembly["rawArtifactRefs"][0]))
    assert not _integrity_errors(loaded)


def test_conflicting_expected_source_occurrences_force_mismatch() -> None:
    loaded = _loaded()
    assembly = loaded[1][2]
    conflict = copy.deepcopy(assembly["rawArtifactRefs"][0])
    conflict["digest"] = "sha256:" + ("1" * 64)
    assembly["rawArtifactRefs"].append(conflict)
    errors = _integrity_errors(loaded)
    assert any("conflicting expected source occurrences" in error.message for error in errors)
    assert any("must be 'mismatched'" in error.message for error in errors)
    assert any("must be rejected" in error.message for error in errors)


def test_duplicate_declared_integrity_rows_remain_incomplete() -> None:
    loaded = _loaded()
    integrity = loaded[3][2]
    integrity["checks"].append(copy.deepcopy(integrity["checks"][0]))
    errors = _integrity_errors(loaded)
    assert any("duplicate integrity checks" in error.message for error in errors)
    assert any("must be 'incomplete'" in error.message for error in errors)
