from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from ppf.evaluation import closure_digest, validate_evaluation_semantics

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


def test_binding_closure_must_equal_referenced_input_manifest() -> None:
    digest = "sha256:" + ("1" * 64)
    fields = {
        name: {"id": name.lower(), "digest": digest}
        for name in (
            "profile",
            "plan",
            "worktree",
            "environment",
            "toolchain",
            "invocationSet",
            "sandboxProfile",
            "adapterSet",
        )
    }
    manifest = {
        "documentType": "evaluation-input-manifest",
        "schemaVersion": "0.2.0",
        "manifestId": "manifest",
        **fields,
    }
    manifest_raw = json.dumps(manifest, sort_keys=True).encode()
    closure = {
        **fields,
        "catalog": {"id": "catalog", "digest": digest},
        "stageRegistry": {"id": "stages", "digest": digest},
        "inputManifest": {
            "id": "manifest",
            "digest": "sha256:" + hashlib.sha256(manifest_raw).hexdigest(),
        },
    }
    binding = {
        "documentType": "evaluation-input-binding",
        "schemaVersion": "0.2.0",
        "bindingId": "binding",
        "closure": closure,
        "closureDigest": closure_digest(closure),
        "createdAt": "2026-07-29T12:00:00Z",
    }
    binding_path = Path("binding.json")
    manifest_path = Path("manifest.json")
    loaded = [
        (binding_path, json.dumps(binding).encode(), binding),
        (manifest_path, manifest_raw, manifest),
    ]
    assert not validate_evaluation_semantics(loaded)[binding_path]

    binding["closure"]["worktree"] = {"id": "other-worktree", "digest": digest}
    binding["closureDigest"] = closure_digest(binding["closure"])
    errors = validate_evaluation_semantics(loaded)[binding_path]
    assert any("input manifest field 'worktree'" in error.message for error in errors)
