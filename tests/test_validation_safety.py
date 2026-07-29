from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

from ppf import ValidationContext, validate_documents
from ppf.core import _document_id, _internal_content_refs, validate_bundle
from ppf.validation import _local_ref_errors

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / ".codex" / "skills" / "python-policy-ppf" / "tests" / "fixtures"


def _profile() -> dict[str, object]:
    return json.loads((FIXTURES / "valid-profile.json").read_text(encoding="utf-8"))


def _profile_with_uri(uri: str, digest: str) -> bytes:
    document = _profile()
    document["gates"][0]["configurationRef"]["uri"] = uri
    document["gates"][0]["configurationRef"]["digest"] = digest
    return json.dumps(document).encode()


def _messages(result: object) -> list[str]:
    return [
        error["message"]
        for document in result.as_dict()["documents"]
        for error in document["errors"]
    ]


def test_unknown_document_type_is_explicitly_rejected() -> None:
    result = validate_documents([(Path("unknown.json"), b'{"documentType":"not-registered"}')])
    assert not result.valid
    assert "unsupported documentType" in _messages(result)[0]


def test_percent_encoded_traversal_is_rejected(tmp_path: Path) -> None:
    raw = _profile_with_uri("%2e%2e/file", "sha256:" + ("1" * 64))
    result = validate_documents(
        [(Path("profile.json"), raw)],
        context=ValidationContext(tmp_path),
    )
    assert any("must not contain '..'" in message for message in _messages(result))


@pytest.mark.parametrize(
    ("uri", "message"),
    [
        ("/absolute.toml", "repository-root-relative"),
        ("config.toml?revision=1", "must not contain a query"),
        ("missing.toml", "regular file"),
    ],
)
def test_invalid_local_uri_forms_are_rejected(tmp_path: Path, uri: str, message: str) -> None:
    result = validate_documents(
        [
            (
                Path("profile.json"),
                _profile_with_uri(uri, "sha256:" + ("1" * 64)),
            )
        ],
        context=ValidationContext(tmp_path),
    )
    assert any(message in item for item in _messages(result))


def test_nul_local_uri_is_rejected(tmp_path: Path) -> None:
    result = validate_documents(
        [
            (
                Path("profile.json"),
                _profile_with_uri("config\u0000.toml", "sha256:" + ("1" * 64)),
            )
        ],
        context=ValidationContext(tmp_path),
    )
    assert not result.valid


def test_symlinks_must_resolve_inside_repository_root(tmp_path: Path) -> None:
    external = tmp_path.parent / f"{tmp_path.name}-external.toml"
    external.write_bytes(b"external")
    escaping = tmp_path / "escaping.toml"
    os.symlink(external, escaping)
    result = validate_documents(
        [
            (
                Path("profile.json"),
                _profile_with_uri(
                    "escaping.toml",
                    "sha256:" + hashlib.sha256(external.read_bytes()).hexdigest(),
                ),
            )
        ],
        context=ValidationContext(tmp_path),
    )
    assert any("escapes repository root" in message for message in _messages(result))

    target = tmp_path / "target.toml"
    target.write_bytes(b"inside")
    os.symlink(target, tmp_path / "inside.toml")
    valid = validate_documents(
        [
            (
                Path("profile.json"),
                _profile_with_uri(
                    "inside.toml",
                    "sha256:" + hashlib.sha256(target.read_bytes()).hexdigest(),
                ),
            )
        ],
        context=ValidationContext(tmp_path),
    )
    assert valid.valid


def test_fragment_is_ignored_for_hashing_and_preserved_in_diagnostics(tmp_path: Path) -> None:
    content = b"configuration"
    (tmp_path / "config.toml").write_bytes(content)
    digest = "sha256:" + hashlib.sha256(content).hexdigest()
    valid = validate_documents(
        [(Path("profile.json"), _profile_with_uri("config.toml#ruff", digest))],
        context=ValidationContext(tmp_path),
    )
    assert valid.valid

    invalid = validate_documents(
        [
            (
                Path("profile.json"),
                _profile_with_uri("config.toml#ruff", "sha256:" + ("1" * 64)),
            )
        ],
        context=ValidationContext(tmp_path),
    )
    assert any("config.toml#ruff" in message for message in _messages(invalid))


def test_missing_repository_context_is_reported_only_for_local_refs() -> None:
    result = validate_documents(
        [
            (
                Path("profile.json"),
                _profile_with_uri("config.toml", "sha256:" + ("1" * 64)),
            )
        ]
    )
    assert any("repository context is required" in message for message in _messages(result))


def test_structurally_invalid_id_is_excluded_from_bundle_index() -> None:
    invalid_profile = _profile()
    del invalid_profile["claims"]
    implementation = json.loads(
        (FIXTURES / "valid-implementation-policy-extension.json").read_text(encoding="utf-8")
    )
    result = validate_documents(
        [
            (Path("invalid-profile.json"), json.dumps(invalid_profile).encode()),
            (Path("implementation.json"), json.dumps(implementation).encode()),
        ],
        context=ValidationContext(ROOT),
    )
    implementation_result = next(
        document
        for document in result.as_dict()["documents"]
        if document["document"] == "implementation.json"
    )
    assert any(
        "required PPF document 'python-3.14-default' is absent" in error["message"]
        for error in implementation_result["errors"]
    )
    assert not any(
        "duplicate document id" in error["message"]
        for document in result.as_dict()["documents"]
        for error in document["errors"]
    )


def test_missing_and_malformed_uv_lock_are_validation_errors(tmp_path: Path) -> None:
    implementation = (FIXTURES / "valid-implementation-policy-extension.json").read_bytes()
    missing = validate_documents(
        [(Path("implementation.json"), implementation)],
        context=ValidationContext(tmp_path),
    )
    assert any("cannot load repository uv.lock" in message for message in _messages(missing))

    (tmp_path / "uv.lock").write_text("not = [valid", encoding="utf-8")
    malformed = validate_documents(
        [(Path("implementation.json"), implementation)],
        context=ValidationContext(tmp_path),
    )
    assert any("cannot load repository uv.lock" in message for message in _messages(malformed))


def test_schema_conformance_identities_and_internal_references() -> None:
    cases = [
        (
            {"documentType": "schema-conformance-policy", "policyId": "policy"},
            "policy",
            {("profileRef",), ("implementationPolicyRef",)},
        ),
        (
            {"documentType": "projection-conformance-report", "reportId": "report"},
            "report",
            {("policyRef",)},
        ),
        (
            {"documentType": "generated-fixture-run", "runId": "run"},
            "run",
            {("policyRef",)},
        ),
    ]
    for document, identifier, ref_paths in cases:
        for path in ref_paths:
            document[path[0]] = {
                "id": path[0],
                "digest": "sha256:" + ("1" * 64),
            }
        assert _document_id(document) == identifier
        assert {path for path, _ in _internal_content_refs(document)} == ref_paths

        path = Path(f"{identifier}.json")
        errors = validate_bundle([(path, json.dumps(document).encode(), document)])
        assert sum("required PPF document" in error.message for error in errors[path]) == len(
            ref_paths
        )

        duplicate_path = Path(f"{identifier}-duplicate.json")
        duplicates = validate_bundle(
            [
                (path, json.dumps(document).encode(), document),
                (duplicate_path, json.dumps(document).encode(), copy.deepcopy(document)),
            ]
        )
        assert any("duplicate document id" in error.message for error in duplicates[duplicate_path])


def test_every_valid_fixture_local_content_reference_is_current() -> None:
    for path in sorted(FIXTURES.glob("valid-*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        assert not _local_ref_errors(document, ValidationContext(ROOT)), path
