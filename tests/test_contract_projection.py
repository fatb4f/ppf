from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from ppf.cli_common import exact_bundle_refs, load_valid_bundle
from ppf.contracts import ContractValidationError, load_contract_bytes, load_execution_contract
from ppf.generated.models import AssessorProfileDocument

DIGEST = "sha256:" + ("1" * 64)


def test_schema_validation_precedes_generated_boundary_parsing(tmp_path: Path) -> None:
    document = {
        "documentType": "assessor-profile",
        "schemaVersion": "0.1.0",
        "profileId": "assessors",
        "assessors": [
            {
                "id": "pytest-assessor",
                "kind": "pytest",
                "executableRef": "pytest-tool",
                "adapterRef": {
                    "id": "adapter",
                    "digest": DIGEST,
                    "uri": "https://example.invalid/adapter",
                },
                "normalizerRef": {
                    "id": "normalizer",
                    "digest": DIGEST,
                    "uri": "https://example.invalid/normalizer",
                },
                "probeRefs": ["pytest-probe"],
            }
        ],
    }
    path = tmp_path / "assessors.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    loaded = load_execution_contract(path)
    assert isinstance(loaded.transport, AssessorProfileDocument)


def test_public_bundle_loader_reuses_validated_bytes_and_exposes_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path(__file__).resolve().parents[1]
    source = (
        root
        / ".codex"
        / "skills"
        / "python-policy-ppf"
        / "tests"
        / "fixtures"
        / "valid-profile.json"
    )
    path = tmp_path / "profile.json"
    original_raw = source.read_bytes()
    path.write_bytes(original_raw)
    original_read_bytes = Path.read_bytes
    reads = 0

    def counted_read_bytes(candidate: Path) -> bytes:
        nonlocal reads
        if candidate == path:
            reads += 1
        return original_read_bytes(candidate)

    monkeypatch.setattr(Path, "read_bytes", counted_read_bytes)
    bundle = load_valid_bundle([path], repository_root=root)
    path.write_bytes(b'{"changed":true}')
    references = exact_bundle_refs(bundle)

    assert reads == 1
    assert references["python-3.14-default"]["digest"] == (
        "sha256:" + hashlib.sha256(original_raw).hexdigest()
    )
    assert bundle.transports["python-3.14-default"].__class__.__name__ == (
        "GenerationPolicyProfileDocument"
    )


def test_contract_boundary_rejects_duplicate_keys() -> None:
    with pytest.raises(ContractValidationError, match="duplicate JSON object key"):
        load_contract_bytes(
            Path("duplicate.json"),
            b'{"documentType":"assessor-profile","documentType":"sandbox-profile"}',
            require_bundle=False,
        )
