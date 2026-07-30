from __future__ import annotations

import json
from pathlib import Path

from ppf.contracts import load_execution_contract
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
