from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from ppf.catalog import SchemaCatalog

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "src" / "ppf" / "schemas"


def _catalog_inputs() -> tuple[dict[str, dict[str, object]], dict[str, str], str]:
    registry = json.loads((SCHEMAS / "schema-registry.json").read_text(encoding="utf-8"))
    schemas: dict[str, dict[str, object]] = {}
    paths: dict[str, str] = {}
    for resource in registry["resources"]:
        schema = json.loads((SCHEMAS / resource["path"]).read_text(encoding="utf-8"))
        schemas[resource["uri"]] = schema
        paths[resource["uri"]] = resource["path"]
    return schemas, paths, registry["composedSchema"]


def _construct(schemas: dict[str, dict[str, object]], paths: dict[str, str], uri: str) -> None:
    SchemaCatalog(schemas=schemas, paths=paths, composed_uri=uri)


def test_catalog_is_complete_and_deterministic() -> None:
    catalog = SchemaCatalog.load()
    assert len(catalog.entries) == 39
    assert [entry.document_type for entry in catalog.entries] == sorted(
        entry.document_type for entry in catalog.entries
    )
    assert {
        "schema-conformance-policy",
        "projection-conformance-report",
        "generated-fixture-run",
        "evaluation-invocation-set",
        "tool-environment-manifest",
        "repair-application-record",
    } <= {entry.document_type for entry in catalog.entries}


def test_catalog_rejects_discriminator_const_disagreement() -> None:
    schemas, paths, composed_uri = _catalog_inputs()
    schemas = copy.deepcopy(schemas)
    official = schemas["urn:python-policy-ppf:generation-policy:0.2.0"]
    official["$defs"]["CounterexampleDocument"]["properties"]["documentType"]["const"] = "wrong"
    with pytest.raises(ValueError, match="differs from target"):
        _construct(schemas, paths, composed_uri)


def test_catalog_rejects_unmapped_top_level_branch() -> None:
    schemas, paths, composed_uri = _catalog_inputs()
    schemas = copy.deepcopy(schemas)
    del schemas[composed_uri]["discriminator"]["mapping"]["counterexample"]
    with pytest.raises(ValueError, match="mapped 0 times"):
        _construct(schemas, paths, composed_uri)


def test_catalog_rejects_unresolvable_target() -> None:
    schemas, paths, composed_uri = _catalog_inputs()
    schemas = copy.deepcopy(schemas)
    schemas[composed_uri]["discriminator"]["mapping"]["counterexample"] = (
        "urn:python-policy-ppf:generation-policy:0.2.0#/$defs/Missing"
    )
    with pytest.raises(ValueError, match="unresolvable JSON Pointer"):
        _construct(schemas, paths, composed_uri)


def test_catalog_rejects_family_missing_from_composed_one_of() -> None:
    schemas, paths, composed_uri = _catalog_inputs()
    schemas = copy.deepcopy(schemas)
    schemas[composed_uri]["oneOf"].pop()
    with pytest.raises(ValueError, match="missing from composed oneOf"):
        _construct(schemas, paths, composed_uri)


def test_catalog_load_rejects_missing_registered_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = {
        "composedSchema": "urn:missing",
        "resources": [{"uri": "urn:missing", "path": "missing.json"}],
    }
    (tmp_path / "schema-registry.json").write_text(json.dumps(registry), encoding="utf-8")
    monkeypatch.setattr("ppf.catalog.files", lambda package: tmp_path)
    with pytest.raises(ValueError, match="path is missing"):
        SchemaCatalog.load()


def test_catalog_load_rejects_registered_id_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = {
        "composedSchema": "urn:registered",
        "resources": [{"uri": "urn:registered", "path": "schema.json"}],
    }
    (tmp_path / "schema-registry.json").write_text(json.dumps(registry), encoding="utf-8")
    (tmp_path / "schema.json").write_text(
        json.dumps({"$id": "urn:different"}),
        encoding="utf-8",
    )
    monkeypatch.setattr("ppf.catalog.files", lambda package: tmp_path)
    with pytest.raises(ValueError, match="differs from resource"):
        SchemaCatalog.load()
