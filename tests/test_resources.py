from __future__ import annotations

import json
from importlib.resources import files

from jsonschema import Draft202012Validator

EXPECTED = {
    "references/python-policy-ppf.schema.json": ("urn:python-policy-ppf:generation-policy:0.2.0"),
    "extensions/python-policy-implementation.extension.schema.json": (
        "urn:python-policy-ppf:implementation-policy-extension:0.2.0"
    ),
    "extensions/python-policy-ppf.eval-workflow-extension.schema.json": (
        "urn:python-policy-ppf:extension:evaluation-workflow:0.2.0"
    ),
    "extensions/python-policy-ppf.schema-conformance-extension.schema.json": (
        "urn:python-policy-ppf:extension:schema-conformance:0.2.0"
    ),
    "extensions/python-policy-ppf.composed.schema.json": (
        "urn:python-policy-ppf:composed:extensions:0.2.0"
    ),
}


def test_packaged_resource_names_and_ids_are_canonical() -> None:
    root = files("ppf.schemas")
    registry = json.loads(root.joinpath("schema-registry.json").read_text(encoding="utf-8"))
    assert {resource["path"]: resource["uri"] for resource in registry["resources"]} == EXPECTED
    assert (
        registry["composedSchema"] == EXPECTED["extensions/python-policy-ppf.composed.schema.json"]
    )
    for path, schema_id in EXPECTED.items():
        resource = root
        for part in path.split("/"):
            resource = resource.joinpath(part)
        schema = json.loads(resource.read_text(encoding="utf-8"))
        assert schema["$id"] == schema_id
        Draft202012Validator.check_schema(schema)
