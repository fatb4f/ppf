from __future__ import annotations

import json
from pathlib import Path

from ppf import ValidationContext, validate_paths

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / ".codex" / "skills" / "python-policy-ppf"
SCHEMAS = ROOT / "src" / "ppf" / "schemas"
PROFILE = PACKAGE / "tests" / "fixtures" / "valid-profile.json"
IMPLEMENTATION_FIXTURE = (
    PACKAGE / "tests" / "fixtures" / "valid-implementation-policy-extension.json"
)


def test_executable_implementation_example_is_valid() -> None:
    assert validate_paths(
        [PROFILE, IMPLEMENTATION_FIXTURE],
        context=ValidationContext(ROOT),
    ).valid


def test_stale_local_configuration_digest_is_rejected(tmp_path: Path) -> None:
    document = json.loads(IMPLEMENTATION_FIXTURE.read_text(encoding="utf-8"))
    document["projection"]["generator"]["configurationRef"]["digest"] = "sha256:" + ("1" * 64)
    document["projection"]["generator"]["configurationRef"]["uri"] = "pyproject.toml"
    mutated = tmp_path / IMPLEMENTATION_FIXTURE.name
    mutated.write_text(json.dumps(document), encoding="utf-8")
    result = validate_paths(
        [PROFILE, mutated],
        context=ValidationContext(ROOT),
    )
    assert not result.valid
    assert any(
        "digest does not match local URI" in error["message"]
        for item in result.as_dict()["documents"]
        for error in item["errors"]
    )


def test_composed_discriminator_targets_are_canonical() -> None:
    composed = json.loads(
        (SCHEMAS / "extensions" / "python-policy-ppf.composed.schema.json").read_text(
            encoding="utf-8"
        )
    )
    mappings = composed["discriminator"]["mapping"]
    assert all(not target.startswith("#/") for target in mappings.values())
    assert all(target.startswith("urn:python-policy-ppf:") for target in mappings.values())
    schemas = {
        schema["$id"]: schema
        for schema in (
            json.loads(
                (SCHEMAS / "references" / "python-policy-ppf.schema.json").read_text(
                    encoding="utf-8"
                )
            ),
            json.loads(
                (
                    SCHEMAS / "extensions" / "python-policy-implementation.extension.schema.json"
                ).read_text(encoding="utf-8")
            ),
            json.loads(
                (
                    SCHEMAS / "extensions" / "python-policy-ppf.eval-workflow-extension.schema.json"
                ).read_text(encoding="utf-8")
            ),
            json.loads(
                (
                    SCHEMAS
                    / "extensions"
                    / "python-policy-ppf.schema-conformance-extension.schema.json"
                ).read_text(encoding="utf-8")
            ),
        )
    }
    for target in mappings.values():
        schema_id, fragment = target.split("#", maxsplit=1)
        value = schemas[schema_id]
        for part in fragment.removeprefix("/").split("/"):
            value = value[part]
        assert isinstance(value, dict)
