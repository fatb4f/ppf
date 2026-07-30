"""Regenerate strict Pydantic boundary models from the composed contract."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "src" / "ppf" / "schemas"
REGISTRY = SCHEMAS / "schema-registry.json"
OUTPUT = ROOT / "src" / "ppf" / "generated" / "models.py"


def _localize_references(value: object, local_names: dict[str, str]) -> object:
    if isinstance(value, dict):
        return {
            name: (
                next(
                    (
                        item.replace(uri, local_name, 1)
                        for uri, local_name in local_names.items()
                        if item.startswith(uri)
                    ),
                    item,
                )
                if name == "$ref" and isinstance(item, str)
                else _localize_references(item, local_names)
            )
            for name, item in value.items()
        }
    if isinstance(value, list):
        return [_localize_references(item, local_names) for item in value]
    return value


def main() -> int:
    """Bundle registered schemas with local references and invoke the pinned generator."""
    with tempfile.TemporaryDirectory(prefix="ppf-models-") as directory:
        temporary = Path(directory)
        registry = json.loads(REGISTRY.read_bytes())
        resources = {
            resource["uri"]: SCHEMAS / resource["path"] for resource in registry["resources"]
        }
        local_names = {uri: f"schema-{index}.json" for index, uri in enumerate(sorted(resources))}
        for uri, source in resources.items():
            schema = json.loads(source.read_bytes())
            localized = _localize_references(schema, local_names)
            (temporary / local_names[uri]).write_text(
                json.dumps(localized),
                encoding="utf-8",
            )
        bundled = temporary / local_names[registry["composedSchema"]]
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "datamodel-codegen",
                "--input",
                str(bundled),
                "--input-file-type",
                "jsonschema",
                "--output",
                str(OUTPUT),
                "--output-model-type",
                "pydantic_v2.BaseModel",
                "--target-python-version",
                "3.14",
                "--strict-nullable",
                "--use-standard-collections",
                "--use-union-operator",
                "--use-default-kwarg",
                "--disable-timestamp",
                "--allow-remote-refs",
                "--formatters",
                "builtin",
            ],
            check=True,
        )
        # datamodel-code-generator 0.71 quotes only the recursive name before
        # applying ``| None`` on Python 3.14. Quote the complete forward
        # expression so importing the generated boundary remains valid.
        generated = OUTPUT.read_text(encoding="utf-8")
        OUTPUT.write_text(
            generated.replace('"JsonValue" | None', '"JsonValue | None"'),
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
