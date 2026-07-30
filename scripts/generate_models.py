"""Regenerate strict Pydantic boundary models from the execution sidecar."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "src" / "ppf" / "schemas"
SOURCE = SCHEMAS / "extensions" / "python-policy-ppf.execution-repair-extension.schema.json"
OFFICIAL = SCHEMAS / "references" / "python-policy-ppf.schema.json"
OUTPUT = ROOT / "src" / "ppf" / "generated" / "models.py"
OFFICIAL_URI = "urn:python-policy-ppf:generation-policy:0.2.0"


def main() -> int:
    """Bundle the trusted external reference and invoke the pinned generator."""
    with tempfile.TemporaryDirectory(prefix="ppf-models-") as directory:
        temporary = Path(directory)
        extensions = temporary / "extensions"
        references = temporary / "references"
        extensions.mkdir()
        references.mkdir()
        bundled = extensions / "execution.schema.json"
        bundled.write_text(
            SOURCE.read_text(encoding="utf-8").replace(
                OFFICIAL_URI,
                "../references/python-policy-ppf.schema.json",
            ),
            encoding="utf-8",
        )
        (references / OFFICIAL.name).write_bytes(OFFICIAL.read_bytes())
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
