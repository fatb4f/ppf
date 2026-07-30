"""Strict JSON decoding for contract and evidence inputs."""

from __future__ import annotations

import json
from typing import Any

Json = Any


class DuplicateKeyError(ValueError):
    """Raised when a JSON object repeats a member name."""


def _object_without_duplicates(pairs: list[tuple[str, Json]]) -> dict[str, Json]:
    result: dict[str, Json] = {}
    for name, value in pairs:
        if name in result:
            raise DuplicateKeyError(f"duplicate JSON object key {name!r}")
        result[name] = value
    return result


def strict_json_loads(raw: bytes | str) -> Json:
    """Decode standards-compliant JSON while rejecting duplicate object keys."""
    return json.loads(
        raw,
        object_pairs_hook=_object_without_duplicates,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"invalid JSON constant {value}")
        ),
    )
