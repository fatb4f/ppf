"""Self-validating catalog of packaged PPF JSON Schema resources."""

from __future__ import annotations

from dataclasses import dataclass
from importlib.resources import files
from pathlib import PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from .json_input import strict_json_loads

Json = Any


@dataclass(frozen=True)
class CatalogEntry:
    """Resolved document-type entry in the composed schema."""

    document_type: str
    schema_uri: str
    target: str
    fragment: dict[str, Json]

    def as_dict(self, *, include_schema: bool = False) -> dict[str, Json]:
        result: dict[str, Json] = {
            "documentType": self.document_type,
            "schemaUri": self.schema_uri,
            "target": self.target,
        }
        if include_schema:
            result["schema"] = self.fragment
        return result


def _resolve_pointer(document: Json, pointer: str) -> Json:
    if pointer == "":
        return document
    if not pointer.startswith("/"):
        raise ValueError(f"invalid JSON Pointer {pointer!r}")
    value = document
    for raw_part in pointer[1:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(value, dict) or part not in value:
            raise ValueError(f"unresolvable JSON Pointer {pointer!r}")
        value = value[part]
    return value


def _split_target(target: str) -> tuple[str, str]:
    uri, separator, fragment = target.partition("#")
    if not uri:
        raise ValueError(f"target must use a canonical schema URI: {target!r}")
    return uri, f"/{fragment.removeprefix('/')}" if separator and fragment else ""


class SchemaCatalog:
    """Load, verify, and expose the canonical packaged schema catalog."""

    def __init__(
        self,
        *,
        schemas: dict[str, dict[str, Json]],
        paths: dict[str, str],
        composed_uri: str,
    ) -> None:
        if composed_uri not in schemas:
            raise ValueError(f"composed schema is not registered: {composed_uri!r}")
        self._schemas = schemas
        self._paths = paths
        self.composed_uri = composed_uri

        registry = Registry()
        for uri, schema in sorted(schemas.items()):
            Draft202012Validator.check_schema(schema)
            registry = registry.with_resource(uri, Resource.from_contents(schema))
        self.registry = registry

        composed = schemas[composed_uri]
        mapping = composed.get("discriminator", {}).get("mapping")
        if not isinstance(mapping, dict):
            raise ValueError("composed schema discriminator mapping is missing")

        family_uris = set(schemas) - {composed_uri}
        one_of = composed.get("oneOf")
        if not isinstance(one_of, list):
            raise ValueError("composed schema oneOf is missing")
        composed_families = {
            branch.get("$ref")
            for branch in one_of
            if isinstance(branch, dict) and isinstance(branch.get("$ref"), str)
        }
        missing_families = sorted(family_uris - composed_families)
        if missing_families:
            raise ValueError(f"family schemas missing from composed oneOf: {missing_families!r}")
        unexpected_families = sorted(composed_families - family_uris)
        if unexpected_families:
            raise ValueError(
                f"composed oneOf references unregistered families: {unexpected_families!r}"
            )

        entries: dict[str, CatalogEntry] = {}
        mapped_targets: dict[str, list[str]] = {}
        for document_type, target in sorted(mapping.items()):
            if not isinstance(document_type, str) or not isinstance(target, str):
                raise ValueError("discriminator mappings must contain string keys and targets")
            schema_uri, pointer = _split_target(target)
            schema = schemas.get(schema_uri)
            if schema is None:
                raise ValueError(f"discriminator target uses unregistered schema: {target!r}")
            fragment = _resolve_pointer(schema, pointer)
            if not isinstance(fragment, dict):
                raise ValueError(f"discriminator target is not a schema object: {target!r}")
            declared_type = fragment.get("properties", {}).get("documentType", {}).get("const")
            if declared_type != document_type:
                raise ValueError(
                    f"discriminator key {document_type!r} differs from target "
                    f"documentType.const {declared_type!r}"
                )
            mapped_targets.setdefault(target, []).append(document_type)
            entries[document_type] = CatalogEntry(
                document_type=document_type,
                schema_uri=schema_uri,
                target=target,
                fragment=fragment,
            )

        for schema_uri in sorted(family_uris):
            schema = schemas[schema_uri]
            branches = schema.get("oneOf")
            if not isinstance(branches, list):
                raise ValueError(f"family schema has no top-level oneOf: {schema_uri!r}")
            for branch in branches:
                reference = branch.get("$ref") if isinstance(branch, dict) else None
                if not isinstance(reference, str):
                    raise ValueError(f"family schema has a non-reference branch: {schema_uri!r}")
                canonical = f"{schema_uri}{reference}" if reference.startswith("#") else reference
                mapped = mapped_targets.get(canonical, [])
                if len(mapped) != 1:
                    raise ValueError(
                        f"top-level document schema {canonical!r} is mapped {len(mapped)} times"
                    )

        self._entries = entries

    @classmethod
    def load(cls) -> SchemaCatalog:
        root = files("ppf.schemas")
        registry_resource = root.joinpath("schema-registry.json")
        registry_document = strict_json_loads(registry_resource.read_text(encoding="utf-8"))
        composed_uri = registry_document.get("composedSchema")
        resources = registry_document.get("resources")
        if not isinstance(composed_uri, str) or not isinstance(resources, list):
            raise ValueError("schema registry must declare composedSchema and resources")

        schemas: dict[str, dict[str, Json]] = {}
        paths: dict[str, str] = {}
        for item in resources:
            if not isinstance(item, dict):
                raise ValueError("schema registry resource entries must be objects")
            uri = item.get("uri")
            path = item.get("path")
            if not isinstance(uri, str) or not isinstance(path, str):
                raise ValueError("schema registry resources require string uri and path")
            relative = PurePosixPath(path)
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError(f"registered schema path escapes package resources: {path!r}")
            resource = root
            for part in relative.parts:
                resource = resource.joinpath(part)
            if not resource.is_file():
                raise ValueError(f"registered schema path is missing: {path!r}")
            schema = strict_json_loads(resource.read_text(encoding="utf-8"))
            if not isinstance(schema, dict):
                raise ValueError(f"registered schema is not an object: {path!r}")
            if schema.get("$id") != uri:
                raise ValueError(
                    f"registered URI {uri!r} differs from resource $id {schema.get('$id')!r}"
                )
            if uri in schemas:
                raise ValueError(f"duplicate registered schema URI: {uri!r}")
            schemas[uri] = schema
            paths[uri] = path
        return cls(schemas=schemas, paths=paths, composed_uri=composed_uri)

    @property
    def entries(self) -> tuple[CatalogEntry, ...]:
        return tuple(self._entries[name] for name in sorted(self._entries))

    @property
    def resource_names(self) -> tuple[str, ...]:
        return tuple(self._paths[uri] for uri in sorted(self._paths))

    def entry(self, document_type: str) -> CatalogEntry | None:
        return self._entries.get(document_type)

    def validator(self, document_type: str) -> Any:
        entry = self._entries[document_type]
        return Draft202012Validator(
            {"$ref": entry.target},
            registry=self.registry,
            format_checker=FormatChecker(),
        )

    def as_dict(self, document_type: str | None = None) -> dict[str, Json]:
        if document_type is None:
            return {
                "composedSchema": self.composed_uri,
                "documents": [entry.as_dict() for entry in self.entries],
            }
        entry = self.entry(document_type)
        if entry is None:
            raise KeyError(document_type)
        return entry.as_dict(include_schema=True)
