from __future__ import annotations

import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from ppf.catalog import SchemaCatalog

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _validator() -> Draft202012Validator:
    catalog = SchemaCatalog.load()
    return Draft202012Validator(
        {"$ref": "urn:python-policy-ppf:implementation-policy-extension:0.2.0"},
        registry=catalog.registry,
    )


def _fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_shaping_documents_are_valid() -> None:
    validator = _validator()
    for path in sorted(FIXTURES.glob("valid-shaping-*.json")):
        assert not list(validator.iter_errors(_fixture(path.name))), path


def test_capability_assembly_documents_are_valid() -> None:
    validator = _validator()
    names = [
        "valid-capability-provider-registry.json",
        "valid-dependency-wiring-plan.json",
        "valid-capability-assembly-record.json",
        "valid-qualification-fixture-projection.json",
    ]
    for name in names:
        assert not list(validator.iter_errors(_fixture(name))), name


def test_decision_record_supports_primary_and_collaborator_profiles() -> None:
    validator = _validator()
    document = _fixture("valid-shaping-decision-record.json")
    assert document["primaryProfileRef"] == "use-case-orchestrator"
    assert document["requiredProfileRefs"] == ["state-transition", "effect-port"]
    assert not list(validator.iter_errors(document))


def test_decision_record_requires_digest_bound_inputs() -> None:
    validator = _validator()
    document = copy.deepcopy(_fixture("valid-shaping-decision-record.json"))
    del document["policyRef"]["digest"]
    errors = list(validator.iter_errors(document))
    assert any("digest" in error.message for error in errors)


def test_predicate_expected_value_matches_operator_shape() -> None:
    validator = _validator()
    document = copy.deepcopy(_fixture("valid-shaping-policy.json"))
    document["predicates"][0]["operator"] = "is-present"
    errors = list(validator.iter_errors(document))
    assert errors


def test_union_dependency_requires_explicit_selection() -> None:
    validator = _validator()
    document = copy.deepcopy(_fixture("valid-capability-provider-registry.json"))
    dependency = document["providers"][-1]["dependencies"][0]
    dependency["cardinality"] = "union"
    errors = list(validator.iter_errors(document))
    assert errors


def test_bulk_fixture_projection_requires_explicit_module() -> None:
    validator = _validator()
    document = copy.deepcopy(_fixture("valid-qualification-fixture-projection.json"))
    document["bulkProjection"]["moduleSelection"] = "caller-stack"
    errors = list(validator.iter_errors(document))
    assert errors
