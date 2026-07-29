from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
SCHEMA_PATH = PACKAGE / "references" / "python-policy-ppf.schema.json"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
MODULE_PATH = PACKAGE / "scripts" / "validate_catalog.py"

SPEC = importlib.util.spec_from_file_location("validate_catalog", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class ValidateCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        cls.profile = json.loads(
            (FIXTURES / "valid-profile.json").read_text(encoding="utf-8")
        )
        cls.report = json.loads(
            (FIXTURES / "valid-report.json").read_text(encoding="utf-8")
        )

    def validate(self, document: dict[str, object]) -> list[object]:
        errors = VALIDATOR.validate_structure(
            document, self.schema, self.schema
        )
        if not errors:
            errors.extend(VALIDATOR.validate_semantics(document))
        return errors

    def test_valid_profile(self) -> None:
        self.assertEqual([], self.validate(copy.deepcopy(self.profile)))

    def test_document_identity_is_required(self) -> None:
        document = copy.deepcopy(self.profile)
        del document["documentType"]
        errors = self.validate(document)
        self.assertTrue(
            any(error.path == ("documentType",) for error in errors), errors
        )

    def test_advisory_source_cannot_bind_claim(self) -> None:
        document = copy.deepcopy(self.profile)
        document["authoritySources"][0]["authorityClass"] = "advisory-reference"
        errors = self.validate(document)
        self.assertTrue(
            any(
                "canonical or project-policy authority" in error.message
                for error in errors
            ),
            errors,
        )

    def test_duplicate_claim_ids_are_rejected(self) -> None:
        document = copy.deepcopy(self.profile)
        document["claims"].append(copy.deepcopy(document["claims"][0]))
        errors = self.validate(document)
        self.assertTrue(
            any("duplicate id" in error.message for error in errors), errors
        )

    def test_valid_report(self) -> None:
        self.assertEqual([], self.validate(copy.deepcopy(self.report)))

    def test_waived_verdict_requires_active_scoped_waiver(self) -> None:
        document = copy.deepcopy(self.report)
        verdict = document["itemVerdicts"][0]
        verdict["verdict"] = "waived"
        document["summary"]["failed"] = 0
        document["summary"]["waived"] = 1
        errors = self.validate(document)
        self.assertTrue(
            any(error.path[-1:] == ("waiver",) for error in errors), errors
        )

    def test_summary_must_match_verdicts(self) -> None:
        document = copy.deepcopy(self.report)
        document["summary"]["passed"] = 1
        errors = self.validate(document)
        self.assertTrue(
            any(error.path == ("summary",) for error in errors), errors
        )

    def test_placeholder_digest_is_rejected(self) -> None:
        document = copy.deepcopy(self.profile)
        document["authoritySources"][0]["digest"] = "sha256:" + ("0" * 64)
        errors = self.validate(document)
        self.assertTrue(
            any("all-zero digest" in error.message for error in errors), errors
        )

    def test_invalid_datetime_is_rejected(self) -> None:
        document = copy.deepcopy(self.report)
        document["generatedAt"] = "not-a-date"
        errors = self.validate(document)
        self.assertTrue(
            any(error.path[-1:] == ("generatedAt",) for error in errors), errors
        )

    def test_stage_dependency_cycle_is_rejected(self) -> None:
        document = {
            "documentType": "stage-registry",
            "schemaVersion": "0.2.0",
            "registryId": "default-stages",
            "stages": [
                {
                    "id": "catalog-validation",
                    "kind": "validation",
                    "dependsOn": ["qualification"],
                    "stateGuards": [],
                },
                {
                    "id": "qualification",
                    "kind": "judgment",
                    "dependsOn": ["catalog-validation"],
                    "stateGuards": [],
                },
            ],
            "groups": {},
        }
        errors = self.validate(document)
        self.assertTrue(
            any("dependency cycle" in error.message for error in errors), errors
        )

    def test_tool_distribution_is_required(self) -> None:
        content_ref = {
            "id": "python-distribution",
            "digest": "sha256:" + ("5" * 64),
        }
        document = {
            "documentType": "toolchain-lock",
            "schemaVersion": "0.2.0",
            "lockId": "default-toolchain",
            "python": {
                "id": "python",
                "assessorKind": "custom",
                "role": "Runtime",
                "version": "3.14.0",
                "distributionRef": content_ref,
            },
            "tools": [
                {
                    "id": "ruff",
                    "assessorKind": "ruff",
                    "role": "Static diagnostics",
                    "version": "1.0.0",
                    "distributionRef": {
                        "id": "ruff-distribution",
                        "digest": "sha256:" + ("6" * 64),
                    },
                }
            ],
            "ansibleCollections": [],
            "executionEnvironmentImages": [],
            "inventories": [],
            "playbooks": [],
        }
        del document["tools"][0]["distributionRef"]
        errors = self.validate(document)
        self.assertTrue(
            any(error.path[-1:] == ("distributionRef",) for error in errors), errors
        )

    def test_bundle_digest_mismatch_is_rejected(self) -> None:
        profile_path = FIXTURES / "valid-profile.json"
        report_path = FIXTURES / "valid-report.json"
        profile_raw = profile_path.read_bytes()
        report_raw = report_path.read_bytes()
        report = copy.deepcopy(self.report)
        report["profileRef"]["digest"] = "sha256:" + ("7" * 64)
        errors = VALIDATOR.validate_bundle(
            [
                (profile_path, profile_raw, copy.deepcopy(self.profile)),
                (report_path, report_raw, report),
            ]
        )
        self.assertTrue(
            any(
                "digest does not match" in error.message
                for error in errors[report_path]
            ),
            errors,
        )


if __name__ == "__main__":
    unittest.main()
