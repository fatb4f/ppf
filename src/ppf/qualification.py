"""Claim-specific oracles and reliability-aware qualification judgment."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

Json = Any
_RELIABILITY = {"R0": 0, "R1": 1, "R2": 2, "R3": 3, "R4": 4}


@dataclass(frozen=True)
class QualificationRequest:
    run_ref: dict[str, Json]
    profile_ref: dict[str, Json]
    profile: dict[str, Json]
    plan: dict[str, Json]
    evidence_catalog: dict[str, Json]
    observations: tuple[dict[str, Json], ...]
    attempts: tuple[dict[str, Json], ...] = ()
    waivers: tuple[dict[str, Json], ...] = ()
    generated_at: str | None = None


@dataclass(frozen=True)
class QualificationResult:
    report: dict[str, Json]
    oracle_results: tuple[dict[str, Json], ...]
    verdict: str


def _oracle_result(
    case: dict[str, Json],
    observations: list[dict[str, Json]],
    oracle_ref: str,
) -> dict[str, Json]:
    unavailable = {
        "unavailable",
        "unsupported",
        "timed-out",
        "error",
    }
    if not observations or any(item["status"] in unavailable for item in observations):
        result = "insufficient-evidence"
        rationale = "required-observation-unavailable"
    else:
        configuration = case["probe"].get("configuration", {})
        actual_codes = [
            (item.get("semanticPayload") or item.get("payload") or {}).get("exitCode")
            for item in observations
        ]
        if configuration.get("expectExitCodeNonzero") is True:
            satisfied = all(code not in (None, 0) for code in actual_codes)
        else:
            expected = configuration.get("expectExitCode", 0)
            satisfied = all(code == expected for code in actual_codes)
        result = "satisfied" if satisfied else "refuted"
        rationale = "expectation-satisfied" if satisfied else "expectation-refuted"
    return {
        "id": f"oracle-{case['id']}-{oracle_ref}",
        "claimRef": case["claimRef"],
        "subjectRef": case["subject"]["id"],
        "oracleRef": oracle_ref,
        "observationRefs": [item["id"] for item in observations],
        "result": result,
        "rationaleCode": rationale,
    }


class QualificationService:
    """Apply oracles, admit claim-relative evidence, and aggregate verdicts."""

    def run(self, request: QualificationRequest) -> QualificationResult:
        observations_by_case: dict[str, list[dict[str, Json]]] = defaultdict(list)
        for observation in request.observations:
            observations_by_case[observation["caseRef"]].append(observation)
        oracle_results: list[dict[str, Json]] = []
        oracle_cases: dict[str, dict[str, Json]] = {}
        for case in request.plan["cases"]:
            for oracle_ref in case["oracleRefs"]:
                oracle = _oracle_result(
                    case,
                    observations_by_case[case["id"]],
                    oracle_ref,
                )
                oracle_results.append(oracle)
                oracle_cases[oracle["id"]] = case

        rules = request.evidence_catalog["rules"]
        admissions: list[dict[str, Json]] = []
        admitted_by_item: dict[tuple[str, str], list[tuple[dict[str, Json], str]]] = (
            defaultdict(list)
        )
        rejected_by_item: dict[tuple[str, str], list[str]] = defaultdict(list)
        for oracle in oracle_results:
            case = oracle_cases[oracle["id"]]
            rule = next(
                (
                    item
                    for item in rules
                    if item["claimRef"] == oracle["claimRef"]
                    and item["probeRef"] == case["probe"]["probeRef"]
                    and item.get("oracleRef") in (None, oracle["oracleRef"])
                ),
                None,
            )
            admission_id = f"admission-{oracle['id']}"
            minimum = case["probe"].get("configuration", {}).get(
                "minimumReliability", "R0"
            )
            admitted = (
                rule is not None
                and _RELIABILITY[rule["assignedReliability"]]
                >= _RELIABILITY[minimum]
            )
            observation_ref = (
                oracle["observationRefs"][0]
                if oracle["observationRefs"]
                else f"missing-{case['id']}"
            )
            admission = {
                "id": admission_id,
                "claimRef": oracle["claimRef"],
                "observationRef": observation_ref,
                "catalogRuleRef": rule["id"] if rule else "missing-rule",
                "assignedReliability": rule["assignedReliability"] if rule else "R0",
                "admitted": admitted,
                "oracleResultRef": oracle["id"],
                "rejectionReason": None if admitted else "reliability-or-source-missing",
            }
            admissions.append(admission)
            key = (oracle["claimRef"], oracle["subjectRef"])
            if admitted:
                admitted_by_item[key].append((oracle, admission_id))
            else:
                rejected_by_item[key].append(admission_id)

        generated_at = request.generated_at or datetime.now(UTC).isoformat().replace(
            "+00:00", "Z"
        )
        report_time = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
        verdicts = []
        for key in sorted(
            {
                (case["claimRef"], case["subject"]["id"])
                for case in request.plan["cases"]
            }
        ):
            evidence = admitted_by_item[key]
            results = {oracle["result"] for oracle, _ in evidence}
            if "refuted" in results:
                verdict = "fail"
                rationale = "At least one admitted oracle result refuted the claim."
                missing: list[str] = []
            elif not evidence or "insufficient-evidence" in results:
                verdict = "inconclusive"
                rationale = "Required admitted evidence is unavailable or insufficient."
                missing = ["required admitted evidence"]
            else:
                verdict = "pass"
                rationale = "All required admitted oracle results satisfied the claim."
                missing = []
            underlying_verdict = verdict
            waiver = next(
                (
                    item
                    for item in request.waivers
                    if key[0] in item["scope"]
                    and datetime.fromisoformat(
                        item["expiresAt"].replace("Z", "+00:00")
                    )
                    >= report_time
                ),
                None,
            )
            if verdict == "fail" and waiver is not None:
                verdict = "waived"
                rationale = (
                    f"{rationale} Active scoped waiver {waiver['id']!r} was applied."
                )
            verdicts.append(
                {
                    "id": f"verdict-{key[0].lower()}-{key[1]}",
                    "itemRef": key[0],
                    "subjectRef": key[1],
                    "verdict": verdict,
                    "underlyingVerdict": underlying_verdict,
                    "admittedEvidenceRefs": [item[1] for item in evidence],
                    "rejectedEvidenceRefs": rejected_by_item[key],
                    "missingEvidence": missing,
                    "rationale": rationale,
                    "waiver": waiver if verdict == "waived" else None,
                }
            )

        summary = {
            "passed": sum(item["verdict"] == "pass" for item in verdicts),
            "failed": sum(item["verdict"] == "fail" for item in verdicts),
            "inconclusive": sum(
                item["verdict"] == "inconclusive" for item in verdicts
            ),
            "notApplicable": sum(
                item["verdict"] == "not-applicable" for item in verdicts
            ),
            "waived": sum(item["verdict"] == "waived" for item in verdicts),
        }
        report = {
            "documentType": "qualification-report",
            "schemaVersion": "0.2.0",
            "reportId": f"report-{request.run_ref['id']}",
            "runRef": request.run_ref,
            "profileRef": request.profile_ref,
            "generatedAt": generated_at,
            "admissions": admissions,
            "summary": summary,
            "itemVerdicts": verdicts,
            "selectedOptionalProfiles": [],
        }
        aggregate = (
            "fail"
            if summary["failed"]
            else "inconclusive"
            if summary["inconclusive"]
            else "pass"
        )
        return QualificationResult(
            report=report,
            oracle_results=tuple(oracle_results),
            verdict=aggregate,
        )
