"""Claim-specific oracles and reliability-aware qualification judgment."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .catalog import SchemaCatalog
from .core import validate_semantics

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
    invocations: tuple[dict[str, Json], ...] = ()
    producer_invocation_refs: tuple[str, ...] = ()
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
    *,
    invocation_coverage_failed: bool = False,
) -> dict[str, Json]:
    unavailable = {
        "unavailable",
        "unsupported",
        "timed-out",
        "error",
    }
    if invocation_coverage_failed:
        result = "insufficient-evidence"
        rationale = "required-invocation-outcome-missing-or-failed"
    elif not observations or any(item["status"] in unavailable for item in observations):
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
        plan_errors = validate_semantics({"documentType": "evaluation-plan", **request.plan})
        input_errors = [
            *(error for error in plan_errors if error.path and error.path[-1] == "oracleRefs"),
            *validate_semantics(
                {
                    "documentType": "evaluation-evidence-catalog",
                    **request.evidence_catalog,
                }
            ),
        ]
        if input_errors:
            raise ValueError(
                "invalid qualification selectors: "
                + "; ".join(error.message for error in input_errors)
            )

        observations_by_case: dict[str, list[dict[str, Json]]] = defaultdict(list)
        for observation in request.observations:
            observations_by_case[observation["caseRef"]].append(observation)

        case_ids = {case["id"] for case in request.plan["cases"]}
        coverage_failed_cases: set[str] = set()
        if request.invocations:
            expected_by_id = {
                invocation["invocationId"]: invocation for invocation in request.invocations
            }
            producer_counts = Counter(request.producer_invocation_refs)
            attempt_counts = Counter(attempt["invocationRef"]["id"] for attempt in request.attempts)
            for invocation_id, invocation in expected_by_id.items():
                producer_count = producer_counts[invocation_id]
                attempt_count = attempt_counts[invocation_id]
                if not (producer_count == 1 and attempt_count == 0):
                    coverage_failed_cases.add(invocation["caseRef"])
            if (
                set(producer_counts) - set(expected_by_id)
                or set(attempt_counts) - set(expected_by_id)
                or len(expected_by_id) != len(request.invocations)
            ):
                coverage_failed_cases.update(case_ids)
        elif request.attempts:
            # Older direct callers do not supply the compiled invocation set. An
            # operational failure is still terminally relevant, so fail closed.
            coverage_failed_cases.update(case_ids)

        oracle_results: list[dict[str, Json]] = []
        oracle_cases: dict[str, dict[str, Json]] = {}
        for case in request.plan["cases"]:
            for oracle_ref in case["oracleRefs"]:
                oracle = _oracle_result(
                    case,
                    observations_by_case[case["id"]],
                    oracle_ref,
                    invocation_coverage_failed=case["id"] in coverage_failed_cases,
                )
                oracle_results.append(oracle)
                oracle_cases[oracle["id"]] = case

        rules = request.evidence_catalog["rules"]
        admissions: list[dict[str, Json]] = []
        admitted_by_item: dict[tuple[str, str], list[tuple[dict[str, Json], str]]] = defaultdict(
            list
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
            minimum = case["probe"].get("configuration", {}).get("minimumReliability", "R0")
            admitted = (
                rule is not None
                and _RELIABILITY[rule["assignedReliability"]] >= _RELIABILITY[minimum]
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

        generated_at = request.generated_at or datetime.now(UTC).isoformat().replace("+00:00", "Z")
        report_time = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
        verdicts = []
        for key in sorted(
            {(case["claimRef"], case["subject"]["id"]) for case in request.plan["cases"]}
        ):
            evidence = admitted_by_item[key]
            results = {oracle["result"] for oracle, _ in evidence}
            rejected = rejected_by_item[key]
            if "refuted" in results:
                verdict = "fail"
                rationale = "At least one admitted oracle result refuted the claim."
                missing: list[str] = []
            elif rejected:
                verdict = "inconclusive"
                rationale = "At least one required case, oracle, or source was rejected."
                missing = [f"rejected required evidence: {reference}" for reference in rejected]
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
                    and datetime.fromisoformat(item["expiresAt"].replace("Z", "+00:00"))
                    > report_time
                ),
                None,
            )
            if verdict == "fail" and waiver is not None:
                verdict = "waived"
                rationale = f"{rationale} Active scoped waiver {waiver['id']!r} was applied."
            verdicts.append(
                {
                    "id": f"verdict-{key[0].lower()}-{key[1]}",
                    "itemRef": key[0],
                    "subjectRef": key[1],
                    "verdict": verdict,
                    "underlyingVerdict": underlying_verdict,
                    "admittedEvidenceRefs": [item[1] for item in evidence],
                    "rejectedEvidenceRefs": rejected,
                    "missingEvidence": missing,
                    "rationale": rationale,
                    "waiver": waiver if verdict == "waived" else None,
                }
            )

        summary = {
            "passed": sum(item["verdict"] == "pass" for item in verdicts),
            "failed": sum(item["verdict"] == "fail" for item in verdicts),
            "inconclusive": sum(item["verdict"] == "inconclusive" for item in verdicts),
            "notApplicable": sum(item["verdict"] == "not-applicable" for item in verdicts),
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
            "fail" if summary["failed"] else "inconclusive" if summary["inconclusive"] else "pass"
        )
        structural_errors = list(
            SchemaCatalog.load().validator("qualification-report").iter_errors(report)
        )
        semantic_errors = validate_semantics(report)
        if structural_errors or semantic_errors:
            details = [
                *(error.message for error in structural_errors),
                *(error.message for error in semantic_errors),
            ]
            raise ValueError(
                "qualification service produced an invalid report: " + "; ".join(details)
            )
        return QualificationResult(
            report=report,
            oracle_results=tuple(oracle_results),
            verdict=aggregate,
        )
