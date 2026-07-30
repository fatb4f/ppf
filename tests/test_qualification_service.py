from __future__ import annotations

import pytest

from ppf.catalog import SchemaCatalog
from ppf.core import validate_semantics
from ppf.qualification import QualificationRequest, QualificationService

DIGEST = "sha256:" + ("1" * 64)


def _ref(identifier: str) -> dict[str, str]:
    return {"id": identifier, "digest": DIGEST}


def _request(
    *,
    status: str | None,
    exit_code: int | None,
    waivers: tuple[dict[str, object], ...] = (),
) -> QualificationRequest:
    case = {
        "id": "case-ho-01",
        "claimRef": "HO-01",
        "subject": {"id": "decorator"},
        "fixture": {"id": "ordinary"},
        "probe": {
            "probeRef": "runtime-probe",
            "configuration": {"expectExitCode": 0, "minimumReliability": "R3"},
        },
        "oracleRefs": ["exit-oracle"],
    }
    observations = ()
    if status is not None:
        observations = (
            {
                "id": "observation",
                "caseRef": "case-ho-01",
                "subjectRef": "decorator",
                "status": status,
                "semanticPayload": {"exitCode": exit_code},
            },
        )
    return QualificationRequest(
        run_ref=_ref("run"),
        profile_ref=_ref("profile"),
        profile={},
        plan={"cases": [case]},
        evidence_catalog={
            "rules": [
                {
                    "id": "runtime-rule",
                    "claimRef": "HO-01",
                    "probeRef": "runtime-probe",
                    "oracleRef": "exit-oracle",
                    "assignedReliability": "R3",
                }
            ]
        },
        observations=observations,
        waivers=waivers,
        generated_at="2026-07-29T12:00:00Z",
    )


def test_judge_separates_pass_failure_and_missing_evidence() -> None:
    service = QualificationService()
    assert service.run(_request(status="passed", exit_code=0)).verdict == "pass"
    assert service.run(_request(status="failed", exit_code=1)).verdict == "fail"
    inconclusive = service.run(_request(status=None, exit_code=None))
    assert inconclusive.verdict == "inconclusive"
    assert inconclusive.report["itemVerdicts"][0]["missingEvidence"]
    assert not list(
        SchemaCatalog.load().validator("qualification-report").iter_errors(inconclusive.report)
    )
    assert not validate_semantics(inconclusive.report)


def test_active_waiver_preserves_underlying_failure() -> None:
    waiver = {
        "id": "waiver-ho-01",
        "owner": "policy-owner",
        "rationale": "Temporary authorized exception.",
        "expiresAt": "2026-07-30T12:00:00Z",
        "scope": ["HO-01"],
        "authorizationRef": {
            "id": "authorization",
            "digest": DIGEST,
            "uri": "https://example.invalid/authorization",
        },
    }
    result = QualificationService().run(_request(status="failed", exit_code=1, waivers=(waiver,)))
    verdict = result.report["itemVerdicts"][0]
    assert result.verdict == "pass"
    assert verdict["verdict"] == "waived"
    assert verdict["underlyingVerdict"] == "fail"
    assert not validate_semantics(result.report)


def test_rejected_required_case_prevents_pass() -> None:
    request = _request(status="passed", exit_code=0)
    second_case = {
        **request.plan["cases"][0],
        "id": "case-ho-01-source",
        "probe": {
            "probeRef": "missing-source-probe",
            "configuration": {"expectExitCode": 0, "minimumReliability": "R3"},
        },
    }
    second_observation = {
        **request.observations[0],
        "id": "observation-source",
        "caseRef": second_case["id"],
    }
    result = QualificationService().run(
        QualificationRequest(
            **{
                **request.__dict__,
                "plan": {"cases": [request.plan["cases"][0], second_case]},
                "observations": (*request.observations, second_observation),
            }
        )
    )
    verdict = result.report["itemVerdicts"][0]
    assert result.verdict == "inconclusive"
    assert verdict["rejectedEvidenceRefs"]
    assert verdict["missingEvidence"]


def test_operational_failure_forces_insufficient_evidence() -> None:
    request = _request(status="passed", exit_code=0)
    result = QualificationService().run(
        QualificationRequest(
            **{
                **request.__dict__,
                "attempts": (
                    {
                        "invocationRef": _ref("invocation-failed"),
                        "status": "preparation-failed",
                    },
                ),
            }
        )
    )
    assert result.verdict == "inconclusive"
    assert result.oracle_results[0]["result"] == "insufficient-evidence"
    assert result.oracle_results[0]["rationaleCode"] == (
        "required-invocation-outcome-missing-or-failed"
    )


def test_compiled_invocations_require_exactly_one_producer_outcome() -> None:
    request = _request(status="passed", exit_code=0)
    invocation = {"invocationId": "invoke-case", "caseRef": "case-ho-01"}
    for producer_refs in ((), ("invoke-case", "invoke-case")):
        result = QualificationService().run(
            QualificationRequest(
                **{
                    **request.__dict__,
                    "invocations": (invocation,),
                    "producer_invocation_refs": producer_refs,
                }
            )
        )
        assert result.verdict == "inconclusive"


def test_waiver_expiring_at_report_time_is_inactive() -> None:
    waiver = {
        "id": "waiver-ho-01",
        "owner": "policy-owner",
        "rationale": "Boundary check.",
        "expiresAt": "2026-07-29T12:00:00Z",
        "scope": ["HO-01"],
        "authorizationRef": {
            "id": "authorization",
            "digest": DIGEST,
            "uri": "https://example.invalid/authorization",
        },
    }
    result = QualificationService().run(_request(status="failed", exit_code=1, waivers=(waiver,)))
    assert result.verdict == "fail"
    assert result.report["itemVerdicts"][0]["verdict"] == "fail"
    assert not validate_semantics(result.report)


def test_duplicate_and_ambiguous_selectors_are_rejected() -> None:
    duplicate = _request(status="passed", exit_code=0)
    duplicate.plan["cases"][0]["oracleRefs"].append("exit-oracle")
    with pytest.raises(ValueError, match="duplicate oracle"):
        QualificationService().run(duplicate)

    ambiguous = _request(status="passed", exit_code=0)
    ambiguous.evidence_catalog["rules"].append(
        {
            **ambiguous.evidence_catalog["rules"][0],
            "id": "runtime-wildcard",
            "oracleRef": None,
        }
    )
    with pytest.raises(ValueError, match="ambiguous wildcard"):
        QualificationService().run(ambiguous)
