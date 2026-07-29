---
name: python-policy-ppf
description: Compile Python 3.14 canonical specifications, project policy, advisory guidance, diagnostics, fixtures, probes, observations, admissions, and waivers into source-locked PPF generation-policy and qualification artifacts. Use for Python generation profiles, Kattis-style evaluation plans, counterexample promotion, or Ruff, ty, Pydantic, pytest, Hypothesis, Cyclopts, and Ansible assessors.
---
# Python Policy PPF

## Inputs

- Canonical and advisory source references.
- Project policy and repository scope.
- Evaluation subjects, fixtures, probes, and gates.
- Existing profile, plan, run, or report artifacts.

## Procedure

1. Discover the packaged contract with `ppf-validate catalog`, then disclose
   only each relevant document schema with `ppf-validate catalog DOCUMENT_TYPE`.
2. Classify each authority as `canonical-specification`, `versioned-rationale`, `project-policy`, `advisory-reference`, or `diagnostic-documentation`.
3. Lock every source, configuration, subject, tool distribution, and artifact by SHA-256 digest.
4. Map each policy claim to applicability, gates, fixtures, probes, oracles, and limitations.
5. Preserve raw execution evidence separately from normalized observations and evidence admission.
6. Preserve `pass`, `fail`, `inconclusive`, `not-applicable`, and `waived`, including the underlying verdict.
7. Emit only document types declared by the official schema or a registered sidecar extension.
8. Validate related artifacts together so semantic cross-references and content
   digests are checked. Pass `--repository-root` whenever the bundle contains
   repository-local content or implementation lock checks:

```bash
ppf-validate validate --repository-root REPOSITORY PATH.json [PATH.json ...]
```

## Evaluation workflow

Treat the evaluation-workflow extension as authoritative for exact states,
transitions, causes, and document constraints. Apply this operational flow:

1. Lock the input closure and move from `planned` to `inputs-bound`.
2. For `qualification-only`, skip the baseline and implementation iterations,
   then run full qualification.
3. For `implement-and-qualify`, run and judge the baseline. A passing baseline
   may proceed to implementation or directly to full qualification; a failed or
   inconclusive baseline may proceed to full qualification or stop.
4. When implementation is authorized, run one or more implementation
   iterations, repeating as needed, then run full qualification.
5. On full qualification, record `qualified` only for a pass. Record `rejected`
   for a failure, inconclusive result, or rejected input integrity.
6. Revoke an existing `qualified` state to `rejected` if input integrity is
   later revoked.

## Constraints

- Do not bind a claim solely to advisory or diagnostic authority.
- Do not treat an assessor, diagnostic, or green tool run as contract authority.
- Convert unavailable, unsupported, timed-out, malformed, or missing required evidence into `inconclusive`.
- Do not infer unsupported source claims.
- Keep canonical claims, versioned rationale, and local policy decisions distinct.
- Require a scoped, authorized, active waiver and retain its underlying failed verdict.
- Promote minimized counterexamples only through a qualification report.
- Keep extension documents separate from official documents; do not add extension
  properties to closed official document types.
