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

1. Read `references/python-policy-ppf.schema.json` and `schema-registry.json`.
2. Classify each authority as `canonical-specification`, `versioned-rationale`, `project-policy`, `advisory-reference`, or `diagnostic-documentation`.
3. Lock every source, configuration, subject, tool distribution, and artifact by SHA-256 digest.
4. Map each policy claim to applicability, gates, fixtures, probes, oracles, and limitations.
5. Preserve raw execution evidence separately from normalized observations and evidence admission.
6. Preserve `pass`, `fail`, `inconclusive`, `not-applicable`, and `waived`, including the underlying verdict.
7. Emit only document types declared by the official schema or a registered sidecar extension.
8. Validate related artifacts together so semantic cross-references and content digests are checked:

```bash
python <skill-directory>/scripts/validate_catalog.py PATH.json [PATH.json ...]
```

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
