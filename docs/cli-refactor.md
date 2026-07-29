# Cyclopts Root CLI Migration

Summary:

- Replace both src argparse entrypoints with one Cyclopts application invoked as ppf-validate DOCUMENT....
- Preserve JSON output and validation exit codes while adopting Cyclopts-native help and argument errors.
- Repair schema and fixture paths for the consolidated python-policy-ppf/ layout.
- Add deterministic qualification coverage and an on-demand, gitignored deterministic-evidence.jsonl.

Interfaces:

- Expose a module-level Cyclopts app; retain main() for the existing console-script entrypoint.
- Make document paths a required, one-or-more root argument accepting files or directories.
- Return 0 for valid bundles and 1 for validation failures; malformed CLI input follows Cyclopts conventions.
- Make core.main() delegate to the same application. Remove its separate --schema interface.
- Leave python-policy-ppf/scripts/validate_catalog.py unchanged because it is outside the requested src CLI.

Implementation:

- Add Cyclopts as a runtime dependency; add direct development dependencies for Pydantic, Hypothesis, and LibCST, then refresh uv.lock.
- Extract a small internal validation-service seam so command behavior can be tested with deterministic fakes without invoking filesystem validation.
- Resolve registered schemas and fixtures from the existing python-policy-ppf/ tree and update stale shared-test paths.
- Add a qualification harness with strict Pydantic evidence records containing a stable check ID, mechanism, status, subject digest, and assertion. Sort
  records and JSON keys; omit timestamps, durations, absolute paths, and temporary-directory values.

- Cover canonical JSON Schema checks, Pydantic evidence validation, AST/LibCST/token migration probes, pytest assertions, Hypothesis-generated path lists
  with a fake validation service, and fixture/adapter tests.

- Write the complete evidence set to repository-root deterministic-evidence.jsonl, exit nonzero on any failed probe, and add the artifact to .gitignore.
