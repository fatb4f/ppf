# PPF Semantic Workspace and Deterministic Graph Projection

## Summary

- Phase 0A — Restore authoritative validation before workspace work:
  - Keep the legacy script as a shim to `ppf.cli`; prohibit independent validation logic.
  - Verify schemas are packaged from `src/ppf/schemas` and loaded only through `importlib.resources`.
  - Preserve structural gating: malformed or structurally invalid documents never enter semantic validators.
  - Add `build` to development dependencies, regenerate `uv.lock`, and repair the currently inconsistent “valid” fixture closure and stale cross-document digests.
  - Add clean-wheel tests proving the installed CLI works without source-tree paths. Workspace implementation starts only after this gate passes.

- Phase 0B — Introduce structured diagnostics additively:
  - Replace internal error construction with `Diagnostic(code, rule_id, severity, subject, instance_path, schema_path, related, evidence)`.
  - Preserve `kind`, `path`, and `message` properties and JSON keys for compatibility.
  - Curate IDs only for semantic/repository rules. For JSON Schema failures, derive `ruleId` as `schema-uri#absolute-schema-path` and `code` from the failing keyword, such as `PPF-SCHEMA-REQUIRED`.
  - Model invalid input files as artifact subjects so parse failures can still produce structured diagnostics.

- Phase 0C — Establish declaration ownership:
  - Make `schema-registry.json` authoritative for schema resources, roles, digests, composition, document types, schema/identity pointers, validator IDs, and `ReferenceFieldSpec` declarations.
  - Load `DocumentTypeSpec` from this registry; do not maintain an independent Python document-type table.
  - Treat schema discriminators and composed mappings as validated/generated projections of registry declarations.
  - Limit Python registries to `validator/projector/command ID → callable`.
  - Fail catalog loading when a declaration lacks an adapter, an adapter lacks a declaration, an identity/schema pointer is invalid, or a composed/discriminator mapping diverges.

- Phase 0D — Generalize references without relying solely on schema introspection:
  - Make registry `ReferenceFieldSpec` records the runtime traversal authority, including pointer pattern, value type, target kind, relation kind, cardinality, internal/external behavior, and required context.
  - Use schema traversal only as an audit: reject declarations that do not resolve to their stated type and report every schema-discovered ContentRef location lacking a runtime declaration.
  - Replace `_internal_content_refs()` and heuristic ContentRef discovery with compiled pointer-pattern traversal.
  - Resolve repository-local ContentRefs exclusively through `ValidationContext.repository_root`; never search arbitrary ancestors.

- Phase 0E — Build a total `ResolvedWorkspace`:
  - Define `EntityKey(workspace_id, kind, namespace, entity_id)`.
  - Resolve `workspace_id` from explicit `--workspace-id`, otherwise from the authoritative verification catalog; if neither exists, emit `PPF-WORKSPACE-ID-REQUIRED` while still returning a workspace with a deterministic provisional ID.
  - Use these identities:
    - Documents: namespace is document type; ID is the canonical identity-pointer value.
    - Embedded records: namespace is the canonical percent-encoded parent `EntityKey`; ID is the local ID.
    - Artifacts: repository-relative normalized POSIX path; digest remains version metadata.
    - Schemas: `$id`; definitions add their JSON Pointer.
    - Python symbols: distribution name/module plus qualified name.
    - Fixtures/tests/probes: verification catalog ID.
    - Diagnostics: SHA-256 over canonical code, subject, instance/schema paths, and sorted related keys; message is excluded.
  - Extend `EntityKind` with explicit claim, case, execution, observation, oracle-result, admission, verdict, workflow, binding, assembly, and integrity-judgment kinds.
  - Stage construction as artifact load → parse → structural validation → identity/reference resolution → semantic/repository validation. Parse failures emit artifact nodes; structural failures emit provisional document shells when possible. No malformed value may abort projection.

- Phase 0F — Add authored rules and authoritative verification metadata:
  - Preserve the official generation-policy `0.2.0` bytes and add an additive semantic-projection sidecar for `EntityRef`, invariant/enforcement definitions, `PythonSymbolRef`, verification catalogs, and receipts.
  - Derive the runtime `RuleCatalog` from authored sidecar invariants and registry validator bindings; do not create a duplicate Python rule table.
  - Make `verification-catalog.json` authoritative for fixture expectations, rule coverage, symbols, probes, and source digests.
  - Mark tests only with `@ppf_verification("catalog-id")`; markers contain no repeated fixtures, rules, or expected diagnostics.
  - Validate that symbols exist, collected tests carry the declared ID, fixtures/rules/probes resolve, and required source digests are current.
  - Emit warning diagnostics for missing positive or negative rule coverage so the graph can answer coverage questions without making initial incompleteness fatal.

- Phase 0G — Index schemas and implementation bindings:
  - Index schema resources and definitions; retain properties and schema relationships as catalog metadata rather than P0 graph nodes.
  - Resolve declared adapter callables into architectural `PythonSymbolRef` records with source ContentRefs and optional source spans.
  - Index only declared validator, command, projector, adapter, test, and probe symbols—never infer a Python call graph.

- Phase 0H — Project a pure `GraphBundle`:
  - Implement `project_graph(workspace)` as a side-effect-free transformation with stable sorting by complete `EntityKey`, relation kind, target key, and provenance.
  - Preserve repository-relative source paths, JSON pointers, extractor IDs, and extractor versions on every relation.
  - Emit derived nodes, typed relations, and diagnostic overlays only; GraphBundle is never an authored canonical input.

- Phase 0I — Add non-circular projection artifacts and receipts:
  - Serialize graph output as `{schema, bundle, receipt}` where `bundleDigest = SHA-256(RFC8785(bundle))`.
  - Keep receipt data and `generatedAt` outside the hashed bundle. Inject the clock for tests.
  - For editable installs, define `ppf.source-manifest.v1` as RFC 8785 over sorted exact-byte digests of `pyproject.toml`, `uv.lock`, and regular non-symlink files under `src/ppf`.
  - Explicitly exclude `.git`, caches, virtual environments, build/dist output, generated evidence, graph artifacts, receipts, credentials, and machine-local state. Register the computed manifest bytes in the workspace content index so its ContentRef is resolvable.
  - Apply receipts to graph artifacts and existing qualification evidence; future generators must use the same contract.

- Phase 0J — Expose total JSON CLI commands:
  - Add `workspace` and `graph` commands accepting document paths, `--repository-root`, `--workspace-id`, and optional `--verification-catalog`.
  - Write exactly one complete JSON value to stdout; reserve stderr for operational logs.
  - Return zero only when no error-severity diagnostics exist. Validation failures still return a complete workspace or graph artifact with diagnostics.
  - Keep persistence, query engines, live graph patches, property nodes, call-graph inference, arbitrary assertion analysis, and visualization state out of P0.

## Validation

- Phase 0A gate:
  - `uv lock && uv sync --frozen`: dependency lock regenerated and reproducible.
  - `uv run pytest`: authoritative source-tree validation suite passes.
  - `uv run python -m build`: wheel and sdist build successfully.
  - Install the newly built wheel into a fresh temporary virtual environment, then run `ppf-validate catalog`.
  - From that clean environment, validate the closure-complete `valid-*.json` fixture bundle successfully and assert each `invalid-*.json` fixture fails with its cataloged diagnostic.
- `uv run ruff check src tests .codex/skills/python-policy-ppf/tests`: pass.
- Catalog tests must reject missing adapters, undeclared adapters, invalid identity/reference pointers, stale resource digests, schema/registry divergence, and unmapped ContentRef locations.
- Workspace tests must cover parse failures, structural failures, missing IDs, duplicate/conflicting identities, reused local IDs across document families, unsafe repository paths, and malformed nested values without crashes.
- Verification tests must enforce catalog-only metadata ownership and marker-ID consistency.
- Graph tests must prove deterministic answers for:
  - fixture → expected diagnostic → rule → validator
  - document type → schema fragment → semantic validator
  - qualification evidence → check → input artifact
  - schema resource → composed schema → registered document types
  - artifact → ContentRef locations → digest diagnostics
  - rule → positive/negative fixtures and tests/probes
- Run workspace and graph projection twice with an injected fixed clock; assert byte-identical RFC 8785 bundles, identical `bundleDigest`, stable relation provenance, and receipts excluded from the bundle hash.
