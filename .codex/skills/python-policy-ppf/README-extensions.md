# Python Policy PPF sidecar extensions

The installed `ppf.schemas` package preserves the official schema unchanged and
registers three additive Draft 2020-12 sidecar schemas:

- `ppf.schemas/extensions/python-policy-ppf.eval-workflow-extension.schema.json`
  (`urn:python-policy-ppf:extension:evaluation-workflow:0.2.0`)
- `ppf.schemas/extensions/python-policy-implementation.extension.schema.json`
  (`urn:python-policy-ppf:implementation-policy-extension:0.2.0`)
- `ppf.schemas/extensions/python-policy-ppf.schema-conformance-extension.schema.json`
  (`urn:python-policy-ppf:extension:schema-conformance:0.2.0`)

The composed schema accepts an official document or a registered extension
document. The packaged registry maps every canonical `$id` to its
package-relative resource; the composed discriminator is authoritative for
document-type targets.

The implementation-policy extension also defines additive shaping documents:

- `shaping-policy` encodes the fact-driven decision flow.
- `shaping-profile-registry` defines the narrow semantic profile and facet vocabulary.
- `shaping-implementation-binding` binds semantic selections to implementation,
  Python 3.14 annotation, HOF, concurrency, isolation, and generation policies.
- `shaping-decision-record` binds admitted facts and the resolved primary,
  collaborator, and facet selections to immutable content references.
- `capability-provider-registry` declares composition roots, providers, scopes,
  contexts, aliases, managed capabilities, and admitted overrides.
- `dependency-wiring-plan` records the immutable normalized dependency-slot
  plan consumed by both graph validation and runtime resolution.
- `capability-assembly-record` records compiled resolver provenance, active
  scopes, context and override overlays, findings, and finalization evidence.
- `qualification-fixture-projection` projects selected provider roots through
  an explicit graph-boundary adapter into pytest fixtures.

Semantic profiles compose. A decision has one primary profile by default and
may require collaborator profiles and composition facets. Profile and facet
dependencies are resolved transitively before implementation binding.

Capability assembly remains downstream from semantic shaping. Technologies such
as `modern-di` and `modern-di-pytest` are implementation bindings. Provider
registries follow `declare → validate → freeze → compile → execute`; fixture
projection validates DI/pytest scope compatibility and fixture-name collisions
before publishing into an explicitly selected module.

The extensions do not patch official instances with `allOf`. Official document
types remain closed and authoritative; extension data is carried in separate
documents linked through official `ContentRef` values.

Use `ppf-validate catalog` for progressive discovery and `ppf-validate validate`
for structural, semantic, bundle, repository, and digest validation. Fixtures
under `tests/fixtures/` demonstrate the implementation and evaluation
extensions.
