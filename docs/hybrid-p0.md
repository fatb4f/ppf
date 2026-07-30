# Hybrid qualification P0

PPF exposes four independent command surfaces:

```text
ppf-validate   structural, semantic, reference, and digest validation
ppf-assess     deterministic planning and evidence-producing execution
ppf-qualify    oracles, evidence admission, and qualification reports
python-ppf     authoritative workflow transitions and bounded Git repair
```

Authoritative input always follows:

```text
SchemaCatalog validation
→ semantic and bundle validation
→ generated Pydantic boundary parsing
→ handwritten domain services
```

`ppf-assess` verifies and copies the declared tool-environment closure into a
disposable root before Bubblewrap mounts it read-only at `/`. The repository is
mounted read-only at `/workspace`; only declared writable paths are overlaid.
Pre-launch failures produce `operational-attempt` documents and never producer
envelopes.

Raw stdout, stderr, Runner events, execution metadata, and control documents are
stored by byte digest in a run-specific artifact manifest. Repeatability is
measured separately through `evaluation-semantic-projection`, which excludes
declared native timestamps, UUIDs, durations, PIDs, temporary paths, and raw
artifact identities.

Repairs are applied only in detached disposable Git worktrees. The actual
resulting tree diff—not merely patch headers—is checked against the repair
decision. Verified trees are promoted by compare-and-swap to
`refs/ppf/repairs/{workflowId}`; the caller's branch and checkout are untouched.
