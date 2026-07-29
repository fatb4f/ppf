---
name: handoff
description: Install and run the handoff CLI to create deterministic Git-and-Codex session handoffs. Use before ending, resetting, or compacting a coding session, or when asked to preserve repository and rollout state for a later agent.
---

# Handoff

## Install

Install the CLI directly from its Git repository when `handoff` is unavailable:

```bash
uv tool install "git+https://github.com/fatb4f/runtime.git"
handoff --help
```

From a local source checkout, use `uv run handoff` instead; `uv` resolves the
locked project environment.

## Create a handoff

1. Finish or interrupt the active operation at a coherent boundary.
2. Emit one concise progress update using only applicable fields:

   ```text
   Objective: <objective>
   Completed:
   - <completed item>
   Current operation: <current operation>
   Next operation: <next operation>
   Completion criteria:
   - <completion criterion>
   Open questions:
   - <open question>
   ```

3. From the target Git repository, run one of:

   ```bash
   handoff create
   uv run handoff create  # local source checkout
   ```

4. Return the emitted `handoff.json` path for the next session.

The command stages repository changes and derives the handoff from staged Git
state plus the current Codex rollout. Do not manually edit the generated file.
If creation fails, report the error and do not claim the handoff is complete.

Use `--rollout PATH` only to select an explicit rollout JSONL file. Use
`--output-root PATH` only when the default state directory is unsuitable; the
output root must remain outside the repository.
