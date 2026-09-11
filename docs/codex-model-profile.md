# Model Profile (Codex / ZCode)

This is the default execution profile for agent-driven EVM audits. The
artifact keeps its machine name `codex-model-profile` for lineage
compatibility; since schema version 2 it carries a `provider` field with two
supported vocabularies. Confirm one profile at audit startup; explicit stage
overrides may customize that profile for the audit.

Codex default (`provider: codex`; unchanged from v1):

| Public phase | Default Codex model |
| --- | --- |
| Project Analysis | Luna · Max |
| Context Analysis | Terra · Medium |
| Initial Review | Terra · High |
| Deep Audit | Sol · High |
| Vulnerability Validation | Sol · Max |
| Final Report | Terra · Medium |

ZCode default (`provider: zcode`; each stage additionally names the worker
agent type that dispatches it, `null` for controller-run stages):

| Public phase | Model | Worker agent |
| --- | --- | --- |
| Project Analysis | GLM-5.3 · Max | — (main agent) |
| Context Analysis · Resolution | GLM-5.3 · Medium | — (main agent) |
| Context Analysis · Domain Context | GLM-5.3-Flash · Medium | `evm-audit-worker-flash` |
| Initial Review | GLM-5.3 · High | `evm-audit-worker-deep` |
| Deep Audit | GLM-5.3 · High | `evm-audit-worker-deep` |
| Vulnerability Validation | GLM-5.3 · Max | `evm-audit-worker-deep` |
| Final Report | GLM-5.3 · Medium | — (main agent) |

Initial Review deliberately uses the flagship model: `NOT_APPLICABLE_CONFIRMED`
is a trusted-absence decision, so triage quality is security-relevant.

Use the defaults unless a stage needs a deliberate model or reasoning
override. The selected profile is stored as
`config/codex-model-profile.json` inside the audit run and must contain every
internal stage ID exactly once. A zcode stage entry is
`{model, reasoning_effort, agent}`; the validator enforces that the declared
`model` matches the model pinned in the named worker agent's template
(`evm-audit-worker-deep` ⇒ GLM-5.3, `evm-audit-worker-flash` ⇒
GLM-5.3-Flash), so the profile cannot claim a model the dispatched agent does
not run. Reasoning effort is advisory metadata for ZCode (the agent type
does not expose a separate effort control).

To set defaults for future audits, create and edit the user-level profile for
your provider:

```bash
python3 scripts/audit_run.py models --init-global --provider codex   # ~/.codex/evm-audit-model-profile.json
python3 scripts/audit_run.py models --init-global --provider zcode   # ~/.zcode/evm-audit-model-profile.json
```

`init --provider <codex|zcode>` copies the validated user-level profile of
that provider into the run. Later global edits apply only to new runs; edit
the run-scoped copy to change an existing run. If the user-level file is
absent, `init` snapshots the built-in defaults for that provider. An explicit
`--model-profile` file always wins over the provider flag. Profiles with an
older schema version are rejected; there is no v1 compatibility path.

## What the profile does and does not do

The model profile controls model selection only. It does not relax immutable
routing, evidence gates, proof requirements, stale-artifact rejection, or
confirmed-only reporting.

The controller exposes the recommended model and reasoning pair (and, for
zcode fan-out stages, the worker agent type) to the executor; it does not
switch the active model of the session it runs in. On Codex, a stage actually
runs on the recommended model only when the user launches that stage session
with it. On ZCode, worker stages actually run on the configured custom agent
types when the Master Skill dispatches Domain workers to them (see the
Orchestration section of `skills/evm-audit-master/SKILL.md`); the main
agent's own model remains whatever the user selected for the session.

The machine-readable contract is the
[model profile schema](../schemas/codex-model-profile.schema.json); the
profile validation and default values live in
[`scripts/codex_model_profile.py`](../scripts/codex_model_profile.py).
