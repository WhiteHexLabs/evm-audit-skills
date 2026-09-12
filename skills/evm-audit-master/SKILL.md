---
name: evm-audit-master
description: Master entry point for EVM smart-contract audits. Route once, enforce evidence-bound review, and synthesize only confirmed findings.
---
# EVM Smart Contract Security Audit — Master

Load this Skill first. Resolve `<suite-root>` as the nearest ancestor containing
`data/`, `domains/`, and `scripts/`; the Skill itself is under
`<suite-root>/skills/`.

## Invariants

- `<suite-root>/data/canonical-checks.json` is the only checklist knowledge source. Generated Markdown is a view; do not load the full registry into model context.
- Run Project Analysis (`RECON`, `ROUTING`) once. Preserve `routing_snapshot_id`, `registry_sha256`, `source_digest`, and `compilation_input_digest` across every artifact.
- Project Analysis may emit `recon/code-index.json` as a navigation hint; inspect it first, load only targeted source ranges, and expand callers/callees whenever reachability is uncertain. Source remains authoritative.
- Query only through the run-bound command (`code_context.py --run-dir <run-dir>`); use `--depth 2 --max-nodes 25 --max-edges 200` when a second hop is needed. Treat node/edge truncation and unresolved edges as reasons to verify more source, never as proof of safety.
- `UNKNOWN` is never absence. Only trusted absence or confirmed environment mismatch may filter; Initial Review (`SCREEN`) may emit only `NOT_APPLICABLE_CONFIRMED` or `CANDIDATE`.
- Deep Audit (`DEEP_REVIEW`) consumes only Initial Review candidates. Every candidate needs one owner-Domain append-only JSONL event stream with valid revisions, typed evidence, and a terminal status.
- `SUSPICIOUS` has no severity and must go through a later Vulnerability Validation (`PROOF`) event. Only `CONFIRMED` records enter the Final Report.
- `CONFIRMED` requires strong proof of reachability, satisfiable preconditions, exploitability, and impact. A runnable PoC is a separate reporting requirement: only confirmed `High` and `Critical` findings require one; confirmed `Info`, `Low`, and `Medium` findings remain reportable without it.
- Solidity POC source is user-owned evidence: archive audit-created or modified tests, helpers, and mocks under `<run-dir>/poc/` before proof, record the durable path in `proof` or `evidence.location`, and never delete or overwrite them after `PROOF` or report generation. Do not add new PoC files to the audited target after routing.
- Keep `<run-dir>` as an external sibling of both the audit and build roots. The controller rejects equal or descendant paths, and pipeline outputs cannot overwrite authoritative source/build inputs.

## Repository Trust Gate

Before opening an original target to an agent or analyzer, inspect its source
trust and `.git` entry with filesystem-only operations. `UNKNOWN` trust counts
as untrusted. When `.git` exists as a directory, file, symlink, or unexpected
object, use a verified `.git`-free snapshot outside the original; do not run
Git, Slither, build/test/package-manager, or target-controlled commands against
the blocked original. Use `scripts/repository_preflight.py` for manual
preflight and sanitization. This boundary is not a lifecycle phase.

```text
Repository Trust Gate
        ↓
Project Analysis
→ Context Analysis
→ Initial Review
→ Deep Audit
→ Vulnerability Validation
→ Final Report
```

## Audit lifecycle

```text
Project Analysis
  ├─ Recon
  └─ Routing
        ↓
Context Analysis
  ├─ Domain Resolution
  └─ Domain Context
        ↓
Initial Review
        ↓
Deep Audit
        ↓
Vulnerability Validation
        ↓
Final Report
```

Names such as `RECON`, `SCREEN`, and `PROOF` are stable internal identifiers
used by configuration, persisted artifacts, and runtime control flow. The
public phase names above are presentation labels; they do not rename or
migrate those internal IDs.

## Controller

```bash
python3 <suite-root>/scripts/audit_run.py init <target> --run-dir <run-dir> --domain <domain>
python3 <suite-root>/scripts/audit_run.py next --run-dir <run-dir>
python3 <suite-root>/scripts/audit_run.py status --run-dir <run-dir>
python3 <suite-root>/scripts/audit_run.py report --run-dir <run-dir>
python3 <suite-root>/scripts/audit_run.py verify-poc --run-dir <run-dir>
```

The controller emits compact progress to stderr by default. Use `--verbose` to
forward child diagnostics or `--quiet` to suppress normal progress; the flags
are available on `init`, `next`, `status`, and `report`, and are mutually exclusive.

Repeat `next` until it returns a template or Final Report (`REPORT`). Resolve
only generated evidence-bound templates. Deep Audit (`DEEP_REVIEW`) means
candidate records are missing; Vulnerability Validation (`PROOF`) means the
latest record is `SUSPICIOUS` and the controller exposes a suspicious-only
`runtime/proof-<owner-domain>.md` view. `report` re-derives state from
current artifacts and refuses stale, incomplete, or under-specified reporting
inputs. The `--poc-evidence` input is required only when current severity
decisions contain a confirmed `High` or `Critical` finding. The controller
validates its lineage, exact required-ID projection, source paths, and source
hashes; it discovers the current reporting inputs from the run directory and
never runs the recorded command automatically. The explicit
`--severity-decisions`, `--finding-details`, and `--poc-evidence` flags are
advanced overrides; do not add `--poc-evidence` for an all-`Info`/`Low`/`Medium`
report. A historical generation is `CURRENT` only while its exact reporting
inputs still match the current run-directory artifacts.

`verify-poc` is the only command that executes recorded Foundry or Hardhat
commands. It uses a controlled build workspace, structured argv, and
`shell=False`, and writes a non-gating v2 `poc-verification` receipt containing
the trusted executable identity, normalized argv, staged source hashes,
workspace/environment policy versions, and output hashes. Dependencies are
copied into the disposable workspace; external symlinks and package-installing
runner forms are rejected, and the child receives no parent credentials.
`status`, `next`, and `report` never execute PoC commands.

For `report` and `status` results, consume the paths under
`report_generation` (and the report result's `report`, `issue_candidates`, and
`report_bundle_path`) as authoritative. Top-level `AUDIT-REPORT.md`,
`issue-candidates.json`, and `report-bundle.json` are convenience copies only;
their synchronization status is explicit and a failed copy must not change the
authoritative generation.

## Codex-visible phase progress

Controller stderr is terminal-oriented and may be collapsed by agent UIs
(Codex, ZCode). After `init`, `next`, `status`, or `report` returns a
user-relevant phase, render compact chat banners from its `progress` and
`recommended_execution` fields before continuing model-owned work. For `init`,
render exactly one banner for each entry in `progress_history`, in order; the
first entries are completed stages and the final entry is the current `next`
stage. Do not render `next` a second time. For the other commands, render one
banner from the returned stage fields.

```text
+----------------------------------------------+
|         EVM AUDIT :: <PHASE NAME>             |
+----------------------------------------------+
  Phase: <step>/<total>
  <summary>
  Model: <model>
  Reasoning: <reasoning_effort>     (codex)
  Thought level: <thought_level>    (zcode)
  Worker agent: <agent>             (zcode fan-out stages only)
```

Use only controller-provided phase and counts; never infer them from stderr.
Keep UI-only last-phase state to avoid repeating a banner when no phase
transition occurred, and never persist that state into audit artifacts. Do not
show these banners for internal helper calls such as `recon.py`,
`select_checks.py`, `render_runtime.py`, or `validate_audit_run.py`. The model
recommendation is a handoff, not an automatic active-model switch.

## Model profile policy

The stage-model profile supports two providers: `codex` (Codex CLI stages)
and `zcode` (ZCode main agent plus custom worker agent types). Ask once
before starting a new audit with no confirmed profile.

Codex default (`--provider codex`):

```text
EVM AUDIT :: MODEL PROFILE (codex)
Project Analysis: gpt-5.6-luna max
Context Analysis: gpt-5.6-terra medium
Initial Review: gpt-5.6-terra high
Deep Audit: gpt-5.6-sol high
Vulnerability Validation: gpt-5.6-sol max
Final Report: gpt-5.6-terra medium

Use this default profile?
1. Use defaults
2. Customize
```

ZCode default (`--provider zcode`): controller stages (Project Analysis,
Domain Resolution, Final Report) run on the main agent (`GLM-5.3`, agent
`null`, handoff recommendations only); Domain Context runs on
`evm-audit-worker-flash` (GLM-5.3-Flash, thought level unpinned/default);
Initial Review and Deep Audit run on `evm-audit-worker-deep` (GLM-5.3,
`thoughtLevel: high`); Vulnerability Validation runs on
`evm-audit-worker-proof` (GLM-5.3, `thoughtLevel: max`). Initial Review
deliberately uses the flagship model: `NOT_APPLICABLE_CONFIRMED` is a
trusted-absence decision. Each worker agent type pins exactly one
model/thought-level contract; a worker invocation never crosses a stage
boundary into a different contract.

The user-level default lives at `~/.codex/evm-audit-model-profile.json` or
`~/.zcode/evm-audit-model-profile.json` (one per provider);
`python3 <suite-root>/scripts/audit_run.py models --init-global --provider <codex|zcode>`
creates it once with canonical defaults. If it exists, display that validated
profile in the prompt instead of the built-in table. On confirmation the
controller snapshots the selected values into the run (`init --provider ...`,
or `--accept-default-models`, or a validated file via `--model-profile`).
Persist the resolved choice in `<run-dir>/config/codex-model-profile.json`;
once present, do not ask again. For customization, show the full current
profile once and accept only changed lines such as `SCREEN = gpt-5.6-sol/high`
(codex) or `SCREEN = GLM-5.3/high/evm-audit-worker-deep` (zcode), preserving
omitted internal stages. A zcode stage entry must match the full execution
contract of its `agent` — model and thought level as pinned in the shipped
worker template, and a stage the agent is allowed to execute; the validator
rejects any mismatch. GLM-5.3 thought levels are `low`, `high`, and `max`;
GLM-5.3-Flash uses `default` (no verified explicit level).

At each transition, follow `recommended_execution`. This is a handoff only:
the controller never switches its own active model. On Codex the stage model
changes only when the user relaunches the stage session with a different
model; on ZCode the worker stages run on the configured custom agent types
dispatched by the Orchestration section below. Do not claim any other switch
mechanism. The profile is execution metadata and never security lineage or
artifact identity.

## Orchestration (main agent + Domain workers)

The pipeline is fan-out/fan-in: the main agent (controller) owns Project
Analysis, Domain Resolution, the stage merge barriers, report publication,
and every `next`/`status`/`verify-poc` call. Per-Domain worker agents own
exactly one stage of work per invocation. Controller discipline: never run
`next`, `status`, `report`, `verify-poc`, or a merge while workers are
active, and never dispatch a worker for a later stage before the current
stage is terminal.

Execution modes:

- **ZCode with worker agent types** (parallel): requires the custom agent
  types `evm-audit-worker-flash`, `evm-audit-worker-deep`, and
  `evm-audit-worker-proof` in the Agent tool's available types. If any is
  missing, stop and fail closed with:

  ```text
  Required ZCode worker agents are not registered.
  Run `<suite-root>/install.sh zcode`, then start a new ZCode session.
  Do not continue this audit with a fallback/wrong agent type.
  ```

  Never copy agent files into `~/.zcode/agents/` during an audit;
  installation is `install.sh`'s job, and a new session is required for the
  definitions to register. Dispatch one worker per Domain that has work in
  the current stage, with the agent type named by the stage profile
  (`recommended_execution.agent`), as parallel background agents; act on
  completion notifications, do not poll.
- **Codex or runtimes without sub-agent dispatch** (sequential): the main
  agent executes the same stage-aligned workflow inline, stage by stage,
  Domain by Domain. Do not fabricate parallel dispatch where the runtime
  provides no mechanism.

The controller `next` call is the only stage transition: it alone advances
the run state, renders the per-owner runtime views, and names the worker
agent for the next wave through `recommended_execution`. A successful merge
publishes stage artifacts but never advances the stage — never infer the
next wave from a successful merge alone. Before every worker dispatch, fail
closed unless all of these hold: the returned stage equals the expected
stage; `recommended_execution.agent` is non-null and equals the shipped
contract for that stage. If any check fails, stop instead of dispatching a
guessed or fallback agent.

Waves (a worker invocation never crosses a stage boundary — each agent type
pins one model/thought-level contract):

1. **Controller head.** `init` (Project Analysis), then `next` until Domain
   Resolution is terminal and `next` returns `DOMAIN_CONTEXT`.
2. **Wave A — DOMAIN_CONTEXT** (`evm-audit-worker-flash`, one per Domain
   required for context). Each worker authors a context input
   `{"context": {...}}` covering exactly its Domain's required context keys
   (every entry `KNOWN` or `NOT_APPLICABLE`, never left `UNKNOWN`) and
   writes it with
   `python3 <suite-root>/scripts/domain_shards.py write-context-shard --run-dir <run-dir> --domain <domain> --input <file>`.
   Quiesce all workers before any controller operation.
3. **Barrier A (controller only).** `domain_shards.py merge-context --run-dir <run-dir>`
   writes the authoritative `reviews/domain-context.json` (`status` reports
   `context_merge_ready`; a present-but-invalid shard is never ready). Then
   run `next` and require stage `SCREEN` with
   `recommended_execution.agent == evm-audit-worker-deep`. Screen may start
   only after both succeed.
4. **Wave B — SCREEN** (`evm-audit-worker-deep`, one per shard-owner
   Domain). Each worker authors a screen input `{"results": [...]}` covering
   exactly its Domain's selected checks (`CANDIDATE` or
   `NOT_APPLICABLE_CONFIRMED` with trusted-absence evidence) and writes it
   with `write-screen-shard` (same CLI shape). Quiesce all workers.
5. **Barrier B (controller only).** `domain_shards.py merge-screen --run-dir <run-dir>`
   requires the authoritative context, writes `reviews/screen-results.json`,
   and derives the review snapshot (`merge-context` followed by
   `merge-screen` equals the combined `merge` convenience command). Then run
   `next`:
   - `REPORT` → zero candidates: skip Deep Review and Proof, go to
     reporting.
   - `DEEP_REVIEW` → require `recommended_execution.agent ==
     evm-audit-worker-deep` and that `runtime/deep-<owner-domain>.md` exists
     for every owner Domain of the returned `pending` candidates.
6. **Wave C — DEEP_REVIEW** (`evm-audit-worker-deep`): dispatch only the
   owner Domains of the pending candidates returned by `next`, not
   unconditionally one worker per Domain. Each worker appends only
   `DEEP_REVIEW` records to its own ledger
   `<run-dir>/reviews/review-<domain>.jsonl` via
   `python3 <suite-root>/scripts/review_ledger.py --manifest <run-dir>/routing/manifest.json --screen-results <run-dir>/reviews/screen-results.json --domain-context <run-dir>/reviews/domain-context.json --ledger <run-dir>/reviews/review-<domain>.jsonl --append-record <record.json>`
   (add `--domain-resolution <run-dir>/reviews/domain-resolution.json` when
   Deferred Domains exist). Append-only, one record at a time; the ledger
   validates revisions, lifecycle transitions, and snapshot binding. Quiesce
   all workers, then run `next`:
   - `REPORT` → no `SUSPICIOUS` records: skip Proof, go to reporting.
   - `PROOF` → require `recommended_execution.agent ==
     evm-audit-worker-proof` and that the returned `runtime_views`
     (`runtime/proof-<owner-domain>.md`) cover exactly the owner Domains of
     the returned `pending` suspicious IDs.
7. **Wave D — PROOF** (`evm-audit-worker-proof`): dispatch only the owner
   Domains represented by the current proof views / pending suspicious IDs.
   Same ledger CLI as wave C, but appending only `PROOF` records that
   resolve prior SUSPICIOUS records against the current review snapshot.
   Quiesce all workers, then run `next` and require `REPORT`.
8. **Controller tail.** Complete the reporting inputs, then run `report`.

Parallelism is across Domains within a stage; stage ordering stays
deterministic. Worker hard rules (enforced by the agent templates and
re-validated by the CLI): workers write only the one artifact their stage
allows (their context shard, their screen shard, or their own ledger), never
edit global run files, never rerun Recon/Routing/Selector, never turn
`UNKNOWN` into trusted absence, and never assign severity to `SUSPICIOUS`.

## Model decisions

The model may choose the audit scope, provide evidence-backed environment and
Domain resolutions, complete required context, classify Initial Review cards,
write Deep Audit/Vulnerability Validation records, and assign structured
severity plus reporting details after confirmation. Per-Domain work follows
the Orchestration section: parallel dispatch only where the active runtime
actually supports it; otherwise sequential execution of the same workflow.

The model must not treat pattern matches as findings, turn `UNKNOWN` into
absence, rerun routing in a Domain Skill, assign severity to `SUSPICIOUS`, or
emit a Final Report from missing/malformed coverage. Do not proactively build
Foundry or Hardhat exploit tests for `Info`, `Low`, or `Medium` findings after
strong proof is otherwise sufficient. Build the smallest deterministic
runnable PoC after severity for `High` and `Critical`; if a reproduction is
needed to establish correctness, keep the finding `SUSPICIOUS` until it is
available. Filing GitHub issues is separate and requires explicit scope; only
confirmed Medium+ findings qualify.

Apply the compact review contract at
`<suite-root>/skills/evm-audit-master/references/check-review-contract.runtime.md`.
Use [`docs/audit-runtime.md`](../../docs/audit-runtime.md) for low-level CLI,
artifact schema, and report-format details.
