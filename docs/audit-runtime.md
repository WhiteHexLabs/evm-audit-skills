# Audit Runtime

The runtime flow is:

```text
source → Project Analysis (`RECON`/`ROUTING`) → Environment Gate → Domain Gate → Check Gate
       → Context Analysis (`DOMAIN_RESOLUTION`/`DOMAIN_CONTEXT`) → Initial Review (`SCREEN`)
       → review snapshot → candidate-only Deep Audit (`DEEP_REVIEW`)
       → Vulnerability Validation (`PROOF`) → review-state digest
       → independently derived state → confirmed-only synthesis
       → severity → runnable PoC gate for High/Critical → Final Report (`REPORT`)
```

Standalone runs use an external run directory and run Project Analysis once.
Orchestrated Domain agents consume the shared context, immutable manifest,
Initial Review results, and rendered runtime file without rerunning routing.

### Parallel orchestration (main agent + Domain workers)

The middle of the pipeline fans out by Domain; the head and tail stay
central. The main agent (controller) runs Project Analysis, completes Domain
Resolution, drives `next`/`status`, merges worker shards, runs `verify-poc`,
and publishes reports. Per-Domain worker agents author their Domain's
context/screen shards and append their Domain's review ledger. Two waves with
one barrier:

```text
controller: init → next → Domain Resolution terminal
wave 1:     per-Domain workers write context + screen shards   (parallel)
barrier:    domain_shards.py merge → review snapshot derived   (controller)
wave 2:     per-Domain workers append DEEP_REVIEW/PROOF records (parallel)
controller: next → report
```

The barrier exists because deep inputs bind to one review snapshot derived
from the complete global `screen-results.json` and `domain-context.json`.
Shards bind to the `routing_snapshot_id`; a stale or foreign shard is
rejected at write time and again at merge. The merge requires exact check
coverage across shards (no missing Domain, no duplicate canonical ID),
replaces only generated templates unless `--force` is passed explicitly, and
runs under an exclusive cross-process lock. Review ledgers are per-owner
files with their own writer lock, so wave-2 workers never contend with each
other. Workers never write shared global artifacts; the controller must not
run `next`, `status`, `report`, or `verify-poc` while workers are active.
Dispatch mechanics (ZCode custom worker agent types, Codex sequential
fallback) are specified in the Master Skill's Orchestration section.

Automatic build-root discovery is bounded to the acquisition root. Use
`--acquisition-root` for a trusted source boundary or pass `--build-root`
explicitly when compilation needs a wider context; unrelated ambient parent
projects are never inferred.

Place the run directory outside the target and build roots, preferably as an
external sibling such as `../protocol-audit-run/`. Resolved equal or descendant
paths are rejected, and generated pipeline artifacts are forbidden from writing
into authoritative source/build trees.

The low-level CLIs below are runtime interfaces. The short user-facing entry
point is `scripts/audit_run.py`; its `next` command returns the next required
phase and its `report` command always re-derives the current state.

### Progress observability

The controller keeps terminal-oriented progress on `stderr` and returns
machine-readable `progress` metadata for executor/UI use on `stdout`. The
Master Skill renders a compact chat banner from that metadata after a
user-relevant stage transition; it does not parse or depend on `stderr`.

`init` additionally returns an additive `progress_history` array. It contains
the completed Project Analysis entries (`RECON` and `ROUTING`) followed by the
current `next` phase. Each entry has `stage`, display-only `state` (`COMPLETED` or `CURRENT`),
`progress`, and `recommended_execution`. `next`, `status`, and `report` keep
their existing single-stage response shape; the history is not persisted in
audit artifacts.

## Runtime profiles and artifacts

### Artifact authority

| Artifact | Authoritative? | Integrity binding | Failure behavior |
|---|---:|---|---|
| Feature Map | yes for Project Analysis (`RECON`) snapshot | source/compilation lineage | fail closed |
| Project Analysis routing manifest (`ROUTING`) | yes | `routing_snapshot_id` | invalid snapshot |
| Context Analysis artifacts (`DOMAIN_RESOLUTION`, `DOMAIN_CONTEXT`) | yes | routing/review snapshot | block downstream |
| Initial Review results (`SCREEN`) | yes | review inputs | block downstream |
| Review JSONL + commit sidecar | yes | checkpoint + committed byte-prefix hash + review snapshot/state digest | block completion |
| runtime Markdown | no, generated view | sidecar identity + body SHA-256 | regenerate |
| code-index | no, navigation hint | Project Analysis `navigation_artifacts.code_index.sha256` plus current target snapshot | disable navigation |
| severity/finding details | reporting input | review-state digest | report admission error |
| `poc-evidence` | reporting input for High/Critical only | severity-decision bytes, review/source/build lineage, source hashes, path safety | `INCOMPLETE_POC` |
| `poc-verification` | optional execution receipt | report/review/PoC identities, source manifest, runner argv, exit/output hashes | non-gating |
| Final Report + issue candidates | derived outputs | immutable report generation, `report-current.json` v3, report-bundle v3 marker, body hashes, and finding-input hashes | stale/incomplete |

The machine-readable JSON/JSONL artifacts are authoritative. Runtime Markdown
is paired with a schema-validated `.meta.json` sidecar containing
`runtime_sha256`; cache reuse hashes the exact Markdown bytes and rejects any
body, sidecar, or identity mismatch. The non-authoritative code index is still
integrity-bound: Project Analysis records its exact serialized body hash, and a changed or
unbound index is reported as unavailable without changing authoritative audit
state. Bound code-index queries validate the routing manifest, target snapshot,
Project Analysis binding, exact body hash, schema version, and index lineage before lookup;
an unbound `--index` query requires explicit development opt-in. `report-bundle.json`
is written inside an immutable
`report-generations/generation-<bundle-sha256>/` directory. The small
`report-current.json` pointer is the publication commit boundary; a failed
generation leaves the previous pointer and generation untouched. Stable
top-level report files and `report-inputs/` files are convenience copies only,
and their synchronization status is returned explicitly. The current bundle is
accepted only when its identity, body hashes, exact generation snapshots, and
deterministic synthesis match the current state. `report-current.json` v3 also
binds the generation to the exact current severity, finding-details, and
conditional PoC input bytes; a cryptographically valid historical generation
is not `CURRENT` when those authoring inputs change. Report publication is
serialized per run, and the pointer is committed only after a final state and
reporting-input identity check. A validated `poc-evidence.json` snapshot is
included only when the confirmed findings contain `High` or `Critical`
severity.

`non-authoritative != integrity-unchecked`.

### Model policy (Codex / ZCode)

The stage execution policy is stored separately from audit artifacts at
`<run-dir>/config/codex-model-profile.json`. It supports `provider: codex`
and `provider: zcode` (zcode stages additionally name a worker agent type).
Confirm it once in the Master Skill, then persist either the canonical
profile or a validated custom profile. New runs use the user-level default
for the chosen provider (`~/.codex/evm-audit-model-profile.json` or
`~/.zcode/evm-audit-model-profile.json`) when it exists:

```bash
python3 scripts/audit_run.py models --init-global --provider codex
python3 scripts/audit_run.py models --init-global --provider zcode
python3 scripts/audit_run.py init <target> --run-dir <run-dir> \
  --domain <domain> --provider zcode --accept-default-models
python3 scripts/audit_run.py init <target> --run-dir <run-dir> \
  --domain <domain> --model-profile <profile.json>
python3 scripts/audit_run.py models --run-dir <run-dir>
python3 scripts/audit_run.py models --run-dir <run-dir> --reset-defaults
```

`--reset-defaults` restores the canonical defaults of the provider the run
already uses. Profiles with older schema versions are rejected; see the
[model profile documentation](codex-model-profile.md).

`next` and `status` expose `recommended_execution` for the next phase, and
stderr gives the same compact model handoff (plus the worker agent name on
zcode fan-out stages). The controller does not switch the active model of the
session it runs in. An absent profile on an older run resolves to the
canonical default in memory and does not change audit state. The global file
is read only during `init`; the run-scoped copy wins afterward.

Project Analysis, routing, validation, hashing, and report admission remain
deterministic controller logic; the recommendation applies only to model judgment.

The profile is execution metadata only. It is excluded from routing, review,
source, compilation, registry, and report identity digests; changing it cannot
stale valid security evidence.

Runtime dependencies are locked with versions and distribution hashes in
`requirements-runtime.lock`. Install reproducibly with:

```bash
python3 -m pip install --require-hashes -r requirements-runtime.lock
```

Maintainers can regenerate the Python 3.12 universal lock (including Linux and
Windows artifacts) with:

```bash
uv pip compile requirements-runtime.in --universal --generate-hashes \
  --python-version 3.12 --no-annotate --output-file requirements-runtime.lock
```

Review the resulting lock diff before committing it.

Build and route one immutable snapshot:

```bash
python3 scripts/recon.py <target> --audit-root <target-root> --build-root <project-root> \
  --output recon/feature-map.json --code-index-out recon/code-index.json
python3 scripts/select_checks.py --feature-map recon/feature-map.json \
  --target-root <target-root> --manifest-out routing/manifest.json \
  --context-out context.json
```

Query the optional navigation hint only after binding it to the run:

```bash
python3 scripts/code_context.py --run-dir <run-dir> --function <function-id> \
  --include-callers --include-callees --depth 2 --max-nodes 25 --max-edges 200
```

`MISSING`, `TAMPERED`, and `UNAVAILABLE` disable navigation; they do not
invalidate authoritative audit state. `edge_count` and `unique_edge_count` are
the deterministic number of unique available graph edges before the cap;
`returned_edge_count` counts unique edges admitted by the cap and
`serialized_edge_count` is the same hard-bounded entry count. Query v5 returns
one `selected_edges` array plus `expansion.callers`/`expansion.callees`, so a
selected edge is not copied into separate caller and callee arrays.
`edges_truncated` exposes omitted unique edges. Capped edges are returned in
deterministic priority order: unresolved, selected, then boundary edges.

Render the runtime views from the immutable manifest:

```bash
python3 scripts/render_runtime.py --manifest routing/manifest.json --profile screen \
  --output runtime/screen.md \
  --domain-resolution-out reviews/domain-resolution.json
python3 scripts/render_runtime.py --manifest routing/manifest.json --profile screen \
  --domain-resolution reviews/domain-resolution.json \
  --domain-context-out reviews/domain-context.json --output runtime/screen.md
python3 scripts/render_runtime.py --manifest routing/manifest.json --profile screen \
  --domain-resolution reviews/domain-resolution.json \
  --domain-context reviews/domain-context.json \
  --screen-results-out reviews/screen-results.json --output runtime/screen.md
python3 scripts/render_runtime.py --manifest routing/manifest.json --profile deep \
  --domain-resolution reviews/domain-resolution.json \
  --domain-context reviews/domain-context.json \
  --screen-results reviews/screen-results.json --output runtime/deep.md
```

The `screen` runtime profile for Initial Review carries only ID, title, and a
compact screen gate (or trigger fallback). It may classify a check only as
`NOT_APPLICABLE_CONFIRMED` or `CANDIDATE`; only `CANDIDATE` cards reach the
`deep` profile. Resolve every Deferred Domain, then resolve the required
snapshot-bound Domain Context and rerun Initial Review with both artifacts.
`NOT_APPLICABLE_CONFIRMED` requires `scope_complete: true`, scope evidence, and
evidence for the relevant exclusion dimension; uncertainty remains `CANDIDATE`.
`LIKELY_SAFE` is not a valid state.

For required Domain Context, `NOT_APPLICABLE` is also trusted absence: it needs
`scope_complete: true` and evidence allowed by the owning Domain's
`trusted_absence_policy`. A manual explanation alone is never enough; use
`UNKNOWN` until non-applicability is proven.

Each candidate canonical ID receives one owner-Domain JSONL event stream. Its
checkpoint and every event bind the deterministic `review_snapshot_id`, derived
from the routing snapshot plus current Domain resolution, Domain Context, and
Initial Review results. Changing any of those artifacts makes prior events stale; start
a new review epoch instead of rewriting history.
Events include snapshot/hash identity, a contiguous revision, typed evidence,
and one of `NOT_APPLICABLE`, `REVIEWED_SAFE`, `SUSPICIOUS`, or `CONFIRMED`.
Payload fields are status-specific: safe/non-applicable records stay compact,
while `CONFIRMED` retains applicability, path, preconditions, exploitability,
impact, and proof.
`SUSPICIOUS` may be resolved only by a later Vulnerability Validation (`PROOF`)
event; the latest valid
event is the derived state and earlier events remain visible in the Markdown
view.

`proof` runtime views contain only current `SUSPICIOUS` IDs and are written as
`runtime/proof-<owner-domain>.md`; full machine identity is kept in the adjacent
`.meta.json` sidecar.

`scripts/benchmark_routing.py` reports UTF-8 byte sizes for Initial Review, Deep Audit, Vulnerability Validation,
and representative safe/confirmed records; it uses no external tokenizer.

`--append-record` accepts a current review payload with `record_type: "review"`
and the version required by `schemas/review-record.schema.json`; the append command assigns the next revision and the
current `review_snapshot_id` when it
is omitted. `CONFIRMED` requires Vulnerability Validation (`PROOF`) and strong proof evidence. Missing,
stale, or older record shapes are rejected.

Append and render a ledger view with:

```bash
python3 scripts/review_ledger.py --manifest routing/manifest.json \
  --screen-results reviews/screen-results.json \
  --domain-context reviews/domain-context.json \
  --ledger reviews/review-<owner-domain>.jsonl --append-record review.json
python3 scripts/review_ledger.py --manifest routing/manifest.json \
  --screen-results reviews/screen-results.json \
  --domain-context reviews/domain-context.json \
  --ledger reviews/review-<owner-domain>.jsonl --render-markdown reviews/review.md
```

Runtime Markdown is a generated model-facing view with only compact phase and
candidate metadata. Full routing/source/compilation/candidate-set identity is
kept in the adjacent `.meta.json` sidecar together with a SHA-256 hash of the
exact UTF-8 body; the controller verifies both the identity and body before
reusing a cached view. Filtered IDs remain in the
manifest and do not generate per-check Markdown records. Completion comes from
`validate_audit_run.py` rather than an upstream completion flag.

Per-Domain shards for orchestrated parallel audits are written and merged
with `scripts/domain_shards.py` (see Parallel orchestration above):

```bash
python3 scripts/domain_shards.py write-context-shard --run-dir <run-dir> \
  --domain <owner-domain> --input context.json
python3 scripts/domain_shards.py write-screen-shard --run-dir <run-dir> \
  --domain <owner-domain> --input screen.json
python3 scripts/domain_shards.py status --run-dir <run-dir>
python3 scripts/domain_shards.py merge --run-dir <run-dir>
```

Shards live at `reviews/shards/{screen,context}-<owner-domain>.json`, are
schema-validated against `schemas/{screen-shard,domain-context-shard}.schema.json`,
and bind to the routing snapshot. The merge writes the authoritative global
`reviews/screen-results.json` and `reviews/domain-context.json` only after
full coverage and snapshot validation succeed.

The controller equivalent is:

```bash
python3 scripts/audit_run.py init <target> --run-dir <run-dir> --domain <domain>
python3 scripts/audit_run.py next --run-dir <run-dir>
python3 scripts/audit_run.py status --run-dir <run-dir>
python3 scripts/audit_run.py report --run-dir <run-dir>
python3 scripts/audit_run.py verify-poc --run-dir <run-dir>
```

The explicit `--severity-decisions`, `--finding-details`, and
`--poc-evidence` options are advanced overrides. The controller discovers the
current reporting inputs from the run directory; do not add `--poc-evidence`
when all confirmed findings are below High.

`next` returns Deep Audit (`DEEP_REVIEW`) for missing candidate records and
Vulnerability Validation (`PROOF`) for latest `SUSPICIOUS` records. `report`
always runs `status_run()` first,
validates and synthesizes in memory, then commits a complete immutable
generation through `report-current.json`. A failed report leaves the previous
current generation untouched and exits non-zero if current reporting is
incomplete. `status` reports a historical generation as stale when current
reporting inputs differ or a newly-required High/Critical PoC is pending. It
never trusts a previous `audit-state.json`. `verify-poc` is explicit and
non-gating; supported Foundry/Hardhat commands use structured argv and
`shell=False`, copy the build tree and its dependencies without external
symlinks, stage the exact validated PoC source bytes, and bind execution to the
staged entrypoint. The child receives a minimal environment with disposable
home/cache/temp paths, no parent credentials, offline hints, and FFI disabled;
OS-level network sandboxing is not provided. Volatile `out/`/`cache/`/`artifacts/`
output stays outside the audited tree, and receipts record hashes rather than
raw command output.

`Proof != PoC`: Vulnerability Validation establishes that a finding is real and
may be a trace, invariant violation, calculation, or test. A runnable PoC is a reporting gate
after severity is assigned: `Info`, `Low`, and `Medium` findings report without
one; `High` and `Critical` findings require a completed, lineage-bound
`poc-evidence` artifact. The controller records the reproduction command but
does not execute arbitrary commands during `status` or ordinary reporting.

When severity is current, controller output exposes the policy projection and,
when validation is incomplete, stable per-ID `poc_errors` reason codes:

```json
{
  "poc_policy": {
    "minimum_severity": "High",
    "required_count": 1,
    "skipped_below_high_count": 2,
    "required_ids": ["EVM-..."],
    "poc_errors": [{"canonical_id": "EVM-...", "code": "POC_SOURCE_MISSING"}]
  }
}
```

The returned `report` and `issue_candidates` paths point into the committed
generation. Use `report_generation.report`, `.issue_candidates`, `.bundle`, and
`.current_pointer` from controller output/status as authoritative paths; stable
top-level files are convenience copies. Older runs with top-level outputs but no
pointer are uncommitted. Rerun the explicit `report` command to rederive state
and republish them; old bodies are never migrated blindly.

Inspect or recover report history with:

```bash
python3 scripts/audit_run.py reports --run-dir <run-dir> --list
python3 scripts/audit_run.py reports --run-dir <run-dir> --gc --dry-run
python3 scripts/audit_run.py reports --run-dir <run-dir> --gc --apply
```

Cleanup protects the current generation, ignores unknown directories, and only
removes stale staging directories or verified orphan generations. If the
current report pointer cannot be validated (unreadable pointer, or its
generation directory is missing or corrupt), report GC fails closed and
removes nothing; use `--list` to inspect the run before repairing it. A
generation does not yet contain a hashed `audit-state.json` snapshot; its
historical state is reconstructed from the immutable run inputs and ledger.

The low-level `synthesize_report.py --audit-state` argument is an optional
derived cache for compatibility; synthesis re-derives the current state from
the authoritative inputs and uses that same state for any report bundle.
When `--poc-evidence` is supplied, pass `--run-dir <run-dir>` explicitly; the
low-level CLI never infers the audit run from the PoC metadata file location.

Derive completion independently from the manifest, Initial Review results,
Context Analysis artifacts, and owner-Domain ledgers:

```bash
python3 scripts/validate_audit_run.py --manifest routing/manifest.json \
  --context context.json \
  --screen-results reviews/screen-results.json \
  --domain-resolution reviews/domain-resolution.json \
  --domain-context reviews/domain-context.json \
  --ledger reviews/review-<owner-domain>.jsonl \
  --output audit-state.json
```

Only `CONFIRMED` records may become findings. `NOT_APPLICABLE`, `REVIEWED_SAFE`,
and `SUSPICIOUS` records never appear as findings in `AUDIT-REPORT.md`. The
machine state is `COMPLETE_CLEAN`, `COMPLETE_WITH_FINDINGS`, or an explicit
`INCOMPLETE_*` state; incomplete artifacts cannot claim a clean audit. Synthesis
also requires current ledger IDs to equal `coverage.deep_reviewed`, and a
complete state requires every Deep Audit candidate to have a current ledger record.

## Confirmed finding format

Confirmed findings use this format:

```md
## [X-N] Title
**Status**: CONFIRMED
**Checklist reference**: `<canonical-id>`
**Provenance references**: `<source IDs from canonical registry>`
**Severity**: Critical / High / Medium / Low / Info
**Category**: [skill name]
**Location**: `functionName()` or file:line
**Applicability**: APPLICABLE — why the checklist item applies
**Code path**: Exact reachable path
**Preconditions**: Concrete conditions
**Exploitability**: How the conditions are satisfied
**Impact**: Concrete consequence
**Strong proof evidence**: Trace, calculation, test, or deterministic invariant violation
**Description**: What the issue is and why it matters.
**Recommendation**: Concrete fix with code snippet.
```

For a complete finding report, provide two snapshot-bound artifacts. Severity
decisions have `schema_version: 2`, the four artifact identity fields, a current
`review_state_digest`, and a
`decisions` object keyed by canonical ID. Each decision requires `severity`,
`rationale`, and `dimensions` with `impact`, `exploitability`, `privileges`,
`capital_required`, `repeatability`, `user_interaction`, `loss_bound`,
`protocol_exposure`, and `recoverability`. Valid severities are exactly
`Info`, `Low`, `Medium`, `High`, and `Critical`; the old flat map and
`Informational` are invalid.

`finding-details.json` has the same identity fields and `review_state_digest`,
plus a `findings` array. `audit-state.json`, `issue-candidates.json`, and final
report metadata also carry the current review snapshot/state identity.
Each confirmed ID must occur exactly once with non-empty `location`,
`description`, and `recommendation`. Category is derived from `owner_domain`.
Missing severity or details is a report admission error (`INCOMPLETE_SEVERITY`
or `INCOMPLETE_REPORTING`), not a new audit-state status.

The controller stores the exact validated UTF-8 reporting inputs in the
committed generation as `severity-decisions.json` and `finding-details.json`.
The report-bundle v3 marker hashes those snapshots and adds
`poc_evidence_sha256`. Clean reports set all three reporting-input hashes to
`null`. A report with only sub-High findings hashes severity and finding details
but leaves `poc_evidence_sha256` as `null`. A High/Critical report stores the
exact validated PoC bytes in the immutable generation and copies each
referenced source into `poc-sources/<sha256>.<extension>`. Historical
generation checks use those snapshots and do not require live PoC source files.
Previous generations
remain available for reproducibility; operators may remove unreferenced
generations only under an explicit retention policy after preserving any
required audit evidence.

For a completed PoC, `poc-evidence.json` contains only the exact current
High/Critical projection. Each entry records its runner, non-empty reproduction
command, entrypoint, expected result, result summary, durable source path, and
SHA-256. Final PoC sources must be stored under `<run-dir>/poc/` and resolve
inside that directory; absolute, traversal, target/build-only, and symlink
escape paths, missing files, changed bytes, stale severity bytes, and
`TEMPLATE` artifacts are rejected.

Severity is assigned only after confirmation using the dimensions and mapping
in [`severity-scoring.md`](../skills/evm-audit-master/references/severity-scoring.md).
Checklist type and confidence never determine severity. The full review
contract is in [`check-review-contract.md`](../skills/evm-audit-master/references/check-review-contract.md);
the compact runtime contract is in
[`check-review-contract.runtime.md`](../skills/evm-audit-master/references/check-review-contract.runtime.md).
