# Runtime Per-Check Review Contract

Review only IDs promoted from Screen to Deep in the immutable routing-v7 manifest.
Filtered and Deferred IDs remain manifest-visible. Each deep-review record is
append-only JSONL at `reviews/review-<owner-domain>.jsonl`; Markdown is a generated view.

Global review contract: verify every reachable path before `REVIEWED_SAFE`.
Use `CONFIRMED` only with reachable preconditions, concrete impact, and strong
deterministic proof such as a trace, invariant violation, calculation, or test.
A runnable exploit PoC is a separate post-confirmation reporting requirement
for final-severity `High` and `Critical` findings only.

## Executors

This contract is executor-agnostic: it binds equally to a single sequential
agent and to per-Domain worker agents running in parallel. A worker writes
only its own Domain's shard (`reviews/shards/<kind>-<domain>.json`, via
`scripts/domain_shards.py`) and its own ledger
(`reviews/review-<owner-domain>.jsonl`). Shared global artifacts —
`screen-results.json`, `domain-context.json`, `audit-state.json`, report
outputs — are written exclusively by the controller (merge barrier, `next`,
`status`, `report`, `verify-poc`), never by a worker. Parallel execution
never weakens the gates below: every record still validates against the same
snapshot binding, revision, lifecycle, and evidence rules.

## Terminal statuses

- `NOT_APPLICABLE`: concrete scope/code evidence proves the selected check cannot apply.
- `REVIEWED_SAFE`: every relevant reachable path preserves the required guard or invariant.
- `SUSPICIOUS`: a plausible concern remains but reachability, preconditions, exploitability, impact, or proof is unresolved. Never assign severity.
- `CONFIRMED`: the defect has a reachable path, satisfiable preconditions, concrete exploitability and impact, plus strong deterministic proof such as a trace, invariant violation, calculation, or test. A runnable PoC is not required merely to mark the record `CONFIRMED`.

Use exactly one terminal status. `LIKELY_SAFE` is not a status. Pattern similarity, an unavailable test, or one
safe path cannot establish `REVIEWED_SAFE` or `CONFIRMED`.

## Record

The authoritative JSON object includes `routing_snapshot_id`,
`registry_sha256`, `source_digest`, `compilation_input_digest`, `owner_domain`,
`check_body_hash`, `revision`, `review_stage`, `status`, and typed `evidence`
entries (`kind`, `location`, `reason`). Records must validate against the current
`<suite-root>/schemas/review-record.schema.json`; status-specific fields are
required by status, so safe and non-applicable records stay compact. A follow-up
revision may resolve only a prior `SUSPICIOUS` event and must use `PROOF`.
`CONFIRMED` records require `PROOF` stage and strong test, trace, invariant, or
calculation evidence.

## PoC source retention

Solidity test/POC source used during Deep Review or `PROOF`, including supporting
helpers and mocks, is user-owned audit evidence and remains a deliverable.

- Archive the exact PoC source and any helpers or mocks under `<run-dir>/poc/`
  before running the proof. Do not add new PoC files to the audited target
  after routing.
- If a useful test already existed in the target before Recon, copy its exact
  source into `<run-dir>/poc/` for the final PoC artifact.
- Record the durable path in `proof` or an `evidence.location` entry.
- After proof succeeds, and after final-report generation or regeneration, do
  not delete or overwrite the source. Cleanup may remove only generated views
  and disposable build/cache artifacts that do not contain POC source.
- A successful report generation copies each explicitly referenced source byte
  into `report-generations/generation-<bundle-sha256>/poc-sources/` as
  `<sha256>.<extension>`. Historical generation validation uses this snapshot,
  not the mutable run-dir source.
- Recorded commands are never executed implicitly. Use the explicit
  `audit_run.py verify-poc --run-dir <run-dir>` command for supported runners;
  its optional `poc-verification` receipt is additional assurance, not a report
  admission gate.

```markdown
### <canonical-id> — <title>
- **Review stage**: DEEP_REVIEW | PROOF
- **Routing basis**: matched features and environment evidence
- **Status**: NOT_APPLICABLE | REVIEWED_SAFE | SUSPICIOUS | CONFIRMED
- **Applicability**: APPLICABLE — ... | NOT_APPLICABLE — ...
- **Code path**: entry point → affected operation
- **Preconditions**: caller, state, timing, balances, roles, and deployment facts
- **Exploitability**: concrete actor actions, or the guard that blocks them
- **Impact**: concrete consequence, or N/A with the preserved invariant
- **Strong proof evidence**: named runnable proof, deterministic invariant, calculation, trace, or UNRESOLVED
- **Evidence**: file:line, test, trace, calculation, or scope inventory
```

For `NOT_APPLICABLE`, set complete scope evidence and cite the relevant exclusion
dimension allowed by the effective owning Domain's `trusted_absence_policy`;
irrelevant evidence kinds are not required. Do not emit unresolved field markers.
For `REVIEWED_SAFE`, cover alternate, inherited, proxy, callback, and
delegatecall paths where relevant. For `SUSPICIOUS`, identify the missing proof
step. Only `CONFIRMED` records enter synthesis or receive severity.

Reject synthesis when any selected Deep ID is missing, malformed, non-terminal,
or has an invalid revision history. Deferred Domains require
`INCOMPLETE_DOMAIN_ROUTING`; unknown required context requires
`INCOMPLETE_CONTEXT`; suspicious records require `INCOMPLETE_REVIEW`. Only
`COMPLETE_CLEAN` is clean, and final findings contain only `CONFIRMED` records.
