# Per-Check Review Contract

This contract defines the audit-run review ledger. The canonical JSON registry is
the knowledge source; generated domain checklists are human-readable runtime
views. Statuses belong only to the run-specific ledger under
`audits/<repo>-<date>/`.

## Review Pipeline

Every selected checklist item follows this order:

```text
Checklist item
      ↓
Applicability check
      ↓
NOT_APPLICABLE or APPLICABLE
      ↓
Code path identification
      ↓
Preconditions
      ↓
Exploitability
      ↓
Impact
      ↓
PoC / invariant violation
      ↓
One terminal status
```

`APPLICABLE` is a branch in the analysis, not a fifth status. Do not skip from recognizing a pattern to confirming a finding.

## Review stages

Use a four-stage funnel for every routed canonical check:

1. **`FAST_FILTER`** — verify the scope-bound Feature Map v5, evaluate
   environment applicability, gate Domains by their surface predicate, then
   compare each candidate check with the feature map. Only a `curated` predicate
   proven `FALSE` is feature-filtered. A `FALSE` result from an `inferred`
   keyword predicate is downgraded to `UNKNOWN`; it remains selected and must
   not become `NOT_APPLICABLE`.
2. **`SCREEN`** — classify selected cards as `NOT_APPLICABLE_CONFIRMED` or
`CANDIDATE`. Uncertainty is always `CANDIDATE`; Screen never filters.
3. **`DEEP_REVIEW`** — for candidates, trace reachability, preconditions,
   guards, and invariants. Use `REVIEWED_SAFE` or `SUSPICIOUS` when proof is not
   complete.
4. **`PROOF`** — establish exploitability and impact with a
   runnable PoC, transaction trace, or deterministic invariant violation before
   using `CONFIRMED`.

The immutable routing-v8 manifest must account for every canonical ID in the considered
Domain scope as `SELECTED`, `FILTERED_ENVIRONMENT`, or `FILTERED_FEATURE` and
must separately account for Selected, Deferred, and filtered Domains. Deferred
Domains must resolve before clean completion. It
must include the feature evidence used for the decision. Filtered IDs are
machine coverage entries only; they do not receive per-check review ledger
records. Selected IDs receive one owner-Domain event stream, including shared
IDs that are listed in more than one Domain. The manifest also records the
registry/source digests, selector version, knowledge/target commits,
chain/runtime/fork/compiler context, and audit timestamp so a later review can
reproduce the routing input.

Validate a completed run with `python3 scripts/validate_audit_run.py`; it
independently derives completion from the immutable manifest, Screen results,
Domain resolution, and JSONL ledgers.

## Terminal Statuses

| Status | Meaning | Required evidence | Final report |
|---|---|---|---|
| `NOT_APPLICABLE` | The checklist item's applicability predicate is absent from the in-scope system. | Concrete scope/code evidence showing why the item cannot apply. | Never a finding. |
| `REVIEWED_SAFE` | The item applies, but all relevant paths preserve the required guard or invariant. | Relevant path coverage plus the guard, invariant, or verified false-positive condition. | Never a finding. |
| `SUSPICIOUS` | A plausible concern remains, but at least one path, precondition, exploitability, impact, or proof step is unresolved. | Exact concern, explored path, and the missing proof step. No severity. | Internal ledger only. |
| `CONFIRMED` | The security-relevant defect is reachable and proven. | Complete path, preconditions, exploitability, concrete impact, and a runnable PoC or deterministic invariant violation. | Eligible for synthesis and reporting. |

Every record must end with exactly one of these four statuses. There is no emitted `UNREVIEWED` or `IN_PROGRESS` status. A later revision may resolve a `SUSPICIOUS` record to `REVIEWED_SAFE` or `CONFIRMED` only after the missing evidence is supplied and the follow-up uses `PROOF`.

## Record Identity and Format

Use the stable `canonical_id` from the routed selected-check body or routing
manifest as the review identity; the JSON registry is machine-only validation
input. Preserve existing source identifiers, including `SAS-AV-*`,
`DROZER-*`, and `AUDITMOS-*`, only as provenance; they are not separate review
items.

Each selected skill appends events to one `review-<skill>.jsonl` ledger for its Screen
candidate IDs. The filename must
match the selected record's `owner_domain` (for example,
`review-evm-audit-erc20.jsonl`). Preserve routed order and assign contiguous
`revision` values per candidate checklist item:

The JSONL checkpoint carries `routing_snapshot_id`, `registry_sha256`,
`source_digest`, and `compilation_input_digest`; every review record also
carries the routed `check_body_hash`. Typed evidence entries use `kind`,
`location`, and `reason`.
Records must validate against the current
`<suite-root>/schemas/review-record.schema.json`. A ledger belongs to exactly one
routing snapshot; if any identity or schema value changes, start a new audit run.
Markdown ledgers are not runtime input; `review_ledger.py` renders them from
JSONL when a human view is needed.

```markdown
### <check-ref> — <title>
- **Review stage**: DEEP_REVIEW | PROOF
- **Routing basis**: matched feature IDs and reconnaissance evidence, or the concrete reason the feature is absent
- **Status**: NOT_APPLICABLE | REVIEWED_SAFE | SUSPICIOUS | CONFIRMED
- **Applicability**: APPLICABLE — ... | NOT_APPLICABLE — ...
- **Code path**: ...
- **Preconditions**: ...
- **Exploitability**: ...
- **Impact**: ...
- **PoC / Invariant violation**: ...
- **Evidence**: file:line, test name, trace, calculation, or explicit scope basis
```

New runs do not write `FAST_FILTER` records: the routing manifest is the sole
FAST_FILTER artifact. Review records use status-specific payloads: `REVIEWED_SAFE`
requires the preserved invariant, `NOT_APPLICABLE` requires complete trusted
absence evidence, `SUSPICIOUS` requires an unresolved reason, and `CONFIRMED`
requires the full proof-bound payload. Do not pad compact statuses with unresolved
placeholders.

## State-Specific Gates

### `NOT_APPLICABLE`

- Set `Applicability` to `NOT_APPLICABLE` and state the concrete absence of the relevant surface.
- Set `scope_complete` to true and cite scope evidence plus evidence for the actual exclusion dimension (source, inheritance, interface, dependency, deployment, or environment).
- “I did not find it quickly,” an unfamiliar dependency, or an inability to run a test is not enough. Use `SUSPICIOUS` when applicability is uncertain.
- When a selected item is later shown to be not applicable, record the concrete
  scope evidence. Do not emit a blanket set of deep fields merely to satisfy a
  filtered routing decision; filtered IDs belong only in the manifest.

### `REVIEWED_SAFE`

- Set `Applicability` to `APPLICABLE`.
- Identify every relevant entry-to-operation path, including inherited, proxy, delegatecall, callback, and alternate state-transition paths where applicable.
- Name the guard, invariant, or verified false-positive condition that blocks the suspected failure.
- A checklist `FP` note is a hypothesis to verify, not automatic proof of safety.

### `SUSPICIOUS`

- Set `Applicability` to `APPLICABLE` and record the uncertainty when the relevant surface cannot yet be excluded. Do not introduce a third applicability value.
- Record the exact code path and what was observed.
- State which proof obligation is missing: reachability, precondition, exploitability, impact, or PoC/invariant evidence.
- Do not assign severity, call it a finding, file an issue, or promote it because the pattern resembles a known vulnerability.
- If the required PoC cannot run because the environment or dependency is unavailable, retain `SUSPICIOUS` and record that limitation.

### `CONFIRMED`

All of the following must be concrete and supported:

1. A reachable code path from an allowed or attacker-controlled entry point.
2. Preconditions that can actually be satisfied in the declared deployment/threat model.
3. An exploitability argument showing who performs which actions and in what order.
4. A specific impact on funds, accounting, authorization, availability, or another stated security invariant.
5. Either a runnable PoC/transaction trace with observed results, or a deterministic invariant violation with a complete path and state relation.

Code pattern matching, a hypothetical “could,” a severity label, or a recommendation alone cannot produce `CONFIRMED`. The record must be at `PROOF` stage and include strong `test`, `trace`, `invariant`, or `calculation` evidence.

Accepted proof includes a named Foundry/Hardhat test and result, a reproducible transaction sequence and state delta, or a static proof of a violated invariant that does not depend on an unverified assumption. If proof depends on unavailable fork state, deployment configuration, or external behavior, keep the record `SUSPICIOUS` until that dependency is established.

## D/FP Handling

Checklist `D` sections identify candidate detection conditions. They do not establish reachability, impact, or exploitability. `FP` sections describe possible false-positive gates. Verify each `FP` condition against the actual implementation and all relevant paths before assigning `REVIEWED_SAFE`.

Reject these shortcuts:

| Shortcut | Correct disposition |
|---|---|
| “The code resembles a known vulnerable pattern.” | Candidate only; trace the path and prove the consequences. |
| “The function was not found in one file.” | Search inheritance, proxy, callbacks, and dependencies; otherwise remain unresolved. |
| “The test or fork was unavailable.” | `SUSPICIOUS`, not `CONFIRMED`. |
| “One path has a guard.” | Check every reachable alternate path before `REVIEWED_SAFE`. |
| “The issue sounds severe.” | Severity comes after the confirmation gate. |

## Minimal Disposition Examples

Pattern absent from scope after secondary inspection:

```markdown
### general/no-proxy-upgrade-path — Proxy upgrade authorization
- **Review stage**: DEEP_REVIEW
- **Routing basis**: unknown proxy feature was selected conservatively; source inventory and inheritance map were inspected.
- **Status**: NOT_APPLICABLE
- **Applicability**: NOT_APPLICABLE — source inventory contains no proxy, upgrade entry point, or delegatecall path.
- **Evidence**: source inventory and inheritance/proxy map reviewed.
```

Pattern applies but the invariant holds:

```markdown
### precision-math/rounding/deposit-rounding — Deposit conversion rounding
- **Review stage**: DEEP_REVIEW
- **Routing basis**: uses-erc4626=PRESENT; uses-math=UNKNOWN
- **Status**: REVIEWED_SAFE
- **Applicability**: APPLICABLE — deposit converts assets to shares.
- **Code path**: deposit() → _convertToShares() → mulDiv(..., Rounding.Down)
- **Preconditions**: Any supported deposit amount.
- **Exploitability**: Blocked because deposits round in the protocol-favoring direction.
- **Impact**: N/A — required rounding invariant is preserved.
- **PoC / Invariant violation**: Invariant holds: minted shares never exceed the exact asset/share conversion.
- **Evidence**: source path and focused rounding tests reviewed.
```

Pattern exists but proof is incomplete:

```markdown
### lending/oracle/spot-price — Spot price used for collateral
- **Review stage**: DEEP_REVIEW
- **Routing basis**: all_of=TRUE; uses-lending and uses-oracle are PRESENT
- **Status**: SUSPICIOUS
- **Applicability**: APPLICABLE — collateral valuation reads the pool spot price.
- **Code path**: borrow() → _healthFactor() → pool.getReserves()
- **Preconditions**: Attacker needs sufficient liquidity and a borrowable market.
- **Exploitability**: UNRESOLVED — executable manipulation cost and available borrow liquidity were not established.
- **Impact**: UNRESOLVED — extractable value is not quantified.
- **PoC / Invariant violation**: UNRESOLVED — no executable fork test or economic bound yet.
- **Evidence**: price read is confirmed; liquidity and cap data are missing.
```

Reachable defect with proof:

```markdown
### erc20/transfer-accounting — Fee-on-transfer amount mismatch
- **Review stage**: PROOF
- **Routing basis**: all_of=TRUE; uses-erc20 and uses-callback-capable-token are PRESENT
- **Status**: CONFIRMED
- **Applicability**: APPLICABLE — the protocol accepts an arbitrary fee-on-transfer token.
- **Code path**: deposit() → token.transferFrom() → credits[msg.sender] = amount
- **Preconditions**: Token burns a fee and the caller deposits through deposit().
- **Exploitability**: Caller deposits amount A while the contract receives less than A; credited balance can be withdrawn against unreceived tokens.
- **Impact**: Protocol insolvency or loss to other depositors.
- **PoC / Invariant violation**: Foundry test demonstrates received amount < credited amount and a later withdrawal exceeds actual token balance.
- **Evidence**: named test, trace, and balance delta.
```

## Synthesis Admission Gate

1. Enumerate every canonical ID from the routing manifest; only selected IDs
   must appear in review ledgers, while filtered IDs remain manifest coverage.
2. Reject manifests or ledgers with missing, duplicate, unknown, malformed, or
   non-terminal records. Mark the audit `INCOMPLETE` and do not write a final report.
3. Consider only records whose exact status is `CONFIRMED` for finding deduplication and report generation.
4. Preserve all relevant checklist references and evidence when merging duplicate confirmed records.
5. Map cross-domain candidates to existing records, or create `review-integration.md` and apply this contract to the new record.
6. If suspicious records remain after complete coverage, the report state is `INCOMPLETE_REVIEW`; it must not claim the audit is clean or vulnerability-free and must not include suspicious details as findings.
7. Assign severity only with the dimensions and mapping in
   [`severity-scoring.md`](severity-scoring.md), after confirmation.
8. If no confirmed records remain, report only that no confirmed findings were established within the reviewed scope.
