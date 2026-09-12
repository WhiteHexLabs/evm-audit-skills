# Audit Workflow

## Overview

An EVM audit is an evidence-gated funnel, not one model reading an entire
repository and guessing vulnerabilities. The runtime starts with a broad
security checklist, narrows it using evidence about the target, investigates
the remaining candidates, and reports only issues that survive Vulnerability
Validation.

The phases are deliberately ordered: later phases rely on the scope and
decisions established earlier, while uncertainty stays visible until it can
be resolved.

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
used by configuration, artifacts, and runtime control flow. The phase names
above are the user-facing presentation layer.

## Sequential and orchestrated execution

The funnel above is the sequential shape: one executor advances every phase
in order. It is also the exact workflow Codex runs, since the Codex runtime
provides no in-session sub-agent dispatch.

When the active runtime can dispatch sub-agents (ZCode custom worker agent
types), the same funnel executes with a main agent plus one worker per
Domain per stage: Project Analysis, Domain Resolution, the stage merges, and
the Final Report stay with the main agent; each of Domain Context, Initial
Review, Deep Audit, and Vulnerability Validation runs as its own stage wave,
with one worker per Domain dispatched to the agent type configured for that
stage. Two controller-owned merge barriers sit between context and screen
work and between screen and deep review, because every deep record must bind
to the single review snapshot derived from the complete global results. The
controller's `next` call is the transition barrier between waves: it alone
advances the stage, renders the per-owner runtime views, and names the next
wave's worker agent — a successful merge publishes artifacts but never
advances the stage. Zero-candidate runs return `REPORT` directly after the
screen barrier, and runs with no `SUSPICIOUS` records return `REPORT`
without a Proof wave. A worker invocation never crosses a stage boundary —
each custom agent pins exactly one model/thought-level contract.
Parallelism is across Domains
within a stage; stage ordering stays deterministic. Parallel execution
changes who runs each phase, never the gates: every shard, ledger record,
and report input passes the same validation as in sequential mode. See the
Master Skill's Orchestration section and [Audit Runtime](audit-runtime.md)
for the exact commands and locking model.

## 1. Project Analysis (`RECON`, `ROUTING`)

Project Analysis builds a trustworthy picture of the project and uses it to
select the checks that belong in the audit.

### Recon (`RECON`)

Recon builds a trustworthy picture of what is being audited. It establishes:

- the audit scope and build root;
- project configuration and dependencies;
- the Solidity compiler and build environment; and
- important protocol features such as upgradeability, ERC-4626 vaults,
  external oracles, flash-loan callbacks, and role-based permissions.

For example, a target may be a vault in `src/Vault.sol`, while its compilation
context comes from the surrounding Foundry project and its configured
dependencies. Recon keeps those two boundaries distinct so the audit does not
silently omit code needed to understand the target.

Keep mutable run artifacts in an external sibling directory such as
`../protocol-audit-run/`; the target and build trees are authoritative inputs.
Recon rejects source/build changes observed during its analysis window, and
PoC verification works from a disposable copy so it cannot mutate those inputs
through the verification workspace. Recon publishes no Feature Map or code
index from an unstable snapshot.

Recon is conservative when traversal or compilation is incomplete. Presence
evidence can still identify code that was seen, but missing evidence is not
treated as proof that a feature or dependency is absent.

Main outputs are:

- a Feature Map;
- scope and build metadata; and
- source and build fingerprints.

### Routing (`ROUTING`)

The suite contains checks for many EVM and DeFi attack classes. Applying every
check to every contract wastes time and model context, so Routing uses Recon
and trusted environment facts to determine which checks belong in the audit.

Checks can be:

- **selected** for the current review;
- **deferred** until protocol-specific context is available; or
- **filtered** only when trusted evidence proves they do not apply.

Examples:

- verified absence of proxy architecture can filter proxy-specific checks;
- an ERC-4626 vault routes in vault accounting and share-price checks; and
- uncertain oracle usage keeps oracle checks visible for further investigation.

Routing creates an immutable snapshot. Later stages consume that snapshot and
cannot silently change the set of checks under review.

## 2. Context Analysis (`DOMAIN_RESOLUTION`, `DOMAIN_CONTEXT`)

Some security questions require protocol-specific facts that syntax alone
cannot establish. The audit may need to understand the oracle, accepted
assets, upgrade authority, liquidation mechanism, or trusted external
protocols.

This phase combines two related runtime activities:

- **Domain Resolution (`DOMAIN_RESOLUTION`)** decides whether a deferred Domain
  applies to the target.
- **Domain Context (`DOMAIN_CONTEXT`)** records the facts required to review an
  active Domain.

For example, the audit may resolve Chainlink as the oracle, WETH and WBTC as
collateral, a 2-of-3 multisig as the upgrade authority, and a permissionless
liquidation path with a 5% incentive. If an important fact remains unknown,
the audit cannot claim a clean completion; it must investigate or disclose the
unresolved context.

## 3. Initial Review (`SCREEN`)

Initial Review is the fast triage phase. Each routed check ends in exactly one
of two user-facing outcomes:

- `NOT_APPLICABLE_CONFIRMED`
- `CANDIDATE`

`NOT_APPLICABLE_CONFIRMED` means evidence proves that the attack class does not
apply. `CANDIDATE` means the check needs deeper analysis, including when the
evidence is incomplete.

For example, an AMM spot-price oracle check can be marked
`NOT_APPLICABLE_CONFIRMED` when the protocol demonstrably never uses an AMM
price. If it does use that price, or the oracle path is unclear, the check
remains a `CANDIDATE`.

The invariant is:

```text
uncertain → CANDIDATE
```

Initial Review does not emit a “probably safe” result. This keeps uncertain
attack paths in the review rather than filtering them out early.

## 4. Deep Audit (`DEEP_REVIEW`)

Deep Audit examines each candidate against the actual implementation. It
traces state transitions, permissions, external calls, invariants, and
economic assumptions instead of relying on a pattern match.

A small vault example might follow:

```text
deposit()
  ↓
share calculation
  ↓
external token transfer
  ↓
totalAssets()
  ↓
withdraw()
```

The reviewer asks whether the suspected behavior is reachable, which state and
permission checks matter, and whether the claimed impact follows from the
real call path. Deep Audit can resolve a candidate as `REVIEWED_SAFE` or leave
it `SUSPICIOUS`; `CONFIRMED` is reserved for Vulnerability Validation.

## 5. Vulnerability Validation (`PROOF`)

`SUSPICIOUS` is a hypothesis, not a finding. Vulnerability Validation tests whether the suspected
attack is reachable and exploitable under the target's actual conditions.

Evidence may include:

- strong proof such as a Foundry test, trace, invariant violation, or calculation;
- transaction traces;
- an invariant violation;
- arithmetic or economic calculations; or
- deterministic reproduction of the exploit path.

Vulnerability Validation also considers attacker privileges, required capital, guards, external
dependencies, repeatability, and measurable impact. For a suspected share-price
manipulation issue, it asks whether an attacker can reach the state, whether a
guard blocks it, and whether value can actually be extracted.

Only strong evidence can move a record to `CONFIRMED`. If the invariant or
guard prevents exploitation, the suspicious candidate is resolved as safe
instead. `Proof != PoC`: proof is a separate validation activity from a
runnable exploit PoC, which is a reporting input and not a prerequisite for
confirmation.

## 6. Final Report (`REPORT`)

Final Report independently re-validates the current audit state before producing
results. It requires:

- current routing;
- complete required context;
- complete Screen coverage;
- a review for every Deep Audit candidate; and
- no unresolved `SUSPICIOUS` item; and
- reporting artifacts that match the current review and proof state; and
- a validated runnable PoC for each confirmed `High` or `Critical` finding.

Only `CONFIRMED` records enter the Final Report. The main artifacts are:

- `AUDIT-REPORT.md` for confirmed findings; and
- `issue-candidates.json` for structured issue candidates.

The controller commits these through an immutable content-addressed report
generation and the `report-current.json` pointer; controller output exposes the
generation paths as authoritative, while top-level files are convenience copies.

Incomplete or stale evidence prevents the runtime from presenting a clean,
completed audit. Confirmed `Info`, `Low`, and `Medium` findings do not need a
PoC merely to report, and remain visible in the Markdown report. `Medium` and
above remain issue candidates.

The reporting rule is severity-gated:

```text
CONFIRMED + Medium → report normally; no PoC required
CONFIRMED + High   → INCOMPLETE_POC until a validated PoC is present
PoC admitted       → report after admission and snapshot validation
```

High/Critical PoC source bytes are retained in the immutable report generation.
If execution evidence is desired, run the explicit `verify-poc` command; it is
additional assurance and is not executed automatically by status or report.

## Example End-to-End Audit

```text
ERC-4626 vault detected
        ↓
vault checks routed in
        ↓
donation attack survives Initial Review
        ↓
Deep Audit finds possible share manipulation
        ↓
Vulnerability Validation runs a Foundry PoC
        ↓
CONFIRMED
        ↓
Final Report
```

This is a generic illustration of the evidence flow; a real report includes a
finding only when the target-specific proof supports it.

For CLI commands, artifact identity, schemas, and controller behavior, see
[Audit Runtime](audit-runtime.md). For the repository's four-plane design, see
[Architecture](architecture.md).
