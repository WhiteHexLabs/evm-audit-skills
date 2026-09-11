---
name: evm-audit-erc20
description: Security review for contracts that implement or integrate ERC20-compatible tokens. Consume routed selected-check bodies at runtime.
---
# ERC20 Integration Security

## Review Focus

Security review for contracts that implement or integrate ERC20-compatible tokens.

## Required Context

- `accepted_tokens`: accepted token contracts and non-standard token assumptions
- `balance_accounting`: balance, supply, and fee accounting
- `allowances`: allowance and approval behavior
- `transfer_wrappers`: transfer and safe-wrapper behavior

## Review Requirements

- test non-standard token behaviors against accounting invariants

## Runtime Modes

Standalone: `python3 <suite-root>/scripts/audit_run.py init <target> --run-dir <run-dir> --domain evm-audit-erc20`. Run `next` until the next template or runtime view is ready, resolve only the generated evidence-bound templates, then use `status` and `report`.

Orchestrated: consume the Master-provided immutable routing artifacts and Screen/Deep views. Never rerun Recon or Selector in orchestrated mode. When running as a dispatched Domain worker (parallel orchestration), write only this Domain's shards (`scripts/domain_shards.py write-context-shard` / `write-screen-shard`) and this Domain's append-only ledger (`reviews/review-evm-audit-erc20.jsonl` via `scripts/review_ledger.py --append-record`); never edit shared global run files — the merge barrier and report publication belong to the controller.

Apply the Master contract at `<suite-root>/skills/evm-audit-master/references/check-review-contract.runtime.md` for global tri-state, reachable-path, proof-gating, and confirmed-only reporting rules. Consume only the routed check bodies; do not load the full canonical registry or generated checklist.

Related Domains (advisory only; never auto-expand direct scope): `evm-audit-general`, `evm-audit-precision-math`.

## Maintenance View
- `references/checklist.md` is a generated human-readable reference view.
