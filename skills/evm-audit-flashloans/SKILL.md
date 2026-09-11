---
name: evm-audit-flashloans
description: Security review for flash loans, flash minting, and atomic economic attacks. Consume routed selected-check bodies at runtime.
---
# Flash-Loan Security

## Review Focus

Security review for flash loans, flash minting, and atomic economic attacks.

## Required Context

- `flash_liquidity_sources`: flash-loan and flash-mint liquidity sources
- `same_transaction_state_dependencies`: same-transaction state, pricing, and callback dependencies

## Review Requirements

- test atomic manipulation of governance, prices, shares, and accounting

## Runtime Modes

Standalone: `python3 <suite-root>/scripts/audit_run.py init <target> --run-dir <run-dir> --domain evm-audit-flashloans`. Run `next` until the next template or runtime view is ready, resolve only the generated evidence-bound templates, then use `status` and `report`.

Orchestrated: consume the Master-provided immutable routing artifacts and Screen/Deep views. Never rerun Recon or Selector in orchestrated mode. When running as a dispatched Domain worker (parallel orchestration), write only this Domain's shards (`scripts/domain_shards.py write-context-shard` / `write-screen-shard`) and this Domain's append-only ledger (`reviews/review-evm-audit-flashloans.jsonl` via `scripts/review_ledger.py --append-record`); never edit shared global run files — the merge barrier and report publication belong to the controller.

Apply the Master contract at `<suite-root>/skills/evm-audit-master/references/check-review-contract.runtime.md` for global tri-state, reachable-path, proof-gating, and confirmed-only reporting rules. Consume only the routed check bodies; do not load the full canonical registry or generated checklist.

Related Domains (advisory only; never auto-expand direct scope): `evm-audit-governance`, `evm-audit-oracles`, `evm-audit-defi-amm`.

## Maintenance View
- `references/checklist.md` is a generated human-readable reference view.
