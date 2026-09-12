---
name: evm-audit-defi-amm
description: Security review for AMMs, DEXs, swap routers, liquidity pools, and hooks. Consume routed selected-check bodies at runtime.
---
# AMM and DEX Security

## Review Focus

Security review for AMMs, DEXs, swap routers, liquidity pools, and hooks.

## Required Context

- `pool_model`: pool and invariant model
- `fee_model`: fee tiers and fee accounting
- `liquidity_model`: liquidity sources, depth, and price impact
- `hook_surface`: hooks, callbacks, and external control points
- `price_source`: spot, TWAP, oracle, or other price source

## Review Requirements

- model price impact, slippage, callback, and accounting invariants

## Runtime Modes

Standalone: `python3 <suite-root>/scripts/audit_run.py init <target> --run-dir <run-dir> --domain evm-audit-defi-amm`. Run `next` until the next template or runtime view is ready, resolve only the generated evidence-bound templates, then use `status` and `report`.

Orchestrated: consume the Master-provided immutable routing artifacts and Screen/Deep views. Never rerun Recon or Selector in orchestrated mode. When running as a dispatched Domain worker (parallel orchestration), write only this Domain's shards (`scripts/domain_shards.py write-context-shard` / `write-screen-shard`) and this Domain's append-only ledger (`reviews/review-evm-audit-defi-amm.jsonl` via `scripts/review_ledger.py --append-record`); never edit shared global run files — the merge barrier and report publication belong to the controller.

Apply the Master contract at `<suite-root>/skills/evm-audit-master/references/check-review-contract.runtime.md` for global tri-state, reachable-path, proof-gating, and confirmed-only reporting rules. Consume only the routed check bodies; do not load the full canonical registry or generated checklist.

Related Domains (advisory only; never auto-expand direct scope): `evm-audit-precision-math`, `evm-audit-erc20`, `evm-audit-oracles`.

## Maintenance View
- `references/checklist.md` is a generated human-readable reference view.
