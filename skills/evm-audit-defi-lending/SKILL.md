---
name: evm-audit-defi-lending
description: Security review for lending, borrowing, collateral, liquidation, and CDP protocols. Consume routed selected-check bodies at runtime.
---
# Lending and Liquidation Security

## Review Focus

Security review for lending, borrowing, collateral, liquidation, and CDP protocols.

## Required Context

- `oracle_configuration`: price sources, freshness, and oracle configuration
- `collateral_parameters`: collateral factors, LTV, and liquidation thresholds
- `market_caps`: supply, borrow, and liquidity caps
- `liquidation_model`: liquidation, auction, and bad-debt handling
- `interest_model`: interest accrual and reserve accounting

## Review Requirements

- model solvency, bad debt, and liquidation economics

## Runtime Modes

Standalone: `python3 <suite-root>/scripts/audit_run.py init <target> --run-dir <run-dir> --domain evm-audit-defi-lending`. Run `next` until the next template or runtime view is ready, resolve only the generated evidence-bound templates, then use `status` and `report`.

Orchestrated: consume the Master-provided immutable routing artifacts and Screen/Deep views. Never rerun Recon or Selector in orchestrated mode. When running as a dispatched Domain worker (parallel orchestration), write only this Domain's shards (`scripts/domain_shards.py write-context-shard` / `write-screen-shard`) and this Domain's append-only ledger (`reviews/review-evm-audit-defi-lending.jsonl` via `scripts/review_ledger.py --append-record`); never edit shared global run files — the merge barrier and report publication belong to the controller.

Apply the Master contract at `<suite-root>/skills/evm-audit-master/references/check-review-contract.runtime.md` for global tri-state, reachable-path, proof-gating, and confirmed-only reporting rules. Consume only the routed check bodies; do not load the full canonical registry or generated checklist.

Related Domains (advisory only; never auto-expand direct scope): `evm-audit-precision-math`, `evm-audit-erc20`, `evm-audit-oracles`.

## Maintenance View
- `references/checklist.md` is a generated human-readable reference view.
