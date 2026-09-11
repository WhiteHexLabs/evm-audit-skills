---
name: evm-audit-erc4626
description: Security review for ERC4626 vaults and vault integrations. Consume routed selected-check bodies at runtime.
---
# ERC4626 Vault Security

## Review Focus

Security review for ERC4626 vaults and vault integrations.

## Required Context

- `asset_decimals`: underlying asset decimals and normalization
- `share_decimals`: share decimals and initial share state
- `conversion_formulas`: asset/share conversion and preview formulas
- `fee_model`: deposit, withdrawal, and performance fee accounting
- `initial_state`: empty-vault, donation, and first-deposit behavior

## Review Requirements

- verify preview parity, rounding, donation, and inflation resistance

## Runtime Modes

Standalone: `python3 <suite-root>/scripts/audit_run.py init <target> --run-dir <run-dir> --domain evm-audit-erc4626`. Run `next` until the next template or runtime view is ready, resolve only the generated evidence-bound templates, then use `status` and `report`.

Orchestrated: consume the Master-provided immutable routing artifacts and Screen/Deep views. Never rerun Recon or Selector in orchestrated mode. When running as a dispatched Domain worker (parallel orchestration), write only this Domain's shards (`scripts/domain_shards.py write-context-shard` / `write-screen-shard`) and this Domain's append-only ledger (`reviews/review-evm-audit-erc4626.jsonl` via `scripts/review_ledger.py --append-record`); never edit shared global run files — the merge barrier and report publication belong to the controller.

Apply the Master contract at `<suite-root>/skills/evm-audit-master/references/check-review-contract.runtime.md` for global tri-state, reachable-path, proof-gating, and confirmed-only reporting rules. Consume only the routed check bodies; do not load the full canonical registry or generated checklist.

Related Domains (advisory only; never auto-expand direct scope): `evm-audit-precision-math`, `evm-audit-erc20`.

## Maintenance View
- `references/checklist.md` is a generated human-readable reference view.
