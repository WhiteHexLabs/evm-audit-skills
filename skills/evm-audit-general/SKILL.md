---
name: evm-audit-general
description: General Solidity and EVM security review for every smart contract. Consume routed selected-check bodies at runtime.
---
# General Solidity/EVM Security

## Review Focus

General Solidity and EVM security review for every smart contract.

## Required Context

- `scope_inventory`: complete source, dependency, and deployment scope inventory
- `entry_points`: state-changing entry points and call paths
- `trust_boundaries`: privilege, user, oracle, and external trust boundaries
- `external_dependencies`: external contracts, libraries, and integration assumptions

## Review Requirements

- trace reachable state changes and cross-domain interactions

## Runtime Modes

Standalone: `python3 <suite-root>/scripts/audit_run.py init <target> --run-dir <run-dir> --domain evm-audit-general`. Run `next` until the next template or runtime view is ready, resolve only the generated evidence-bound templates, then use `status` and `report`.

Orchestrated: consume the Master-provided immutable routing artifacts and Screen/Deep views. Never rerun Recon or Selector in orchestrated mode. When running as a dispatched Domain worker (parallel orchestration), write only this Domain's shards (`scripts/domain_shards.py write-context-shard` / `write-screen-shard`) and this Domain's append-only ledger (`reviews/review-evm-audit-general.jsonl` via `scripts/review_ledger.py --append-record`); never edit shared global run files — the merge barrier and report publication belong to the controller.

Apply the Master contract at `<suite-root>/skills/evm-audit-master/references/check-review-contract.runtime.md` for global tri-state, reachable-path, proof-gating, and confirmed-only reporting rules. Consume only the routed check bodies; do not load the full canonical registry or generated checklist.

Related Domains (advisory only; never auto-expand direct scope): `evm-audit-precision-math`.

## Maintenance View
- `references/checklist.md` is a generated human-readable reference view.
