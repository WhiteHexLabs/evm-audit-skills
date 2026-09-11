---
name: evm-audit-chain-specific
description: Security review for non-mainnet EVM deployments and chain-specific execution assumptions. Consume routed selected-check bodies at runtime.
---
# Chain-Specific Security

## Review Focus

Security review for non-mainnet EVM deployments and chain-specific execution assumptions.

## Required Context

- `chain_family`: target chain family and network
- `execution_environment`: EVM, EraVM, interpreter, or other execution environment
- `evm_fork`: active EVM fork and opcode semantics
- `deployed_bytecode`: deployed bytecode and system-contract assumptions

## Review Requirements

- verify every relied-upon opcode and system-contract behavior

## Runtime Modes

Standalone: `python3 <suite-root>/scripts/audit_run.py init <target> --run-dir <run-dir> --domain evm-audit-chain-specific`. Run `next` until the next template or runtime view is ready, resolve only the generated evidence-bound templates, then use `status` and `report`.

Orchestrated: consume the Master-provided immutable routing artifacts and Screen/Deep views. Never rerun Recon or Selector in orchestrated mode. When running as a dispatched Domain worker (parallel orchestration), write only this Domain's shards (`scripts/domain_shards.py write-context-shard` / `write-screen-shard`) and this Domain's append-only ledger (`reviews/review-evm-audit-chain-specific.jsonl` via `scripts/review_ledger.py --append-record`); never edit shared global run files — the merge barrier and report publication belong to the controller.

Apply the Master contract at `<suite-root>/skills/evm-audit-master/references/check-review-contract.runtime.md` for global tri-state, reachable-path, proof-gating, and confirmed-only reporting rules. Consume only the routed check bodies; do not load the full canonical registry or generated checklist.

Related Domains (advisory only; never auto-expand direct scope): `evm-audit-oracles`, `evm-audit-assembly`.

## Maintenance View
- `references/checklist.md` is a generated human-readable reference view.
