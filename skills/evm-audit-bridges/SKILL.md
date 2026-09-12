---
name: evm-audit-bridges
description: Security review for cross-chain bridges, messaging, relayers, and adapters. Consume routed selected-check bodies at runtime.
---
# Bridge and Cross-Chain Security

## Review Focus

Security review for cross-chain bridges, messaging, relayers, and adapters.

## Required Context

- `source_chain`: source chain and message origin
- `destination_chain`: destination chain and message execution target
- `finality_model`: finality, confirmations, and reorg assumptions
- `message_authentication`: message validation and authentication path
- `relayer_model`: relayer, quorum, and delivery assumptions

## Review Requirements

- model message lifecycle, replay, ordering, and failure recovery

## Runtime Modes

Standalone: `python3 <suite-root>/scripts/audit_run.py init <target> --run-dir <run-dir> --domain evm-audit-bridges`. Run `next` until the next template or runtime view is ready, resolve only the generated evidence-bound templates, then use `status` and `report`.

Orchestrated: consume the Master-provided immutable routing artifacts and Screen/Deep views. Never rerun Recon or Selector in orchestrated mode. When running as a dispatched Domain worker (parallel orchestration), write only this Domain's shards (`scripts/domain_shards.py write-context-shard` / `write-screen-shard`) and this Domain's append-only ledger (`reviews/review-evm-audit-bridges.jsonl` via `scripts/review_ledger.py --append-record`); never edit shared global run files — the merge barrier and report publication belong to the controller.

Apply the Master contract at `<suite-root>/skills/evm-audit-master/references/check-review-contract.runtime.md` for global tri-state, reachable-path, proof-gating, and confirmed-only reporting rules. Consume only the routed check bodies; do not load the full canonical registry or generated checklist.

Related Domains (advisory only; never auto-expand direct scope): `evm-audit-signatures`, `evm-audit-chain-specific`.

## Maintenance View
- `references/checklist.md` is a generated human-readable reference view.
