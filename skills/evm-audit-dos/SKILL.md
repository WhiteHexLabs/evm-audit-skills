---
name: evm-audit-dos
description: Security review for denial-of-service, gas griefing, unbounded work, and revert propagation. Consume routed selected-check bodies at runtime.
---
# Denial-of-Service and Griefing Security

## Review Focus

Security review for denial-of-service, gas griefing, unbounded work, and revert propagation.

## Required Context

- `collection_bounds`: collection, loop, queue, and batch bounds
- `external_call_surface`: external calls and failure propagation
- `callback_surface`: callbacks, hooks, and reentrant control flow
- `returndata_handling`: returndata size, decoding, and bubbling behavior

## Review Requirements

- establish attacker-controlled work and recovery paths

## Runtime Modes

Standalone: `python3 <suite-root>/scripts/audit_run.py init <target> --run-dir <run-dir> --domain evm-audit-dos`. Run `next` until the next template or runtime view is ready, resolve only the generated evidence-bound templates, then use `status` and `report`.

Orchestrated: consume the Master-provided immutable routing artifacts and Screen/Deep views. Never rerun Recon or Selector in orchestrated mode. When running as a dispatched Domain worker (parallel orchestration), write only this Domain's shards (`scripts/domain_shards.py write-context-shard` / `write-screen-shard`) and this Domain's append-only ledger (`reviews/review-evm-audit-dos.jsonl` via `scripts/review_ledger.py --append-record`); never edit shared global run files — the merge barrier and report publication belong to the controller.

Apply the Master contract at `<suite-root>/skills/evm-audit-master/references/check-review-contract.runtime.md` for global tri-state, reachable-path, proof-gating, and confirmed-only reporting rules. Consume only the routed check bodies; do not load the full canonical registry or generated checklist.

Related Domains (advisory only; never auto-expand direct scope): `evm-audit-general`.

## Maintenance View
- `references/checklist.md` is a generated human-readable reference view.
