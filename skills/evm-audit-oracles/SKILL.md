---
name: evm-audit-oracles
description: Security review for price feeds, TWAPs, VRF, and external data inputs. Consume routed selected-check bodies at runtime.
---
# Oracle and Pricing Security

## Review Focus

Security review for price feeds, TWAPs, VRF, and external data inputs.

## Required Context

- `feed_contracts`: feed contracts and data sources
- `feed_decimals`: feed and protocol decimal scaling
- `heartbeat`: heartbeat and staleness handling
- `bounds`: answer bounds, deviation, and circuit breakers
- `fallback_behavior`: fallback, sequencer, and failure behavior

## Review Requirements

- verify freshness, scaling, sequencer, and manipulation resistance

## Runtime Modes

Standalone: `python3 <suite-root>/scripts/audit_run.py init <target> --run-dir <run-dir> --domain evm-audit-oracles`. Run `next` until the next template or runtime view is ready, resolve only the generated evidence-bound templates, then use `status` and `report`.

Orchestrated: consume the Master-provided immutable routing artifacts and Screen/Deep views. Never rerun Recon or Selector in orchestrated mode. When running as a dispatched Domain worker (parallel orchestration), write only this Domain's shards (`scripts/domain_shards.py write-context-shard` / `write-screen-shard`) and this Domain's append-only ledger (`reviews/review-evm-audit-oracles.jsonl` via `scripts/review_ledger.py --append-record`); never edit shared global run files — the merge barrier and report publication belong to the controller.

Apply the Master contract at `<suite-root>/skills/evm-audit-master/references/check-review-contract.runtime.md` for global tri-state, reachable-path, proof-gating, and confirmed-only reporting rules. Consume only the routed check bodies; do not load the full canonical registry or generated checklist.

Related Domains (advisory only; never auto-expand direct scope): `evm-audit-chain-specific`, `evm-audit-precision-math`.

## Maintenance View
- `references/checklist.md` is a generated human-readable reference view.
