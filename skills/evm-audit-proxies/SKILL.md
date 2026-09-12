---
name: evm-audit-proxies
description: Security review for proxies, upgrade mechanisms, initializers, and storage layouts. Consume routed selected-check bodies at runtime.
---
# Proxy and Upgrade Security

## Review Focus

Security review for proxies, upgrade mechanisms, initializers, and storage layouts.

## Required Context

- `proxy_kind`: proxy pattern and deployment topology
- `implementation`: implementation address and code identity
- `admin`: upgrade administrator or governance authority
- `initializer`: initializer and initialization state
- `upgrade_path`: upgrade authorization, storage, and migration path

## Review Requirements

- trace initialization, authorization, and storage compatibility

## Runtime Modes

Standalone: `python3 <suite-root>/scripts/audit_run.py init <target> --run-dir <run-dir> --domain evm-audit-proxies`. Run `next` until the next template or runtime view is ready, resolve only the generated evidence-bound templates, then use `status` and `report`.

Orchestrated: consume the Master-provided immutable routing artifacts and Screen/Deep views. Never rerun Recon or Selector in orchestrated mode. When running as a dispatched Domain worker (parallel orchestration), write only this Domain's shards (`scripts/domain_shards.py write-context-shard` / `write-screen-shard`) and this Domain's append-only ledger (`reviews/review-evm-audit-proxies.jsonl` via `scripts/review_ledger.py --append-record`); never edit shared global run files — the merge barrier and report publication belong to the controller.

Apply the Master contract at `<suite-root>/skills/evm-audit-master/references/check-review-contract.runtime.md` for global tri-state, reachable-path, proof-gating, and confirmed-only reporting rules. Consume only the routed check bodies; do not load the full canonical registry or generated checklist.

Related Domains (advisory only; never auto-expand direct scope): `evm-audit-access-control`, `evm-audit-assembly`.

## Maintenance View
- `references/checklist.md` is a generated human-readable reference view.
