---
name: evm-audit-assembly
description: Security review for inline assembly, Yul, CREATE2, low-level calls, and EVM opcodes. Consume routed selected-check bodies at runtime.
---
# Assembly and Opcode Security

## Review Focus

Security review for inline assembly, Yul, CREATE2, low-level calls, and EVM opcodes.

## Required Context

- `compiler_target`: compiler version, target, and EVM fork
- `assembly_call_sites`: assembly blocks, opcodes, and reachable call sites

## Review Requirements

- compare Yul/EVM behavior with the selected runtime

## Runtime Modes

Standalone: `python3 <suite-root>/scripts/audit_run.py init <target> --run-dir <run-dir> --domain evm-audit-assembly`. Run `next` until the next template or runtime view is ready, resolve only the generated evidence-bound templates, then use `status` and `report`.

Orchestrated: consume the Master-provided immutable routing artifacts and Screen/Deep views. Never rerun Recon or Selector in orchestrated mode. When running as a dispatched Domain worker (parallel orchestration), write only this Domain's shards (`scripts/domain_shards.py write-context-shard` / `write-screen-shard`) and this Domain's append-only ledger (`reviews/review-evm-audit-assembly.jsonl` via `scripts/review_ledger.py --append-record`); never edit shared global run files — the merge barrier and report publication belong to the controller.

Apply the Master contract at `<suite-root>/skills/evm-audit-master/references/check-review-contract.runtime.md` for global tri-state, reachable-path, proof-gating, and confirmed-only reporting rules. Consume only the routed check bodies; do not load the full canonical registry or generated checklist.

Related Domains (advisory only; never auto-expand direct scope): `evm-audit-general`, `evm-audit-chain-specific`.

## Maintenance View
- `references/checklist.md` is a generated human-readable reference view.
