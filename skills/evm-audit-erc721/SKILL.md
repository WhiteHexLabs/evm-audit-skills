---
name: evm-audit-erc721
description: Security review for ERC721, ERC1155, NFT implementations, and NFT integrations. Consume routed selected-check bodies at runtime.
---
# ERC721 and ERC1155 Security

## Review Focus

Security review for ERC721, ERC1155, NFT implementations, and NFT integrations.

## Required Context

- `accepted_nft_standards`: accepted ERC721/ERC1155 standards and token assumptions
- `receiver_hooks`: receiver callbacks and hook behavior
- `approval_model`: approval, operator, and transfer authorization model
- `custody_model`: custody, ownership, and escrow model

## Review Requirements

- trace ownership, callback, and transfer compatibility

## Runtime Modes

Standalone: `python3 <suite-root>/scripts/audit_run.py init <target> --run-dir <run-dir> --domain evm-audit-erc721`. Run `next` until the next template or runtime view is ready, resolve only the generated evidence-bound templates, then use `status` and `report`.

Orchestrated: consume the Master-provided immutable routing artifacts and Screen/Deep views. Never rerun Recon or Selector in orchestrated mode. When running as a dispatched Domain worker (parallel orchestration), write only this Domain's shards (`scripts/domain_shards.py write-context-shard` / `write-screen-shard`) and this Domain's append-only ledger (`reviews/review-evm-audit-erc721.jsonl` via `scripts/review_ledger.py --append-record`); never edit shared global run files — the merge barrier and report publication belong to the controller.

Apply the Master contract at `<suite-root>/skills/evm-audit-master/references/check-review-contract.runtime.md` for global tri-state, reachable-path, proof-gating, and confirmed-only reporting rules. Consume only the routed check bodies; do not load the full canonical registry or generated checklist.

Related Domains (advisory only; never auto-expand direct scope): `evm-audit-general`, `evm-audit-access-control`.

## Maintenance View
- `references/checklist.md` is a generated human-readable reference view.
