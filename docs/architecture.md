# Architecture

The suite has four planes:

```text
 KNOWLEDGE  canonical-checks.json + domains/*.json + feature-detectors.json
     ↓
ROUTING    Project Analysis (`RECON`, `ROUTING`) → environment → Domain → check gates → immutable manifest v7
     ↓
RUNTIME    manifest → Context Analysis → Initial Review (`SCREEN`) → candidate-only Deep Audit (`DEEP_REVIEW`) → Vulnerability Validation (`PROOF`)
     ↓
REPORTING  Final Report (`REPORT`) → confirmed-only synthesis → severity → conditional PoC gate → report generation → report-current.json
```

The authority boundary is explicit: the target/build tree is immutable audit
input, the controller owns one explicitly managed output subtree
(`<build-root>/.evm-auditor-work` by default, or an explicit `--output-dir`)
that is excluded from scope discovery, compilation fingerprints, source
snapshots, and PoC build-tree copies, and `report-generations/` contains
immutable derived outputs. High/Critical PoC
sources are copied into the generation; recorded commands execute only through
the explicit `verify-poc` command. Verification copies dependencies into a
disposable workspace, stages the exact validated PoC bytes, rejects external
symlinks and package-installing runner forms, and scrubs parent credentials.

User-facing Skill packages live under `skills/`; runtime assets remain in
`data/`, `domains/`, `scripts/`, and the small pure-decision package
`evm_audit_runtime/`. Benchmark fixtures live under
`development/` and are not part of a normal audit run.

The registry is the only checklist knowledge source. The generator renders
human-readable reference Markdown; Skills execute the selected runtime artifacts.

Safety invariants: UNKNOWN, Initial Review uncertainty, and DECLARED environment facts
never filter; only trusted absence or CONFIRMED environment mismatch filters;
all filtered/Deferred items stay manifest-visible; Deferred Domains must resolve
before clean completion; required Domain Context is a separate snapshot-bound
artifact; only CONFIRMED records reach reporting and SUSPICIOUS records never
receive severity. `validate_audit_run.py` derives completion from the artifacts
instead of trusting an upstream completion flag. Strong proof establishes
`CONFIRMED`; a runnable PoC is separate reporting evidence required only for
confirmed `High` and `Critical` findings. The PoC artifact is lineage-bound to
severity-decision bytes and source hashes, and is snapshotted in report-bundle
v3 without changing the review lifecycle. A separate v2 `poc-verification`
receipt is optional and non-gating.
