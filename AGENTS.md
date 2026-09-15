# AGENTS.md

Repository: `iavl/evm-audit-skills`

This file defines the persistent engineering rules for AI agents (Codex and similar tools) working in this repository.

The repository is a deterministic, evidence-gated EVM smart-contract audit Skill suite. Its core job is not merely to generate prompts: it maintains an auditable pipeline from Recon → Routing → Domain Resolution / Context → Screen → Deep Review → Proof → Report, with machine-readable lineage and conservative security semantics.

When a task-specific `plan.md` exists, follow both files:
- `AGENTS.md` defines persistent repository rules.
- `plan.md` defines the current implementation task.
- If they conflict, preserve the security invariants in this file and surface the conflict instead of silently weakening them.

---

# 1. Repository mission

The repository must help an AI auditor investigate EVM/Solidity code without silently turning incomplete knowledge into a clean result.

Optimize for:

1. audit correctness;
2. security recall;
3. deterministic behavior;
4. evidence quality;
5. artifact lineage;
6. reproducibility;
7. maintainability;
8. token/context efficiency.

Token savings, shorter prompts, faster execution, or prettier output are never allowed to reduce audit coverage or weaken evidence requirements.

---

# 2. Non-negotiable security invariants

These rules MUST remain true after every change.

## 2.1 Unknown is not absence

```text
UNKNOWN != ABSENT
```

Do not treat:

- missing evidence;
- failed compilation;
- missing tool output;
- absent keyword matches;
- incomplete source coverage;
- unsupported analyzer behavior;
- ambiguous environment facts;

as proof that a vulnerability class or protocol surface is absent.

Only explicitly trusted absence evidence may produce `ABSENT_CONFIRMED` or equivalent filtering behavior.

---

## 2.2 Incomplete compilation is fail-closed

At the repository execution boundary, preserve this conservative rule:

```text
UNTRUSTED_SOURCE && HAS_DOT_GIT => POTENTIALLY_EXECUTABLE
```

Unknown source trust counts as untrusted for this decision. This does not claim
that `.git` is malware; it defines when an original repository must be
sanitized before agent or analyzer execution.

If the complete audit scope cannot be reliably compiled or analyzed:

- do not claim trusted absence from incomplete traversal;
- preserve relevant checks as selected/deferred/unknown;
- do not allow incomplete Recon to become a clean audit;
- surface the missing coverage in machine-readable state.

Never "fix" a compilation problem by silently narrowing the audit scope.

---

## 2.3 Routing must be conservative

The router must prioritize recall over aggressive filtering.

A check may be filtered only when its exclusion condition is justified by trusted evidence.

Rules:

- inferred uncertainty stays visible;
- an inferred false predicate must not automatically become a trusted filter;
- dependency-only evidence must not automatically prove first-party applicability unless the owning Domain explicitly allows it;
- environment mismatches may filter only when the relevant environment fact is trusted.

Do not add heuristics that increase false negatives merely to reduce candidate count.

---

## 2.4 Screen cannot declare safety

Screen is triage, not final review.

Allowed Screen outcomes remain conceptually limited to:

```text
CANDIDATE
NOT_APPLICABLE_CONFIRMED
```

Screen must not emit or imply:

- `REVIEWED_SAFE`;
- `CONFIRMED`;
- severity;
- final exploitability conclusions.

If uncertainty remains, promote the check to deeper investigation.

---

## 2.5 Deep Review requires reachable-path reasoning

A check may be marked `REVIEWED_SAFE` only after relevant reachable paths have been considered.

Where relevant, include:

- alternate entry points;
- inherited paths;
- modifiers;
- callbacks;
- reentrancy paths;
- delegatecall paths;
- proxy / implementation behavior;
- initialization paths;
- multicall / batching;
- cross-function state interactions;
- role transitions;
- economic state transitions.

One safe path is not enough to prove the entire check safe.

---

## 2.6 Suspicious findings require Proof

`SUSPICIOUS` is unresolved.

It MUST NOT receive final severity and MUST NOT enter the final findings report.

A later Proof-stage revision must resolve it to an allowed terminal state.

---

## 2.7 Confirmed findings require strong evidence

`CONFIRMED` must remain proof-gated.

A confirmed finding requires, as applicable:

- a reachable code path;
- satisfiable preconditions;
- concrete exploitability;
- concrete impact;
- a runnable PoC, trace, deterministic invariant violation, or rigorous calculation.

Pattern similarity alone is never a confirmed finding.

---

## 2.8 Final report contains confirmed findings only

The final report must never convert:

- heuristic matches;
- Screen candidates;
- incomplete review;
- suspicious findings;

into final vulnerabilities.

A clean result is valid only when the authoritative audit state is complete and explicitly clean.

---

# 3. Artifact authority and lineage

The repository relies on machine-readable artifacts. Treat lineage as a security property.

## 3.1 Authoritative knowledge source

`data/canonical-checks.json` is the authoritative checklist source.

Generated per-Domain checklist Markdown is derived output.

Do not manually edit generated checklist content if the generator will overwrite it.

If canonical knowledge changes:

1. modify the canonical source;
2. validate it;
3. regenerate derived artifacts;
4. review generated diff;
5. run all required knowledge checks.

---

## 3.2 Snapshot binding

Preserve all relevant identity fields across the pipeline, including where applicable:

- `routing_snapshot_id`;
- `review_snapshot_id`;
- `review_state_digest`;
- `registry_sha256`;
- `source_digest`;
- `audit_source_digest`;
- `dependency_digest`;
- `build_config_digest`;
- `compilation_input_digest`;
- `check_body_hash`.

Do not remove a lineage field just because it appears redundant.

If an artifact consumes another artifact and can affect model behavior or final audit state, stale inputs must be detectable.

---

## 3.3 Generated views are not authoritative

Markdown runtime files and rendered review views are convenience/model-facing views.

Machine-readable JSON/JSONL remains authoritative.

Generated views:

- must be regenerable;
- must not silently diverge from their metadata;
- must not become the sole source of truth;
- must be treated as untrusted if stale, malformed, or identity-mismatched.

The code index is also a navigation hint, not security evidence.

---

## 3.4 Atomic writes

Any artifact that can affect:

- routing;
- review state;
- model-facing runtime context;
- final reporting;

should be written atomically whenever practical.

Do not leave partially written JSON, JSONL, Markdown, or sidecar metadata that can be mistaken for complete output.

The target/build trees are immutable authoritative audit input. The controller
owns one explicitly managed output subtree (`<build-root>/.evm-auditor-work` by
default, or an explicit `--output-dir`), which is excluded from audit scope
discovery, compilation fingerprints, source snapshots, and PoC build-tree
copies. Resolved output paths equal to either authoritative root, inside
`.git` or dependency/build/cache trees, or nested inside a narrower audit root
are rejected; external output directories remain supported. Everything outside
the managed output subtree remains authoritative input. Generated outputs must
not write over source, build configuration, dependency metadata, or lockfiles. Report
generations are immutable derived outputs, and High/Critical PoC source bytes
are snapshotted under their generation. Recorded PoC commands run only through
the explicit `verify-poc` command, with structured argv and `shell=False`.

---

# 4. Repository architecture

Maintain clear responsibility boundaries.

## 4.1 `data/`

Contains canonical security knowledge and feature registries.

Do not place runtime state here.

---

## 4.2 `domains/`

Contains Domain taxonomy, routing surface definitions, context requirements, and trusted absence policy.

Domain configuration should remain declarative where practical.

Do not embed large amounts of executable runtime logic into Domain JSON.

---

## 4.3 `skills/`

Contains user/model-facing Skill packages and generated checklist views.

`skills/evm-audit-master/agents/` ships the ZCode custom worker agent templates (`evm-audit-worker-flash`, `evm-audit-worker-deep`, `evm-audit-worker-proof`); their pinned `model` and `thoughtLevel` frontmatter is the execution contract the model-profile validator checks against. `install.sh zcode` installs them into `~/.zcode/agents/`; the audit Skill itself must never mutate agent configuration at runtime.

Keep global audit safety rules centralized in the Master Skill / shared review contract.

Domain Skills should contain domain-specific methodology, not repeated copies of generic global rules.

Do not duplicate generic instructions across every Domain only to make prompts longer.

---

## 4.4 `scripts/`

Contains CLI entry points, generation tools, validation, orchestration, benchmarks, and maintenance commands.

New reusable pure logic should prefer `evm_audit_runtime/` when doing so reduces duplication without breaking CLI compatibility.

Avoid adding more responsibilities to already-large scripts when a small pure helper is clearer.

---

## 4.5 `evm_audit_runtime/`

Contains shared runtime logic that should be:

- deterministic;
- side-effect-light where possible;
- independently testable;
- decoupled from CLI argument parsing.

Prefer moving reusable state/routing/artifact logic here incrementally.

Do not perform large architectural rewrites unless the task explicitly calls for them.

---

## 4.6 `schemas/`

Schemas are part of the runtime contract.

Every new machine-readable artifact or material shape change must be schema-validated.

Do not loosen schemas simply to make invalid data pass tests.

---

## 4.7 `tests/`

Tests are security controls, not cosmetic CI.

A bug fix must normally include a regression test.

Do not delete, skip, or weaken a test merely because a new implementation fails it unless the previous behavior is explicitly proven wrong and the test is updated to assert the correct invariant.

---

## 4.8 `development/`

Benchmarks, model-knowledge fixtures, maintenance data, and development-only evaluation artifacts belong here.

Do not make production runtime correctness depend on developer-only benchmark data unless explicitly designed.

---

# 5. Analyzer integration rules

This repository depends heavily on Slither and Solidity build tooling. Treat third-party API assumptions carefully.

## 5.1 Slither object shapes

Do not guess Slither API shapes.

When consuming objects such as:

- `Function`;
- `InternalCall`;
- `HighLevelCall`;
- `LibraryCall`;
- `LowLevelCall`;
- `SolidityCall`;
- compilation units;
- source mappings;

verify the pinned Slither API and add a regression test using real Slither objects.

Do not write only synthetic dictionary tests for analyzer integration.

---

## 5.2 Real integration fixtures

For functionality derived from analyzer output, prefer at least one real Solidity fixture that exercises the actual analyzer.

Examples:

- call graph;
- inheritance;
- modifiers;
- storage writes;
- compilation closure;
- compiler versions;
- low-level calls;
- delegatecall;
- external dependencies.

Synthetic fixtures are useful for edge cases but must not replace all real integration coverage.

---

## 5.3 Analyzer uncertainty

If Slither cannot resolve a dynamic target, do not fabricate a concrete callee.

Represent unresolved edges explicitly.

Source code remains authoritative.

---

# 6. Code-index rules

The code index exists to reduce model context and improve navigation.

It is NOT proof of reachability or safety.

Requirements:

- stable, collision-safe function identity;
- deterministic ordering;
- clear caller/callee semantics;
- no silent ambiguity resolution;
- bounded graph expansion;
- source-range references where available;
- unresolved dynamic calls remain unresolved;
- local-variable writes must not be mislabeled as storage writes;
- host-specific absolute paths must not become portable identity when avoidable.

If code-index generation or validation fails:

- do not consume the invalid index;
- do not convert the failure into a clean audit;
- fall back to source inspection where possible;
- surface navigation degradation clearly.

---

# 7. Compilation and scope rules

The distinction between audit scope and build/compilation root is intentional.

Do not collapse them.

## 7.1 Audit scope

Defines what the auditor is responsible for reviewing.

## 7.2 Build root

Defines the compilation context necessary to analyze the audit scope.

A dependency may be outside the audit scope but still affect the compilation digest.

---

## 7.3 Compilation closure

Prefer the actual compiler/Slither compilation closure over a broad filesystem guess.

If the exact closure is known:

- hash the exact compiled inputs.

If exact closure is unavailable:

- use a conservative fallback;
- mark the fallback explicitly.

If an observed compiled input falls outside the declared build root:

- do not silently omit it;
- fail closed or include it through an explicitly supported external-input identity mechanism.

Resolve symlinks before deciding whether a source is inside the build root.

---

# 8. Review-ledger rules

Review JSONL is append-only evidence.

Do not rewrite historical review events during normal operation.

## 8.1 Revision semantics

- first review revision for an ID starts at `1`;
- follow-up revisions must be contiguous;
- only valid transitions may be appended;
- a Proof revision must bind to the current review snapshot.

---

## 8.2 Concurrency

Multiple agents may work on independent Domains.

Ledger operations must therefore be process-safe.

Workers write only their own per-Domain shards and ledger; the global shard merge runs under an exclusive cross-process lock and must preserve exact-coverage semantics (no missing Domain, no duplicate canonical ID).

Do not introduce a platform where locking silently becomes a no-op.

If cross-platform locking differs by OS, tests must cover supported behavior.

---

## 8.3 Durability

When appending:

1. acquire the writer lock;
2. read current history;
3. calculate revision;
4. validate transition;
5. serialize complete JSON line(s);
6. write;
7. flush;
8. `fsync()` where practical;
9. release lock.

Never write half a JSON record.

---

# 9. Skill and prompt editing rules

Prompt changes can change audit behavior and must be treated like code changes.

## 9.1 Preserve role separation

Keep:

- Recon focused on evidence collection;
- Routing focused on conservative selection;
- Screen focused on triage;
- Deep Review focused on security reasoning;
- Proof focused on proving/disproving suspicious findings;
- Report focused on synthesis of confirmed results.

Do not blur stages merely to shorten the pipeline.

---

## 9.2 Avoid prompt duplication

Generic rules such as:

- verify reachable paths;
- uncertainty is not safety;
- confirmed findings require proof;

belong in centralized shared contracts.

Domain Skills should focus on domain-specific reasoning.

---

## 9.3 Do not optimize prompts by deleting safeguards

Prompt/context optimization is allowed only when:

- meaning is preserved;
- routing recall is preserved;
- evidence requirements are preserved;
- benchmark/regression tests stay green.

Measure token/byte savings separately from correctness.

---

## 9.4 Model profile defaults

The stage-model profile supports two providers (`codex`, `zcode`). Do not change default Codex stage-model assignments or reasoning effort unless the task explicitly asks for that change; the same applies to the default zcode worker assignments (controller stages on the main agent, `DOMAIN_CONTEXT` on `evm-audit-worker-flash`, `SCREEN`/`DEEP_REVIEW` on `evm-audit-worker-deep`, `PROOF` on `evm-audit-worker-proof`). ZCode thinking levels are model-specific: GLM-5.3 supports `low`/`high`/`max`; GLM-5.3-Flash is `default` (unpinned). Do not invent levels ZCode does not document.

A zcode stage entry's `agent`, `model`, and `thought_level` must match the full execution contract pinned in the shipped worker agent template, and the agent must be allowed to execute that stage; the validator rejects mismatches. A worker dispatch must never cross a stage boundary into a different execution contract.

Model profile configuration is execution metadata, not security lineage.

Do not claim that the runtime actually switches models unless a real supported runtime mechanism performs the switch. The controller never switches its own active model or thinking level; zcode controller-stage entries are handoff recommendations. ZCode worker dispatch through the Master Skill's orchestration is a real dispatch mechanism; Codex runs the same workflow sequentially.

---

# 10. Knowledge-base maintenance rules

When modifying canonical checks:

## Required qualities

Each check should be:

- specific;
- actionable;
- non-duplicative;
- technically correct;
- scoped to a real vulnerability/invariant;
- usable by an auditor without relying on vague prose.

Avoid generic filler such as repeatedly restating the same reachable-path rule in every check.

Use shared policy fields for generic FP/proof rules where available.

---

## Deduplication

Do not delete two similar checks solely because titles overlap.

Before merging checks, compare:

- trigger;
- affected invariant;
- exploit path;
- false-positive conditions;
- proof strategy;
- applicable protocols/chains;
- historical source/provenance.

Keep materially different failure modes separate.

---

## Provenance

Preserve provenance and knowledge lineage.

Do not fabricate source attribution.

If upstream material is updated, keep enough metadata to reproduce what was incorporated.

---

# 11. Schema/versioning rules

Artifact versions are explicit compatibility boundaries.

When changing a machine-readable artifact:

1. decide whether the old shape remains compatible;
2. update schema;
3. update runtime constant;
4. update generator;
5. update validator;
6. update tests;
7. update docs;
8. update fixtures;
9. update migration/compatibility behavior if required.

Do not "accept both" indefinitely without an explicit compatibility policy.

Do not dynamically trust arbitrary schema versions supplied by input files.

---

# 12. Error-handling rules

Security-sensitive failures should prefer clear fail-closed behavior.

Good:

```text
compiled source is outside build_root; choose a build_root containing the complete compilation closure
```

Bad:

```text
something failed, continuing with defaults
```

Do not catch broad exceptions and silently downgrade authoritative evidence.

Broad catches are acceptable at CLI boundaries to produce a clean error message, but internal helpers should preserve actionable error context.

---

# 13. Performance and token-efficiency rules

Performance improvements are welcome, but measure them correctly.

Track separately:

- runtime duration;
- analyzer invocations;
- artifact byte size;
- model-facing context size;
- number of selected checks;
- routing recall;
- known false negatives.

A lower candidate count is not automatically an improvement.

A smaller prompt is not automatically an improvement.

Never optimize solely against byte/token metrics.

---

# 14. Testing requirements

Before completing a material change, run the applicable full validation suite.

Minimum:

```bash
python3 scripts/generate_checklists.py --check
python3 scripts/validate_checklists.py --strict
python3 scripts/benchmark_routing.py
python3 -m unittest discover -s tests -v
git diff --check
```

When runtime dependencies are not installed:

```bash
python3 -m pip install -r requirements-runtime.lock
```

When changing Recon / Slither / compilation logic, also run real analyzer-backed tests.

When changing semantics covered by the scheduled heavy quality workflow, run where available:

```bash
python3 scripts/benchmark_routing.py --e2e

bash tests/semantics/test_eip6780_differential.sh paris
bash tests/semantics/test_eip6780_differential.sh cancun

python3 scripts/knowledge_metrics.py --output /tmp/knowledge-metrics.json
```

Do not claim completion if required tests were not run. Report exactly which tests were run and which were not.

---

# 15. CI rules

Normal PR CI should protect fast, high-value correctness properties.

Scheduled CI may contain heavier semantic and benchmark work.

Do not move every expensive task into pull-request CI without considering maintenance cost.

GitHub Actions dependencies should remain pinned to immutable revisions where practical.

Do not replace pinned action SHAs with floating tags without explicit reason.

---

# 16. Dependency rules

Runtime dependencies must remain pinned in `requirements-runtime.lock`.

When adding or upgrading a dependency:

- explain why it is needed;
- pin it;
- assess whether it changes analyzer behavior;
- run regression tests;
- update build/provenance expectations if relevant.

Avoid adding a large dependency for functionality that can be implemented safely with the standard library.

---

# 17. Refactoring and maintainability rules

Maintainability is a first-class engineering requirement, but it must never weaken the security invariants in this file.

## 17.1 Prefer maintainable implementations

When changing code, prefer the smallest coherent design that is easy for a future maintainer to understand, verify, test, and modify safely.

Prefer:

- clear responsibility boundaries over convenience-driven coupling;
- small, cohesive functions/modules over large multi-purpose implementations;
- existing abstractions and repository conventions over parallel one-off patterns;
- explicit data flow, state transitions, and invariants over hidden behavior;
- descriptive names over clever or overly compressed code;
- pure or side-effect-light helpers where practical;
- stable interfaces and backward-compatible evolution where safe;
- deterministic behavior and serialization;
- regression tests close to the behavior they protect;
- comments that explain non-obvious intent, constraints, or security reasoning rather than restating the code.

Avoid:

- unnecessary abstraction or indirection;
- speculative generalization for hypothetical future requirements;
- duplicated business/security logic across multiple modules;
- magic constants or implicit conventions when a named constant/type/helper is clearer;
- hidden mutable global state;
- large functions that mix parsing, validation, state mutation, persistence, and presentation when those responsibilities can be separated cleanly;
- compatibility shims with no explicit removal or support policy;
- broad rewrites when a local, well-tested change solves the task safely.

Before introducing a new abstraction, helper, dependency, configuration field, or compatibility layer, check whether an existing repository mechanism already serves that responsibility. Reuse or extend it when doing so keeps ownership clear and does not distort the abstraction.

Do not optimize for fewer lines of code at the expense of readability, testability, debuggability, or explicit security semantics.

## 17.2 Preserve local design consistency

Before editing a subsystem:

1. inspect the nearby implementation and tests;
2. identify the existing ownership boundary and data flow;
3. determine whether the file is generated or authoritative;
4. follow established naming, typing, error-handling, serialization, and testing patterns unless there is a concrete reason to change them;
5. keep unrelated cleanup out of the patch.

If the existing design is poor but not necessary to change for the task, do not silently redesign it. Record the concern as deferred work when material.

## 17.3 Clarify material uncertainty before coding

If an uncertainty could materially change the architecture, public behavior, security semantics, compatibility, data model, dependency choice, or scope of the requested change, ask the user for clarification before implementing that decision.

Examples that normally require clarification:

- two plausible interpretations of the requested behavior would produce different user-visible or security-relevant results;
- a change may break an existing public CLI/API/artifact/schema contract;
- a migration or backward-compatibility policy is not specified;
- the correct owner/module for substantial new behavior is ambiguous;
- adding a new third-party dependency is optional rather than clearly necessary;
- the requested change conflicts with an invariant or another explicit repository rule;
- a destructive migration, large rewrite, or removal of supported behavior appears necessary;
- the task depends on a product/security assumption that cannot be established from repository evidence.

Do not interrupt the user for low-impact implementation details when the repository conventions, tests, or surrounding code provide a safe and obvious default. In those cases, choose the most conservative maintainable option and state the assumption in the completion report if it is material.

Never resolve material ambiguity by silently choosing the fastest implementation.

## 17.4 Refactoring discipline

Avoid "cleanup" refactors that mix with security-sensitive behavior changes.

Preferred order:

1. add failing regression test;
2. fix behavior;
3. verify;
4. refactor behind green tests.

Do not combine:

- routing semantic changes;
- schema migrations;
- large directory moves;
- prompt rewrites;
- dependency upgrades;

into one oversized change unless the task specifically requires it.

---

# 18. Generated-file rules

Before editing a file, determine whether it is generated.

If generated:

- locate the source generator;
- change the source;
- regenerate;
- do not hand-maintain generated output.

Typical generated artifacts may include per-Domain checklist views and runtime Markdown.

Use comments/headers such as "GENERATED" as authoritative signals where present.

---

# 19. Git and patch discipline

Keep diffs reviewable.

Do not:

- reformat the entire 2+ MB canonical registry for a small content fix;
- reorder large JSON collections without need;
- rewrite unrelated docs;
- rename many files during a bug fix;
- include temporary audit run output;
- commit local caches or build artifacts.

Prefer deterministic serialization so identical data does not create noisy diffs.

---

# 20. Security review of repository changes

Before finishing, inspect the patch for repository-specific failure modes.

Ask:

- Can this change turn unknown into absent?
- Can it reduce routing recall?
- Can stale artifacts now be reused?
- Can an invalid optional artifact accidentally affect clean completion?
- Can concurrency lose a review record?
- Can a generated view diverge from its machine identity?
- Can a change to dependencies escape the compilation digest?
- Can duplicate function/contract names overwrite graph entries?
- Can a heuristic be mistaken for evidence?
- Can report generation include unresolved findings?
- Can a previous valid deliverable be destroyed before replacement succeeds?
- Did a prompt optimization delete domain-specific review guidance?

If the answer might be yes, add a regression test before completion.

---

# 21. Task completion report

When Codex finishes a substantial repository change, return a concise engineering report with:

1. summary of behavior changed;
2. files changed;
3. root cause of each bug fixed;
4. tests added;
5. schema/version changes;
6. compatibility notes;
7. commands executed;
8. test results;
9. benchmark/routing-recall changes;
10. generated files changed;
11. remaining known risks;
12. deferred work.

Do not say "all tests pass" unless the full claimed test set was actually executed.

---

# 22. Default decision policy

When multiple implementations are possible, prefer the option that is:

1. fail-closed;
2. easier to verify;
3. deterministic;
4. explicit about uncertainty;
5. maintainable and easy to understand locally;
6. cohesive with existing repository architecture and conventions;
7. backward-compatible where safe;
8. low-noise in generated diffs;
9. easy to cover with regression tests;
10. minimal in scope without becoming a brittle special case.

If two reasonable options have materially different architectural, compatibility, or security consequences and the repository does not establish which one is intended, ask the user before choosing.

For this repository, correctness and security audit integrity take precedence over convenience. Subject to those constraints, prefer long-term maintainability over short-term implementation speed.
