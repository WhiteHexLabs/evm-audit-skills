# Project Analysis (`RECON`, `ROUTING`)

Run Project Analysis against the audit scope and its distinct compilation/build root. Its Feature Map v5 records the
scope digest, compilation-input digest, compilation coverage, analyzed files,
tool versions, actual compiler versions, and a scope-bound `recon_context`. The
map also classifies each presence evidence item as `AUDIT_SCOPE`, `DEPENDENCY`,
or `UNKNOWN`; dependency-only surface evidence remains Deferred unless a Domain
explicitly opts into it. The map uses
`PRESENT`, `ABSENT_CONFIRMED`, or `UNKNOWN`.

Selector rejects a missing or mismatched scope before filtering. Incomplete
compilation is accepted in conservative degraded mode: presence evidence is
usable, every claimed absence is downgraded to `UNKNOWN`, and
`recon_quality.mode` records the reduced coverage. Add
`--require-complete-compilation` for strict fail-fast behavior. `UNKNOWN`
remains selected. `ABSENT_CONFIRMED` is valid only after complete Slither
coverage and acceptable typed evidence. Evidence for confirmed states uses
`kind`, `location`, and `reason`; absence is accepted only when the feature's
`absence_policy` allows that evidence kind.

## Project Analysis: Recon (`RECON`)

Build the initial Feature Map from Slither's AST/IR, then supplement remaining
`UNKNOWN` features from deployment evidence. Feature-to-detector mapping lives
in `data/feature-detectors.json`; Python only implements the named structural
detectors:
Only `uses-assembly`, `uses-msg-value`, and `uses-payable` are currently
absence-capable. Their node/function traversal is explicit and complete for
the scoped compilation; all other detectors remain presence-only because a
negative keyword or partial structural traversal is not a sound protocol
absence proof.

```bash
python3 scripts/recon.py <target-project-or-solidity-file> --audit-root <audit-scope> \
  --build-root <project-root> \
  --output recon-features.json --code-index-out code-index.json
```

当一个工作区包含互不兼容的 Solidity 编译配置时，使用受校验的编译计划逐目标串行运行 Recon，并把结果绑定到同一个 Feature Map：

```bash
python3 scripts/recon.py <workspace> --audit-root <workspace> --build-root <workspace> \
  --compilation-plan compilation-plan.json --output recon-features.json
```

计划的 `units` 为每个编译目标声明 `target`、负责的 `scope_roots`，以及可选的
`foundry_profile` 和 `expected_compiler_versions`。目标失败、配置未验证或 scope
文件未覆盖时，Feature Map 保持 `CONSERVATIVE_DEGRADED`；不能把其它目标的成功
当作缺失证据。`recon_context.compilation_targets`、`compilation_plan_digest` 和
`compilation_targets_digest` 记录覆盖与身份。计划不接受自由 shell 命令，Foundry
profile 只通过 `FOUNDRY_PROFILE` 和现有 `foundry.toml` 选择。

## Project Analysis: Routing (`ROUTING`)

Project Analysis routing v8 applies environment, Domain, and canonical feature gates. Domains
are `SELECTED`, `DEFERRED`, or `FILTERED`; an `UNKNOWN` Domain is Deferred with
a small screening card, and only confirmed absence or confirmed environment
mismatch can filter. Related Domains never auto-expand.

```bash
python3 scripts/select_checks.py --feature-map recon-features.json --target-root <target-repo> \
  --chain-id <id> --chain-family <family> --execution-environment <environment> \
  --fork-block <block> --compiler-version <version> --evm-fork <fork> \
  --manifest-out routing/manifest.json --context-out context.json \
  --environment-out routing/environment-context.json \
  --format json
```

The v8 manifest records selected, Deferred, and filtered Domain/check stages;
registry, source, dependency, build-config, and compilation fingerprints; and
evidence-backed environment facts. It also snapshots immutable required-context
definitions; resolution state lives in `domain-context.json`. `fork_block` is
reproducibility metadata, not hardfork inference.

Automatic build-root discovery stops at the acquisition boundary: the audit
root for standalone calls, or an explicit `--acquisition-root`. A wider
compilation context must be supplied explicitly with `--build-root`; this
prevents an ambient parent project or HOME-level `package.json` from silently
changing the compilation fingerprint. The audit scope can remain one file, but
the compilation fingerprint includes Solidity sources and build/remapping
configuration from the selected build root. Generated directories remain excluded;
top-level dependency roots default to `lib` and `node_modules`, while
`src/lib/` remains first-party. Use `--include lib/MyProtocol.sol` to audit an
explicit first-party path under a default dependency root, and repeat
`--dependency-root` when a project uses a different dependency layout. Those
effective policies are recorded in Project Analysis and therefore change routing identity.

Canonical predicates use `all_of` / `any_of` / `none_of`. Only a curated
predicate can filter on `FALSE`; an inferred `FALSE` becomes `UNKNOWN` and
remains selected. This allows keyword inference to improve recall without
proving non-applicability.

The optional `code-index.json` is a compact Slither-derived navigation hint
bound to the source and compilation digests. Normal audit queries must bind it
to the run:

```bash
python3 scripts/code_context.py --run-dir <run-dir> --function <function-id> \
  --include-callers --include-callees --depth 2 --max-nodes 25 --max-edges 200
```

Development-only standalone inspection requires `--allow-unbound-index`.
Query v5 returns one `selected_edges` array with explicit
`expansion.callers`/`expansion.callees`; unresolved calls remain in
`unresolved_edges` because uncertainty is not absence. Expansion is
deterministic and cycle-safe; verify every returned range against source
because the index is never authoritative. `edge_count`/`unique_edge_count`,
`returned_edge_count`, and `serialized_edge_count` expose unique and serialized
counts, with the serialized count hard-bounded by `max_edges`.
`edges_truncated` and `truncated` mean the graph is incomplete and require
direct source inspection. When the edge cap applies, deterministic priority is
unresolved edges, selected edges, then boundary edges; each category is already
stably sorted. The actual compilation closure is used for the compilation
digest when Slither exposes it, with the conservative full-source fallback
otherwise; `recon_quality.compilation_provenance` records which mode was used.
Older Feature Maps without multi-target fields are treated as the
conservative fallback for navigation/lineage purposes and never upgraded to
exact-closure provenance.

The manifest is immutable; `render_runtime.py` never re-runs routing. Initial
Review (`SCREEN`) cards can promote candidates to Deep Audit but never filter
uncertainty. Context Analysis artifacts and `screen-results.json` are
separately evidenced snapshot-bound artifacts. A Deferred `UNKNOWN` or required
Domain Context `UNKNOWN` blocks Deep Audit and completion.
