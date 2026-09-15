# Quick Start

## 1. Install the suite

Clone the suite and run the installer with your agent's name (`zcode` or
`codex`):

```bash
git clone https://github.com/iavl/evm-audit-skills
cd evm-audit-skills
./install.sh zcode
```

For an already checked out suite, run `./install.sh` from that directory
instead.

## 2. Start the audit

Use `evm-audit-master` unless you have a specific Domain in mind. Give your
agent (Codex or ZCode) a local Solidity repository or repository URL, for
example:

```text
Audit this Solidity repository with evm-audit-master: /path/to/project
```

On ZCode the master skill may fan Domain work out to parallel worker agents
(`evm-audit-worker-flash` / `evm-audit-worker-deep` / `evm-audit-worker-proof`,
installed into `~/.zcode/agents/` by `./install.sh zcode`; a new ZCode
session is required for the definitions to register). On Codex the same
audit runs sequentially in one session. The evidence gates are identical in
both modes.

## 3. Read the artifacts

Audit output lands inside the audited project by default:

```text
<repo>/.evm-auditor-work/
```

Pass `--output-dir <path>` at initialization for a custom location: relative
paths resolve against the project's build root, and external directories stay
supported (`--run-dir` remains a legacy alias). The authoritative source/build
inputs are immutable: the controller owns one explicitly managed output
subtree, which is excluded from audit scope discovery, compilation
fingerprints, source snapshots, and PoC build-tree copies. Using the project
root itself as the output directory is rejected.

Open `AUDIT-REPORT.md` for the final findings. Supporting Project Analysis,
Context Analysis, Initial Review, Deep Audit, and Vulnerability Validation
evidence is kept beside it; only `CONFIRMED` records enter the Final Report.
Required context and unresolved Deferred Domains prevent a clean completion.
