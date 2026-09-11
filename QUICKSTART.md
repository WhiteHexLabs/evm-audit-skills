# Quick Start

## 1. Install the suite

Clone the suite and run the installer with your agent's name (`zcode` or
`codex`):

```bash
git clone https://github.com/iavl/evm-audit-skills-standalone
cd evm-audit-skills-standalone
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
(`evm-audit-worker-deep` / `evm-audit-worker-flash`, auto-installed from the
suite on first use; a session restart is required to register them). On Codex
the same audit runs sequentially in one session. The evidence gates are
identical in both modes.

## 3. Read the artifacts

Choose an external sibling run directory, for example:

```text
../<repo>-audit-run/
```

The target/build tree is authoritative input and the run directory is mutable
authoring state; equal or descendant run paths are rejected.

Open `AUDIT-REPORT.md` for the final findings. Supporting Project Analysis,
Context Analysis, Initial Review, Deep Audit, and Vulnerability Validation
evidence is kept beside it; only `CONFIRMED` records enter the Final Report.
Required context and unresolved Deferred Domains prevent a clean completion.
