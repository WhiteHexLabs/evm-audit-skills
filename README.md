# EVM Audit Skills

A deterministic, evidence-gated EVM smart-contract audit Skill suite for
Codex and ZCode.

It combines evidence-backed Project Analysis and Context Analysis,
candidate-only Deep Audit, proof-gated findings, and confirmed-only reporting.

- `evm-audit-master` is the default entry point.
- Evidence-backed Project Analysis routing keeps uncertainty visible.
- Only proven `CONFIRMED` findings reach the Final Report.

## Quick Start

### 1. Install and make the Skills discoverable

Clone the suite and run the installer with your agent's name (`zcode` or
`codex`):

```bash
git clone https://github.com/iavl/evm-audit-skills-standalone
cd evm-audit-skills-standalone
./install.sh zcode
```

For an existing checkout, run `./install.sh` from that directory instead.
The script symlinks each Skill package into the agent's skills directory, is
safe to re-run, and verifies the result; it refuses to replace entries it did
not create. See [QUICKSTART.md](QUICKSTART.md) for the focused start guide.

### 2. Open the target repository

Open the local smart-contract project, or provide its repository URL.

### 3. Ask the agent to run the Master Skill

```text
Audit this smart-contract repository using evm-audit-master:
https://github.com/owner/repo
```

GitHub issue creation is opt-in. Ask the agent to file confirmed Medium+
findings only when you explicitly want issue creation.

## Stage Models

The default stage-model profile assigns different models to different audit
phases, with two provider vocabularies. Codex default:

| Public phase | Default Codex model |
| --- | --- |
| Project Analysis | Luna · Max |
| Context Analysis | Terra · Medium |
| Initial Review | Terra · High |
| Deep Audit | Sol · High |
| Vulnerability Validation | Sol · Max |
| Final Report | Terra · Medium |

ZCode default: controller phases (Project Analysis, Domain Resolution, Final
Report) run on the main agent (GLM-5.3); Domain Context runs on
`evm-audit-worker-flash` (GLM-5.3-Flash); Initial Review, Deep Audit, and
Vulnerability Validation run on `evm-audit-worker-deep` (GLM-5.3).

Use the defaults unless you explicitly customize the profile. It is confirmed
once at audit startup. See the
[Model Profile documentation](docs/codex-model-profile.md) for details.

## Parallel Orchestration

On ZCode, the Master Skill can fan the middle of the pipeline out to one
worker agent per Domain (custom agent types pinned to the models above),
with a controller-owned merge barrier and confirmed-only fan-in. On Codex
the same workflow runs sequentially in one session — the runtime provides no
sub-agent dispatch, and no parallelism is simulated. Either way the evidence
gates are identical. See
[Sequential and orchestrated execution](docs/audit-workflow.md).

## How It Works

Instead of asking one model to read the entire codebase and guess
vulnerabilities, the audit progressively narrows a large security checklist
into a small set of evidence-backed findings.

```text
Project Analysis
→ Context Analysis
→ Initial Review
→ Deep Audit
→ Vulnerability Validation
→ Final Report
```

```text
                      all security checks
                              │
                              ▼
                    Project Analysis
                              │
                              ▼
                     Context Analysis
                              │
                              ▼
                       relevant checks
                              │
                              ▼
                      Initial Review
                         /        \
              proven irrelevant   candidate
                                     │
                                     ▼
                              Deep Audit
                                 /       \
                              safe     suspicious
                                          │
                                          ▼
                          Vulnerability Validation
                                      /        \
                                   safe      confirmed
                                               │
                                               ▼
                                         Final Report
```

| Public phase | Internal stage ID | What it does |
| --- | --- | --- |
| **Project Analysis** | `RECON`, `ROUTING` | Understands the audit scope, build environment, dependencies, protocol features, and applicable security checks. |
| **Context Analysis** | `DOMAIN_RESOLUTION`, `DOMAIN_CONTEXT` | Resolves protocol-specific facts such as oracle usage, permissions, assets, and liquidation assumptions. |
| **Initial Review** | `SCREEN` | Separates checks that are provably irrelevant from checks that require deeper investigation. |
| **Deep Audit** | `DEEP_REVIEW` | Analyzes candidate vulnerabilities against real code paths, state transitions, invariants, and economic assumptions. |
| **Vulnerability Validation** | `PROOF` | Uses traces, invariants, calculations, or PoCs to prove or disprove suspicious issues. |
| **Final Report** | `REPORT` | Re-validates the audit state and reports only confirmed findings. |

The key rule throughout the pipeline is:

```text
uncertain → investigate further
uncertain ≠ safe
```

This prevents incomplete analysis from silently becoming a clean audit. For a
detailed walkthrough of every phase, see [Audit Workflow](docs/audit-workflow.md).

## Safety Guarantees

```text
UNKNOWN ≠ ABSENT

incomplete compilation
→ cannot establish trusted absence

Initial Review (`SCREEN`)
→ CANDIDATE or NOT_APPLICABLE_CONFIRMED

SUSPICIOUS
→ Vulnerability Validation (`PROOF`) required

CONFIRMED
→ Final Report only

stale artifacts
→ rejected
```

Uncertainty is never silently filtered, incomplete artifacts cannot claim a
clean audit, and stale review artifacts are not reused. See
[Audit Runtime](docs/audit-runtime.md) for implementation-level details.

## Audit Output

Runs are written to an external sibling such as `../<repo>-audit-run/`, never
inside the target or build root. `AUDIT-REPORT.md`
contains only `CONFIRMED` findings; supporting Project Analysis, Context
Analysis, Initial Review, Deep Audit, and Vulnerability Validation artifacts
remain beside it.

## Using Individual Domain Skills

Use `evm-audit-master` by default. When the audit scope is already known, use
an individual Domain Skill from the [Skill Catalog](skills/README.md).

## Development & Internals

For maintainers, contributors, and advanced users who want to understand or
extend the repository.

### Architecture & Documentation

- [Audit Workflow](docs/audit-workflow.md)
- [Architecture](docs/architecture.md)
- [Audit Runtime](docs/audit-runtime.md)
- [Project Analysis details](docs/recon-and-routing.md)
- [Codex Model Profile](docs/codex-model-profile.md)
- [Knowledge Evidence](docs/knowledge-evidence.md)
- [Knowledge Lineage](docs/knowledge-lineage.md)

### Repository Layout

- `skills/` — directly usable Skill packages
- `data/` — canonical security knowledge
- `domains/` — Domain configuration
- `scripts/` — audit runtime and maintenance tooling
- `evm_audit_runtime/` — shared pure runtime logic
- `schemas/` — artifact schemas
- `docs/` — architecture and runtime documentation
- `development/` — benchmarks and maintenance fixtures
- `tests/` — runtime and regression tests

### Knowledge Base

`data/canonical-checks.json` is the authoritative checklist source. Generated
Skill Markdown is derived output and should not be edited directly. See
[Knowledge Maintenance](docs/knowledge-maintenance.md) for editing and
generation rules.

### Development & Validation

See the [Development Guide](development/README.md).

## License

The repository is licensed under the MIT License in [`LICENSE`](LICENSE).
Source provenance and pinned upstream revisions are documented in
[`docs/knowledge-lineage.md`](docs/knowledge-lineage.md).
