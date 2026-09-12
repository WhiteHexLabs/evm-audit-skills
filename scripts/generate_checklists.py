#!/usr/bin/env python3
"""Render runtime Markdown views from the canonical JSON registry.

The generator is deliberately knowledge-free: it never repairs, infers, or
rewrites canonical records. Normal maintenance edits
``data/canonical-checks.json`` and regenerates the derived views.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "data" / "canonical-checks.json"


def load_registry(path: Path = REGISTRY_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_domains(root: Path = ROOT) -> dict[str, dict[str, Any]]:
    domains: dict[str, dict[str, Any]] = {}
    for path in sorted((root / "domains").glob("*.json")):
        if path.name == "domain.schema.json":
            continue
        domain = json.loads(path.read_text(encoding="utf-8"))
        if domain["id"] in domains:
            raise ValueError(f"duplicate domain id: {domain['id']}")
        domains[domain["id"]] = domain
    return domains


def one_line(value: Any) -> str:
    if isinstance(value, list):
        return " ".join(str(part).strip() for part in value if str(part).strip())
    return str(value).strip()


def render_provenance(item: dict[str, Any]) -> str:
    rendered: list[str] = []
    for entry in item.get("provenance", []):
        label = entry.get("label", "unknown source")
        url = entry.get("url")
        rendered.append(f"[{label}]({url})" if url else str(label))
    return "; ".join(dict.fromkeys(rendered)) or "Canonical registry entry"


def render_full_item(item: dict[str, Any]) -> list[str]:
    metadata = f"_({item['type']}; {item['confidence']})_"
    description = one_line(item["description"])
    lines = [f"- [ ] **[{item['canonical_id']}] {item['title']}** {metadata}: {description}"]
    seen = {description}
    for label, field in (
        ("Trigger", "trigger"),
        ("Risk", "risk"),
        ("Detection", "detection"),
        ("Specific FP", "false_positive_gates"),
        ("Specific proof", "proof"),
    ):
        if field == "false_positive_gates" and item.get("fp_policy") != "specific":
            continue
        if field == "proof" and item.get("proof_policy") != "specific":
            continue
        value = one_line(item[field])
        if value and value not in seen:
            lines.append(f"  - **{label}:** {value}")
            seen.add(value)
    lines.append(f"  - **Provenance:** {render_provenance(item)}")
    if item.get("related"):
        lines.append(f"  - **Related:** {', '.join(item['related'])}")
    if item.get("origin_notes"):
        lines.append(f"  - **Source detail:** {one_line(item['origin_notes'])}")
    if item.get("notes"):
        lines.append(f"  - **Notes:** {one_line(item['notes'])}")
    return lines


def render_alias(item: dict[str, Any]) -> list[str]:
    return [
        f"- [ ] **[{item['canonical_id']}] {item['title']}**: Shared canonical check; "
        f"apply the primary definition and evidence requirements for `{item['primary_domain']}`."
    ]


def render_domain(registry: dict[str, Any], config: dict[str, Any]) -> str:
    domain = config["id"]
    items = [item for item in registry["checks"] if domain in item.get("domains", [])]
    sections = list(dict.fromkeys(item.get("section", "Uncategorized") for item in items))
    output = [
        "<!-- GENERATED FILE: source is ../../../data/canonical-checks.json; do not edit by hand. -->",
        f"# {config['checklist_title']}",
        "",
        "Each entry has a stable canonical ID, a type/confidence label, and an explicit evidence path. Shared entries are deduplicated by canonical ID.",
        "Global FP/proof obligations live in the Review Contract; only check-specific gates and proofs are repeated below.",
        "",
    ]
    for section in sections:
        output.extend([f"## {section}", ""])
        for item in items:
            if item.get("section") != section:
                continue
            output.extend(render_full_item(item) if item.get("primary_domain") == domain else render_alias(item))
            output.append("")
    return "\n".join(output).rstrip() + "\n"


def render_skill(config: dict[str, Any]) -> str:
    domain = config["id"]
    related = ", ".join(f"`{value}`" for value in config["related_domains"]) or "none"
    required_context = "\n".join(f"- `{value['key']}`: {value['description']}" for value in config["required_context"])
    review_requirements = "\n".join(f"- {value}" for value in config["review_requirements"])
    return f"""---
name: {domain}
description: {config['description']} Consume routed selected-check bodies at runtime.
---
# {config['name']}

## Review Focus

{config['description']}

## Required Context

{required_context}

## Review Requirements

{review_requirements}

## Runtime Modes

Standalone: `python3 <suite-root>/scripts/audit_run.py init <target> --run-dir <run-dir> --domain {domain}`. Run `next` until the next template or runtime view is ready, resolve only the generated evidence-bound templates, then use `status` and `report`.

Orchestrated: consume the Master-provided immutable routing artifacts and Screen/Deep views. Never rerun Recon or Selector in orchestrated mode. When running as a dispatched Domain worker (parallel orchestration), write only this Domain's shards (`scripts/domain_shards.py write-context-shard` / `write-screen-shard`) and this Domain's append-only ledger (`reviews/review-{domain}.jsonl` via `scripts/review_ledger.py --append-record`); never edit shared global run files — the merge barrier and report publication belong to the controller.

Apply the Master contract at `<suite-root>/skills/evm-audit-master/references/check-review-contract.runtime.md` for global tri-state, reachable-path, proof-gating, and confirmed-only reporting rules. Consume only the routed check bodies; do not load the full canonical registry or generated checklist.

Related Domains (advisory only; never auto-expand direct scope): {related}.

## Maintenance View
- `references/checklist.md` is a generated human-readable reference view.
"""


def render_domain_catalog(registry: dict[str, Any], domains: dict[str, dict[str, Any]]) -> str:
    lines = [
        "<!-- GENERATED FILE: source is domains/*.json and data/canonical-checks.json; do not edit by hand. -->",
        "# Domain Catalog",
        "",
        "| Domain | Purpose | Surface features | Related domains | Runtime entries |",
        "|---|---|---|---|---:|",
    ]
    for domain, config in domains.items():
        count = sum(domain in check.get("domains", []) for check in registry["checks"])
        features = ", ".join(f"`{value}`" for value in config["surface_features"])
        related = ", ".join(f"`{value}`" for value in config["related_domains"]) or "—"
        lines.append(f"| `{domain}` | {config['description']} | {features} | {related} | {count} |")
    return "\n".join(lines) + "\n"


def generated_outputs(registry: dict[str, Any], root: Path) -> dict[Path, str]:
    domains = load_domains(root)
    outputs: dict[Path, str] = {}
    for domain, config in domains.items():
        outputs[root / "skills" / domain / "references" / "checklist.md"] = render_domain(registry, config)
        outputs[root / "skills" / domain / "SKILL.md"] = render_skill(config)
    outputs[root / "skills" / "evm-audit-master" / "references" / "domains.md"] = render_domain_catalog(registry, domains)
    return outputs


def write_outputs(registry: dict[str, Any], root: Path) -> None:
    for path, content in generated_outputs(registry, root).items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def check_outputs(registry: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    for path, expected in generated_outputs(registry, root).items():
        if not path.exists():
            errors.append(f"missing generated file: {path}")
        elif path.read_text(encoding="utf-8") != expected:
            errors.append(f"generated file is stale: {path}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--check", action="store_true", help="verify generated Markdown without writing files")
    args = parser.parse_args(argv)
    root = args.root.resolve()

    try:
        registry = load_registry(root / "data" / "canonical-checks.json")
        errors = check_outputs(registry, root)
        if args.check:
            for error in errors:
                print(f"ERROR: {error}", file=sys.stderr)
            print(f"canonical_checks={len(registry.get('checks', []))} generated_errors={len(errors)}")
            return 1 if errors else 0
        write_outputs(registry, root)
        print(f"canonical_checks={len(registry.get('checks', []))} generated={len(load_domains(root))}")
        return 0
    except (OSError, json.JSONDecodeError, KeyError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
