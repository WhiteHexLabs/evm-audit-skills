#!/usr/bin/env python3
"""Per-Domain shard authoring, stage merges, and readiness for orchestrated audits.

Domain workers never edit the shared run files directly. Each worker writes
its own shard (screen triage results or domain context) through this CLI,
which validates the shard against the routing manifest before it is stored.
The controller later merges shards into the authoritative global artifacts
under an exclusive cross-process lock, stage by stage:

- ``merge-context`` requires exact context shard coverage and writes
  ``reviews/domain-context.json``; it does not derive the review snapshot.
- ``merge-screen`` additionally requires an authoritative domain-context
  file, merges screen shards with exact selected-check coverage, writes
  ``reviews/screen-results.json``, and derives the review snapshot.
- ``merge`` is the compatibility convenience: context merge followed by
  screen merge. Both outputs are built and validated before either write,
  then replaced individually and atomically under one exclusive merge lock;
  the pair is not a transactional two-file atomic commit.

Shards bind to the routing snapshot: a shard authored against a different
snapshot is rejected at write time and again at merge time. ``status``
validates every present shard with the same contract as merge, and the
authoritative domain context with the same contract as ``merge-screen``, so
a present-but-invalid shard (or a stale/malformed authoritative context)
can never be reported as merge-ready.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from evm_audit_runtime.versions import (
    DOMAIN_CONTEXT_SHARD_VERSION,
    DOMAIN_CONTEXT_VERSION,
    SCREEN_RESULTS_VERSION,
    SCREEN_SHARD_VERSION,
)

try:
    from runtime_log import configure, error
except ImportError:  # pragma: no cover
    from scripts.runtime_log import configure, error

try:
    from audit_artifacts import (
        atomic_write_json,
        derive_review_snapshot_id,
        load_json,
        trusted_absence_policy,
        validate_domain_context,
        validate_domain_resolution,
        validate_non_applicability,
        validate_schema,
    )
except ImportError:  # pragma: no cover
    from scripts.audit_artifacts import (
        atomic_write_json,
        derive_review_snapshot_id,
        load_json,
        trusted_absence_policy,
        validate_domain_context,
        validate_domain_resolution,
        validate_non_applicability,
        validate_schema,
    )

try:
    from audit_run import paths
except ImportError:  # pragma: no cover
    from scripts.audit_run import paths

try:
    from render_runtime import (
        domain_context_template,
        screen_results_template,
        selected_entries,
        validate_manifest,
        validate_screen_results,
    )
except ImportError:  # pragma: no cover
    from scripts.render_runtime import (
        domain_context_template,
        screen_results_template,
        selected_entries,
        validate_manifest,
        validate_screen_results,
    )

try:
    from review_ledger import _ledger_lock
except ImportError:  # pragma: no cover
    from scripts.review_ledger import _ledger_lock


ROOT = Path(__file__).resolve().parents[1]


def _shard_dir(run_dir: Path) -> Path:
    return run_dir.resolve() / "reviews" / "shards"


def _shard_path(run_dir: Path, kind: str, domain: str) -> Path:
    return _shard_dir(run_dir) / f"{kind}-{domain}.json"


def _load_run(root: Path, run_dir: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None]:
    values = paths(run_dir.resolve())
    registry = load_json(root / "data" / "canonical-checks.json")
    manifest = load_json(values["manifest"])
    validate_manifest(root, manifest, registry)
    resolution: dict[str, Any] | None = None
    if manifest["deferred_domains"]:
        if not values["resolution"].exists():
            raise ValueError(
                "Deferred Domains require a completed domain-resolution.json before shard work; "
                "run the controller `next` step and resolve every Deferred Domain first"
            )
        resolution = load_json(values["resolution"])
        unresolved = validate_domain_resolution(root, manifest, resolution)
        if unresolved:
            raise ValueError(
                "domain resolution remains unresolved for: "
                + ", ".join(sorted(unresolved))
                + "; complete Domain Resolution before writing shards"
            )
    return manifest, values, resolution


def _screen_domains(manifest: dict[str, Any], resolution: dict[str, Any] | None) -> dict[str, list[str]]:
    domains: dict[str, list[str]] = {}
    for entry in selected_entries(manifest, domain_resolution=resolution):
        domains.setdefault(entry["owner_domain"], []).append(entry["canonical_id"])
    return {domain: sorted(ids) for domain, ids in domains.items()}


def _context_domains(manifest: dict[str, Any], resolution: dict[str, Any] | None) -> dict[str, list[str]]:
    eligible = {entry["domain"] for entry in manifest["selected_domains"]}
    if resolution is not None:
        eligible |= {
            domain
            for domain, resolved in resolution["domains"].items()
            if resolved["status"] == "PRESENT"
        }
    required = manifest["required_context_requirements"]
    return {
        domain: sorted(required[domain])
        for domain in sorted(eligible)
        if domain in required
    }


def _validate_screen_shard(
    root: Path,
    manifest: dict[str, Any],
    resolution: dict[str, Any] | None,
    shard: dict[str, Any],
) -> None:
    validate_schema(root, "screen-shard.schema.json", shard)
    if shard["routing_snapshot_id"] != manifest["routing_snapshot_id"]:
        raise ValueError(
            f"screen shard for {shard['owner_domain']!r} is bound to a different routing snapshot; "
            "re-run Routing and re-author the shard"
        )
    domain = shard["owner_domain"]
    expected = _screen_domains(manifest, resolution).get(domain, [])
    if not expected:
        raise ValueError(f"domain {domain!r} owns no selected checks in this run")
    results = shard["results"]
    ids = [entry["canonical_id"] for entry in results]
    if len(ids) != len(set(ids)):
        raise ValueError(f"screen shard for {domain!r} contains duplicate canonical IDs")
    unknown = set(ids) - set(expected)
    if unknown:
        raise ValueError(
            f"screen shard for {domain!r} contains checks it does not own: {', '.join(sorted(unknown))}"
        )
    if set(ids) != set(expected):
        missing = sorted(set(expected) - set(ids))
        raise ValueError(
            f"screen shard for {domain!r} is missing checks: {', '.join(missing)}"
        )
    recon_quality = manifest.get("feature_map", {}).get("recon_context", {}).get("recon_quality")
    for entry in results:
        if entry["result"] == "NOT_APPLICABLE_CONFIRMED":
            errors = validate_non_applicability(
                evidence=entry["evidence"],
                scope_complete=entry.get("scope_complete"),
                trusted_absence_policy=trusted_absence_policy(manifest, domain),
                recon_quality=recon_quality,
                label=entry["canonical_id"],
            )
            if errors:
                raise ValueError("; ".join(errors))


def _validate_context_shard(
    root: Path,
    manifest: dict[str, Any],
    resolution: dict[str, Any] | None,
    shard: dict[str, Any],
) -> None:
    validate_schema(root, "domain-context-shard.schema.json", shard)
    if shard["routing_snapshot_id"] != manifest["routing_snapshot_id"]:
        raise ValueError(
            f"context shard for {shard['owner_domain']!r} is bound to a different routing snapshot; "
            "re-run Routing and re-author the shard"
        )
    domain = shard["owner_domain"]
    required = manifest["required_context_requirements"].get(domain)
    if not required:
        raise ValueError(f"domain {domain!r} has no required context in this run")
    keys = set(shard["context"])
    if keys != set(required):
        missing = sorted(set(required) - keys)
        extra = sorted(keys - set(required))
        detail = []
        if missing:
            detail.append(f"missing keys: {', '.join(missing)}")
        if extra:
            detail.append(f"unexpected keys: {', '.join(extra)}")
        raise ValueError(f"context shard for {domain!r} does not cover its required keys ({'; '.join(detail)})")


def write_screen_shard(root: Path, run_dir: Path, domain: str, input_path: Path) -> dict[str, Any]:
    manifest, values, resolution = _load_run(root, run_dir)
    payload = load_json(input_path)
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list) or not results:
        raise ValueError("screen shard input must be an object with a non-empty results array")
    shard = {
        "schema_version": SCREEN_SHARD_VERSION,
        "routing_snapshot_id": manifest["routing_snapshot_id"],
        "owner_domain": domain,
        "results": results,
    }
    _validate_screen_shard(root, manifest, resolution, shard)
    target = _shard_path(run_dir, "screen", domain)
    atomic_write_json(target, shard)
    return {
        "command": "write-screen-shard",
        "owner_domain": domain,
        "shard_path": str(target),
        "result_count": len(results),
        "not_applicable_confirmed": sum(1 for entry in results if entry["result"] == "NOT_APPLICABLE_CONFIRMED"),
        "candidate_count": sum(1 for entry in results if entry["result"] == "CANDIDATE"),
    }


def write_context_shard(root: Path, run_dir: Path, domain: str, input_path: Path) -> dict[str, Any]:
    manifest, values, resolution = _load_run(root, run_dir)
    if domain not in _context_domains(manifest, resolution):
        raise ValueError(f"domain {domain!r} is not an eligible context Domain in this run")
    payload = load_json(input_path)
    context = payload.get("context") if isinstance(payload, dict) else None
    if not isinstance(context, dict) or not context:
        raise ValueError("context shard input must be an object with a non-empty context map")
    shard = {
        "schema_version": DOMAIN_CONTEXT_SHARD_VERSION,
        "routing_snapshot_id": manifest["routing_snapshot_id"],
        "owner_domain": domain,
        "context": context,
    }
    _validate_context_shard(root, manifest, resolution, shard)
    target = _shard_path(run_dir, "context", domain)
    atomic_write_json(target, shard)
    return {
        "command": "write-context-shard",
        "owner_domain": domain,
        "shard_path": str(target),
        "context_keys": sorted(context),
    }


def _guard_replace(existing_path: Path, new_value: dict[str, Any], template_value: dict[str, Any], force: bool, label: str) -> bool:
    """Allow replacing a missing file or the generated template; refuse anything else without --force."""
    if not existing_path.exists():
        return False
    existing = load_json(existing_path)
    if existing == new_value:
        return False
    if existing != template_value and not force:
        raise ValueError(
            f"{label} exists with content that is neither the generated template nor the merged shards; "
            "pass --force to replace it"
        )
    return True


def _build_context_merge(
    root: Path,
    run_dir: Path,
    manifest: dict[str, Any],
    values: dict[str, Any],
    resolution: dict[str, Any] | None,
    *,
    force: bool,
) -> tuple[dict[str, Any], bool, list[str]]:
    expected = _context_domains(manifest, resolution)
    merged_domains: dict[str, dict[str, Any]] = {}
    for domain in sorted(expected):
        shard_path = _shard_path(run_dir, "context", domain)
        if not shard_path.exists():
            raise ValueError(f"missing context shard for Domain {domain!r}: {shard_path}")
        shard = load_json(shard_path)
        _validate_context_shard(root, manifest, resolution, shard)
        if shard["owner_domain"] != domain:
            raise ValueError(f"context shard {shard_path.name} declares owner {shard['owner_domain']!r}")
        merged_domains[domain] = shard["context"]
    audit = manifest["audit_context"]
    merged_context = {
        "schema_version": DOMAIN_CONTEXT_VERSION,
        "routing_snapshot_id": manifest["routing_snapshot_id"],
        "registry_sha256": audit["registry_sha256"],
        "source_digest": audit["source_digest"],
        "compilation_input_digest": audit["compilation_input_digest"],
        "domains": merged_domains,
    }
    unresolved_context = validate_domain_context(root, manifest, merged_context, resolution)
    if unresolved_context:
        raise ValueError(
            "merged context remains UNKNOWN for: " + ", ".join(sorted(unresolved_context))
        )
    replaced = _guard_replace(
        values["domain_context"],
        merged_context,
        domain_context_template(manifest, resolution),
        force,
        "reviews/domain-context.json",
    )
    return merged_context, replaced, sorted(expected)


def _build_screen_merge(
    root: Path,
    run_dir: Path,
    manifest: dict[str, Any],
    values: dict[str, Any],
    resolution: dict[str, Any] | None,
    effective_context: dict[str, Any],
    *,
    force: bool,
) -> tuple[dict[str, Any], set[str], str, bool, list[str]]:
    expected = _screen_domains(manifest, resolution)
    merged_results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for domain in sorted(expected):
        shard_path = _shard_path(run_dir, "screen", domain)
        if not shard_path.exists():
            raise ValueError(f"missing screen shard for Domain {domain!r}: {shard_path}")
        shard = load_json(shard_path)
        _validate_screen_shard(root, manifest, resolution, shard)
        if shard["owner_domain"] != domain:
            raise ValueError(f"screen shard {shard_path.name} declares owner {shard['owner_domain']!r}")
        for entry in shard["results"]:
            if entry["canonical_id"] in seen:
                raise ValueError(
                    f"canonical ID {entry['canonical_id']!r} appears in more than one screen shard"
                )
            seen.add(entry["canonical_id"])
            merged_results.append(entry)
    merged_results.sort(key=lambda entry: entry["canonical_id"])
    audit = manifest["audit_context"]
    merged_screen = {
        "schema_version": SCREEN_RESULTS_VERSION,
        "routing_snapshot_id": manifest["routing_snapshot_id"],
        "registry_sha256": audit["registry_sha256"],
        "source_digest": audit["source_digest"],
        "compilation_input_digest": audit["compilation_input_digest"],
        "results": merged_results,
    }
    candidates = validate_screen_results(root, manifest, merged_screen, resolution)
    replaced = _guard_replace(
        values["screen_results"],
        merged_screen,
        screen_results_template(manifest, resolution),
        force,
        "reviews/screen-results.json",
    )
    review_snapshot = derive_review_snapshot_id(root, manifest, resolution, effective_context, merged_screen)
    return merged_screen, candidates, review_snapshot, replaced, sorted(expected)


def _diagnose_authoritative_context(
    root: Path,
    manifest: dict[str, Any],
    values: dict[str, Any],
    resolution: dict[str, Any] | None,
) -> dict[str, Any]:
    """Non-mutating authoritative-context check shared by status and merge-screen.

    Keeping one implementation means ``status`` diagnoses readiness with the
    exact contract ``merge-screen`` enforces, so the two can never drift.
    """
    if not values["domain_context"].exists():
        return {
            "present": False,
            "valid": False,
            "error": "authoritative reviews/domain-context.json is missing; run merge-context first",
        }
    try:
        context = load_json(values["domain_context"])
        unresolved = validate_domain_context(root, manifest, context, resolution)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        return {"present": True, "valid": False, "error": str(exc)}
    if unresolved:
        return {
            "present": True,
            "valid": False,
            "error": "authoritative domain-context.json remains UNKNOWN for: "
            + ", ".join(sorted(unresolved)),
        }
    return {"present": True, "valid": True}


def _authoritative_context(
    root: Path,
    manifest: dict[str, Any],
    values: dict[str, Any],
    resolution: dict[str, Any] | None,
) -> dict[str, Any]:
    diagnostic = _diagnose_authoritative_context(root, manifest, values, resolution)
    if not diagnostic["valid"]:
        raise ValueError(diagnostic["error"])
    return load_json(values["domain_context"])


def merge_context(root: Path, run_dir: Path, *, force: bool = False) -> dict[str, Any]:
    run_dir = run_dir.resolve()
    with _ledger_lock(run_dir / "domain-shards-merge", shared=False):
        manifest, values, resolution = _load_run(root, run_dir)
        merged, replaced, domains = _build_context_merge(
            root, run_dir, manifest, values, resolution, force=force
        )
        atomic_write_json(values["domain_context"], merged)
    return {
        "command": "merge-context",
        "context_shard_domains": domains,
        "domain_context_replaced": replaced,
        "context_domain_count": len(domains),
    }


def merge_screen(root: Path, run_dir: Path, *, force: bool = False) -> dict[str, Any]:
    run_dir = run_dir.resolve()
    with _ledger_lock(run_dir / "domain-shards-merge", shared=False):
        manifest, values, resolution = _load_run(root, run_dir)
        effective_context = _authoritative_context(root, manifest, values, resolution)
        merged, candidates, review_snapshot, replaced, domains = _build_screen_merge(
            root, run_dir, manifest, values, resolution, effective_context, force=force
        )
        atomic_write_json(values["screen_results"], merged)
    return {
        "command": "merge-screen",
        "screen_shard_domains": domains,
        "screen_results_replaced": replaced,
        "selected_count": len(merged["results"]),
        "candidate_count": len(candidates),
        "not_applicable_count": len(merged["results"]) - len(candidates),
        "review_snapshot_id": review_snapshot,
    }


def merge_shards(root: Path, run_dir: Path, *, force: bool = False) -> dict[str, Any]:
    run_dir = run_dir.resolve()
    with _ledger_lock(run_dir / "domain-shards-merge", shared=False):
        manifest, values, resolution = _load_run(root, run_dir)
        merged_context, context_replaced, context_domains = _build_context_merge(
            root, run_dir, manifest, values, resolution, force=force
        )
        merged_screen, candidates, review_snapshot, screen_replaced, screen_domains = _build_screen_merge(
            root, run_dir, manifest, values, resolution, merged_context, force=force
        )
        # Both outputs are fully built and validated above, so an ordinary
        # validation failure changes neither file. The two replacements are
        # each atomic but sequential: this is not a transactional commit
        # across the pair.
        atomic_write_json(values["domain_context"], merged_context)
        atomic_write_json(values["screen_results"], merged_screen)
    return {
        "command": "merge",
        "context_shard_domains": context_domains,
        "screen_shard_domains": screen_domains,
        "domain_context_replaced": context_replaced,
        "screen_results_replaced": screen_replaced,
        "selected_count": len(merged_screen["results"]),
        "candidate_count": len(candidates),
        "not_applicable_count": len(merged_screen["results"]) - len(candidates),
        "review_snapshot_id": review_snapshot,
    }


def shard_status(root: Path, run_dir: Path) -> dict[str, Any]:
    run_dir = run_dir.resolve()
    manifest, values, resolution = _load_run(root, run_dir)

    def diagnose(kind: str, expected_domains: dict[str, Any], validator) -> tuple[list[dict[str, Any]], list[str], list[str]]:
        entries: list[dict[str, Any]] = []
        missing: list[str] = []
        invalid: list[str] = []
        for domain in sorted(expected_domains):
            path = _shard_path(run_dir, kind, domain)
            entry: dict[str, Any] = {"owner_domain": domain, "shard_present": path.exists()}
            if path.exists():
                try:
                    shard = load_json(path)
                    validator(root, manifest, resolution, shard)
                    entry["valid"] = True
                except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
                    entry["valid"] = False
                    entry["error"] = str(exc)
                    invalid.append(domain)
            else:
                missing.append(domain)
            entries.append(entry)
        return entries, missing, invalid

    screen_entries, missing_screen, invalid_screen = diagnose(
        "screen", _screen_domains(manifest, resolution), _validate_screen_shard
    )
    context_entries, missing_context, invalid_context = diagnose(
        "context", _context_domains(manifest, resolution), _validate_context_shard
    )
    context_diagnostic = _diagnose_authoritative_context(root, manifest, values, resolution)
    context_merge_ready = not missing_context and not invalid_context
    screen_merge_ready = (
        not missing_screen
        and not invalid_screen
        and context_diagnostic["present"]
        and context_diagnostic["valid"]
    )
    return {
        "command": "status",
        "routing_snapshot_id": manifest["routing_snapshot_id"],
        "screen_shards": screen_entries,
        "context_shards": context_entries,
        "context_merge_ready": context_merge_ready,
        "screen_merge_ready": screen_merge_ready,
        "merge_ready": context_merge_ready and screen_merge_ready,
        "missing_screen_shards": missing_screen,
        "missing_context_shards": missing_context,
        "invalid_screen_shards": invalid_screen,
        "invalid_context_shards": invalid_context,
        "global_domain_context": context_diagnostic,
        "global_domain_context_present": values["domain_context"].exists(),
        "global_screen_results_present": values["screen_results"].exists(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    for name in ("write-screen-shard", "write-context-shard"):
        command = subparsers.add_parser(name)
        command.add_argument("--run-dir", type=Path, required=True)
        command.add_argument("--domain", required=True)
        command.add_argument("--input", type=Path, required=True)
        command.add_argument("--root", type=Path, default=ROOT)

    for name in ("merge", "merge-context", "merge-screen"):
        command = subparsers.add_parser(name)
        command.add_argument("--run-dir", type=Path, required=True)
        command.add_argument("--force", action="store_true", help="replace global artifacts that are neither the template nor the merged shards")
        command.add_argument("--root", type=Path, default=ROOT)

    status = subparsers.add_parser("status")
    status.add_argument("--run-dir", type=Path, required=True)
    status.add_argument("--root", type=Path, default=ROOT)

    args = parser.parse_args(argv)
    configure(quiet=False)
    try:
        root = args.root.resolve()
        if args.command == "write-screen-shard":
            result = write_screen_shard(root, args.run_dir, args.domain, args.input)
        elif args.command == "write-context-shard":
            result = write_context_shard(root, args.run_dir, args.domain, args.input)
        elif args.command == "merge-context":
            result = merge_context(root, args.run_dir, force=args.force)
        elif args.command == "merge-screen":
            result = merge_screen(root, args.run_dir, force=args.force)
        elif args.command == "merge":
            result = merge_shards(root, args.run_dir, force=args.force)
        else:
            result = shard_status(root, args.run_dir)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        error(exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
