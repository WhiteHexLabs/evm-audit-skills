#!/usr/bin/env python3
"""Derive audit completion from immutable routing and run artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_SUITE_ROOT = str(Path(__file__).resolve().parents[1])
if _SUITE_ROOT not in sys.path:
    sys.path.insert(0, _SUITE_ROOT)
from evm_audit_runtime.state import COMPLETE_STATES, derive_status
from evm_audit_runtime.controller_state import progress_metadata
from evm_audit_runtime.versions import AUDIT_STATE_VERSION

try:
    from audit_artifacts import (
        atomic_write_text,
        derive_review_snapshot_id,
        load_json,
        require_distinct_paths,
        review_state_digest,
        validate_artifact_identity,
        validate_context,
        validate_domain_context,
        validate_domain_resolution,
        validate_generated_artifact_path,
        validate_schema,
        validate_target_snapshot,
    )
    from render_runtime import selected_entries, validate_manifest, validate_screen_results
    from review_ledger import collect_review_records
except ImportError:  # pragma: no cover
    from scripts.audit_artifacts import (
        atomic_write_text,
        derive_review_snapshot_id,
        load_json,
        require_distinct_paths,
        review_state_digest,
        validate_artifact_identity,
        validate_context,
        validate_domain_context,
        validate_domain_resolution,
        validate_generated_artifact_path,
        validate_schema,
        validate_target_snapshot,
    )
    from scripts.render_runtime import selected_entries, validate_manifest, validate_screen_results
    from scripts.review_ledger import collect_review_records

try:
    from runtime_log import configure, error, info, stage, success, warning
except ImportError:  # pragma: no cover
    from scripts.runtime_log import configure, error, info, stage, success, warning


ROOT = Path(__file__).resolve().parents[1]
def _domain_ids(manifest: dict[str, Any], bucket: str) -> set[str]:
    return {entry["domain"] for entry in manifest.get(bucket, [])}


def validate_run(
    root: Path,
    manifest: dict[str, Any],
    registry: dict[str, Any],
    screen_results: dict[str, Any] | None,
    domain_resolution: dict[str, Any] | None,
    domain_context: dict[str, Any] | None,
    context: dict[str, Any] | None,
    ledger_paths: list[Path],
    *,
    managed_output_root: Path | None = None,
) -> dict[str, Any]:
    invalid: list[str] = []
    coverage_errors: list[str] = []
    domain_errors: list[str] = []
    context_errors: list[str] = []
    review_errors: list[str] = []
    review_snapshot: str | None = None
    screen_valid = False
    domain_context_valid = False

    try:
        validate_manifest(root, manifest, registry)
    except (ValueError, KeyError) as error:
        invalid.append(str(error))
    try:
        validate_target_snapshot(manifest, managed_output_root=managed_output_root)
    except (ValueError, KeyError) as error:
        invalid.append(str(error))

    try:
        selected = {entry["canonical_id"] for entry in selected_entries(manifest, domain_resolution=domain_resolution)}
    except (KeyError, TypeError) as error:
        invalid.append(f"invalid routing manifest selection buckets: {error}")
        selected = set()
    if any(isinstance(entry, dict) and entry.get("route_status") == "SELECTED" for entry in manifest.get("deferred", [])):
        coverage_errors.append("Deferred bucket contains a selected route")

    screen_not_applicable: set[str] = set()
    candidates: set[str] = set()
    if screen_results is None:
        coverage_errors.append("screen-results.json is required")
    else:
        try:
            validate_artifact_identity(screen_results, manifest)
        except ValueError as error:
            invalid.append(str(error))
        try:
            candidates = validate_screen_results(root, manifest, screen_results, domain_resolution)
            screen_not_applicable = selected - candidates
            screen_valid = True
        except (ValueError, KeyError) as error:
            coverage_errors.append(str(error))
            raw_results = screen_results.get("results", [])
            if isinstance(raw_results, list):
                candidates = {item["canonical_id"] for item in raw_results if isinstance(item, dict) and isinstance(item.get("canonical_id"), str) and item.get("result") == "CANDIDATE"}
                screen_not_applicable = {item["canonical_id"] for item in raw_results if isinstance(item, dict) and isinstance(item.get("canonical_id"), str) and item.get("result") == "NOT_APPLICABLE_CONFIRMED"}

    if screen_not_applicable & candidates or screen_not_applicable | candidates != selected:
        coverage_errors.append("coverage equation failed: selected_ids != screen_not_applicable_ids union deep_candidate_ids")

    deferred_domains = _domain_ids(manifest, "deferred_domains")
    if deferred_domains and domain_resolution is None:
        domain_errors.append("domain-resolution.json is required for Deferred Domains")
    elif domain_resolution is not None:
        try:
            unresolved_domains = validate_domain_resolution(root, manifest, domain_resolution)
        except (ValueError, KeyError) as error:
            invalid.append(str(error))
        else:
            domain_errors.extend(
                f"Deferred Domain {domain} remains UNKNOWN" for domain in sorted(unresolved_domains)
            )

    if context is None:
        invalid.append("context.json is required")
    else:
        invalid.extend(validate_context(root, manifest, context))

    if domain_context is None:
        if manifest.get("required_context_requirements"):
            context_errors.append("domain-context.json is required")
    else:
        try:
            unresolved_context = validate_domain_context(
                root, manifest, domain_context, domain_resolution
            )
        except (ValueError, KeyError) as error:
            invalid.append(str(error))
        else:
            context_errors.extend(
                f"required Domain context remains UNKNOWN: {item}"
                for item in sorted(unresolved_context)
            )

            domain_context_valid = True

    if screen_valid and domain_context_valid and not domain_errors and not context_errors:
        try:
            review_snapshot = derive_review_snapshot_id(
                root, manifest, domain_resolution, domain_context, screen_results
            )
        except (ValueError, KeyError) as error:
            review_errors.append(f"review snapshot is unavailable: {error}")

    records, ledger_errors = collect_review_records(
        ledger_paths, manifest, registry, candidates, domain_resolution, review_snapshot,
        managed_output_root=managed_output_root,
    )
    review_errors.extend(ledger_errors)
    reviewed = set(records)
    if candidates - reviewed:
        review_errors.append(f"missing Deep record(s): {sorted(candidates - reviewed)}")

    statuses = {canonical_id: record.get("status") for canonical_id, record in records.items()}
    suspicious = {canonical_id for canonical_id, status in statuses.items() if status == "SUSPICIOUS"}
    confirmed = {canonical_id for canonical_id, status in statuses.items() if status == "CONFIRMED"}
    unresolved = suspicious | (candidates - reviewed)
    if suspicious:
        review_errors.append(f"SUSPICIOUS records block clean completion: {sorted(suspicious)}")

    state_review_digest: str | None = None
    if review_snapshot is not None and not ledger_errors and candidates <= reviewed:
        try:
            state_review_digest = review_state_digest(records, candidates)
        except ValueError as error:
            review_errors.append(str(error))

    status = derive_status(
        invalid=bool(invalid),
        coverage=bool(coverage_errors),
        domain=bool(domain_errors),
        context=bool(context_errors),
        review=bool(review_errors),
        confirmed=bool(confirmed),
    )
    complete = status in COMPLETE_STATES
    recon_quality = manifest.get("feature_map", {}).get("recon_context", {}).get("recon_quality")

    reasons: list[str] = []
    for reason in [*invalid, *coverage_errors, *domain_errors, *context_errors, *review_errors]:
        if reason not in reasons:
            reasons.append(reason)
    state = {
        "schema_version": AUDIT_STATE_VERSION,
        "routing_snapshot_id": manifest.get("routing_snapshot_id"),
        "review_snapshot_id": review_snapshot,
        "review_state_digest": state_review_digest,
        "registry_sha256": manifest.get("audit_context", {}).get("registry_sha256"),
        "source_digest": manifest.get("audit_context", {}).get("source_digest"),
        "compilation_input_digest": manifest.get("audit_context", {}).get("compilation_input_digest"),
        "status": status,
        "complete": complete,
        "clean": status == "COMPLETE_CLEAN",
        "reasons": reasons,
        "recon_quality": recon_quality,
        "coverage": {
            "selected": sorted(selected),
            "screen_not_applicable": sorted(screen_not_applicable),
            "deep_candidates": sorted(candidates),
            "deep_reviewed": sorted(reviewed),
            "suspicious": sorted(suspicious),
            "confirmed": sorted(confirmed),
            "unresolved": sorted(unresolved),
        },
    }
    try:
        validate_schema(root, "audit-state.schema.json", state)
    except ValueError as error:
        state["reasons"].append(str(error))
        state["status"] = "INVALID_SNAPSHOT"
        state["complete"] = False
        state["clean"] = False
    return state


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--screen-results", type=Path, required=True)
    parser.add_argument("--domain-resolution", type=Path)
    parser.add_argument("--domain-context", type=Path, required=True)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--registry", type=Path, default=ROOT / "data/canonical-checks.json")
    parser.add_argument("--ledger", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--managed-output-root",
        type=Path,
        help="controller-owned audit output root; required when the run lives inside the audited project",
    )
    parser.add_argument("--quiet", action="store_true", help="suppress progress output")
    args = parser.parse_args(argv)
    configure(quiet=args.quiet)
    try:
        stage("REPORT", detail="Deriving the final audit state independently")
        manifest = load_json(args.manifest)
        registry = load_json(args.registry)
        require_distinct_paths(
            ("manifest", args.manifest),
            ("registry", args.registry),
            ("screen results", args.screen_results),
            ("domain resolution", args.domain_resolution),
            ("domain context", args.domain_context),
            ("context", args.context),
            ("audit state", args.output),
        )
        if args.output:
            recon_context = manifest.get("feature_map", {}).get("recon_context", {})
            validate_generated_artifact_path(
                args.output,
                audit_root=Path(recon_context["target_root"]),
                build_root=Path(recon_context["build_root"]),
                label="audit state",
                managed_output_root=args.managed_output_root,
            )
        screen = load_json(args.screen_results) if args.screen_results.exists() else None
        domain = load_json(args.domain_resolution) if args.domain_resolution else None
        domain_context = load_json(args.domain_context)
        context = load_json(args.context)
        state = validate_run(
            ROOT, manifest, registry, screen, domain, domain_context, context, args.ledger,
            managed_output_root=args.managed_output_root,
        )
        rendered = json.dumps(state, ensure_ascii=False, indent=2) + "\n"
        if args.output:
            atomic_write_text(args.output, rendered)
        print(rendered, end="")
        coverage = state["coverage"]
        snapshot_valid = state["status"] != "INVALID_SNAPSHOT"
        coverage_valid = state["status"] not in {"INVALID_SNAPSHOT", "INCOMPLETE_COVERAGE"}
        domain_valid = state["status"] not in {"INVALID_SNAPSHOT", "INCOMPLETE_COVERAGE", "INCOMPLETE_DOMAIN_ROUTING"}
        review_complete = not coverage["unresolved"]
        if snapshot_valid:
            success("Routing snapshot valid")
        else:
            warning("Routing snapshot invalid")
        if snapshot_valid and coverage_valid:
            success("Screen coverage complete")
        if snapshot_valid and coverage_valid and domain_valid and review_complete:
            success("Candidate Deep coverage complete")
        if snapshot_valid and domain_valid:
            success(f"{progress_metadata('DOMAIN_RESOLUTION')['label']} routing resolved")
        if snapshot_valid:
            success("Artifact identities match")
        info(f"Confirmed: {len(coverage['confirmed'])}")
        info(f"Suspicious: {len(coverage['suspicious'])}")
        reviewed_safe = 0
        try:
            records, _ = collect_review_records(
                args.ledger,
                manifest,
                registry,
                set(coverage["deep_candidates"]),
                domain,
                state.get("review_snapshot_id"),
                managed_output_root=args.managed_output_root,
            )
            reviewed_safe = sum(record.get("status") == "REVIEWED_SAFE" for record in records.values())
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            pass
        info(f"Reviewed safe: {reviewed_safe}")
        if state["status"] in {"COMPLETE_CLEAN", "COMPLETE_WITH_FINDINGS"}:
            success(f"{progress_metadata('REPORT')['label']} state complete")
            info(f"Status: {state['status']}")
        else:
            warning(f"{progress_metadata('REPORT')['label']} state incomplete")
            info(f"Status: {state['status']}")
            if coverage["unresolved"]:
                warning(f"{len(coverage['unresolved'])} candidate(s) require further review")
            elif state["status"] == "INCOMPLETE_DOMAIN_ROUTING":
                warning("Deferred Domain resolution requires further work")
            elif state["status"] == "INCOMPLETE_CONTEXT":
                warning("Required Domain context requires further work")
            else:
                warning("Further review or resolution is required")
        return 0 if state["complete"] else 1
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        error(exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
