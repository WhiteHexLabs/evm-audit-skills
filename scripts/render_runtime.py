#!/usr/bin/env python3
"""Render immutable routing output into compact Screen/Deep/Proof views."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from evm_audit_runtime.controller_state import progress_metadata
from evm_audit_runtime.versions import DOMAIN_CONTEXT_VERSION, DOMAIN_RESOLUTION_VERSION, RUNTIME_METADATA_VERSION, SCREEN_RESULTS_VERSION
from evm_audit_runtime.limits import MAX_SCREEN_GATE_LENGTH

try:
    from audit_artifacts import (
        atomic_write_json,
        atomic_write_text,
        canonical_sha256,
        check_body_hash,
        derive_review_snapshot_id,
        load_json,
        require_distinct_paths,
        registry_sha256,
        resolved_routes,
        trusted_absence_policy,
        validate_domain_context,
        validate_domain_resolution,
        validate_artifact_identity,
        validate_generated_artifact_path,
        validate_non_applicability,
        validate_routing_snapshot,
        validate_schema,
        validate_target_snapshot,
    )
except ImportError:  # pragma: no cover
    from scripts.audit_artifacts import (
        atomic_write_json,
        atomic_write_text,
        canonical_sha256,
        check_body_hash,
        derive_review_snapshot_id,
        load_json,
        require_distinct_paths,
        registry_sha256,
        resolved_routes,
        trusted_absence_policy,
        validate_domain_context,
        validate_domain_resolution,
        validate_artifact_identity,
        validate_generated_artifact_path,
        validate_non_applicability,
        validate_routing_snapshot,
        validate_schema,
        validate_target_snapshot,
    )

try:
    from runtime_log import configure, error, info, stage, success, verbose as verbose_log, warning
except ImportError:  # pragma: no cover
    from scripts.runtime_log import configure, error, info, stage, success, verbose as verbose_log, warning


ROOT = Path(__file__).resolve().parents[1]
ROUTE_BUCKETS = ("selected", "deferred", "filtered")


def one_line(value: Any) -> str:
    return " ".join(str(item).strip() for item in value if str(item).strip()) if isinstance(value, list) else str(value or "").strip()


def selected_entries(manifest: dict[str, Any], owner_domain: str | None = None, domain_resolution: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    entries = resolved_routes(manifest, domain_resolution)
    return [entry for entry in entries if owner_domain is None or entry["owner_domain"] == owner_domain]


def validate_manifest(root: Path, manifest: dict[str, Any], registry: dict[str, Any]) -> str:
    validate_schema(root, "routing-manifest.schema.json", manifest)
    validate_schema(root, "feature-map.schema.json", manifest["feature_map"])
    snapshot = validate_routing_snapshot(manifest)
    if manifest["audit_context"]["registry_sha256"] != registry_sha256(registry):
        raise ValueError("routing manifest does not match this registry")
    recon_context = manifest["feature_map"]["recon_context"]
    for key in ("source_digest", "audit_source_digest", "dependency_digest", "build_config_digest", "compilation_input_digest"):
        if manifest["audit_context"][key] != recon_context[key]:
            raise ValueError(f"routing manifest {key} does not match Recon")
    checks = {check["canonical_id"]: check for check in registry["checks"]}
    ids_by_bucket: dict[str, list[str]] = {}
    for bucket in ROUTE_BUCKETS:
        ids_by_bucket[bucket] = []
        for entry in manifest[bucket]:
            ids_by_bucket[bucket].append(entry["canonical_id"])
            if entry["owner_domain"] not in entry["domains"]:
                raise ValueError(f"routing manifest owner is outside route domains: {entry['canonical_id']}")
            check = checks.get(entry["canonical_id"])
            if check is None:
                raise ValueError(f"routing manifest references unknown check: {entry['canonical_id']}")
            if entry["check_body_hash"] != check_body_hash(check):
                raise ValueError(f"routing manifest has stale check body: {entry['canonical_id']}")
        if manifest[f"{bucket}_count"] != len(manifest[bucket]):
            raise ValueError(f"routing manifest {bucket}_count is stale")
    all_ids = [canonical_id for bucket in ROUTE_BUCKETS for canonical_id in ids_by_bucket[bucket]]
    if len(all_ids) != len(set(all_ids)):
        raise ValueError("routing manifest contains duplicate canonical IDs")
    if manifest["scope"]["candidate_count"] != len(all_ids):
        raise ValueError("routing manifest scope candidate_count is stale")
    if manifest["filtered_out"] != ids_by_bucket["filtered"]:
        raise ValueError("routing manifest filtered_out is stale")
    domain_buckets = [set(entry["domain"] for entry in manifest[bucket + "_domains"]) for bucket in ("selected", "deferred", "filtered")]
    if any(domain_buckets[left] & domain_buckets[right] for left in range(3) for right in range(left + 1, 3)):
        raise ValueError("routing manifest Domain buckets overlap")
    for bucket, expected_status in (("selected", "SELECTED"), ("deferred", "DEFERRED_DOMAIN")):
        if any(entry["route_status"] != expected_status for entry in manifest[bucket]):
            raise ValueError(f"routing manifest {bucket} route status is inconsistent")
    if any(not entry["route_status"].startswith("FILTERED_") for entry in manifest["filtered"]):
        raise ValueError("routing manifest filtered route status is inconsistent")
    selected_domains = domain_buckets[0]
    deferred_domains = domain_buckets[1]
    filtered_domains = domain_buckets[2]
    required_context_domains = set(manifest["required_context_requirements"])
    if required_context_domains != selected_domains | deferred_domains:
        raise ValueError("required_context_requirements must cover selected and Deferred Domains only")
    if required_context_domains & filtered_domains:
        raise ValueError("filtered Domains must not have required context")
    for entry in manifest["selected"]:
        if not set(entry["domains"]) & selected_domains:
            raise ValueError(f"selected check is not owned by a selected Domain: {entry['canonical_id']}")
    for entry in manifest["deferred"]:
        if not set(entry["domains"]) & deferred_domains:
            raise ValueError(f"deferred check is not owned by a Deferred Domain: {entry['canonical_id']}")
    for entry in manifest["filtered"]:
        if not set(entry["domains"]) & (filtered_domains | selected_domains):
            raise ValueError(f"filtered check is not in the routed Domain scope: {entry['canonical_id']}")
    return snapshot


def _empty_identity(manifest: dict[str, Any], schema_version: int = SCREEN_RESULTS_VERSION) -> dict[str, Any]:
    audit = manifest["audit_context"]
    return {
        "schema_version": schema_version,
        "routing_snapshot_id": manifest["routing_snapshot_id"],
        "registry_sha256": audit["registry_sha256"],
        "source_digest": audit["source_digest"],
        "compilation_input_digest": audit["compilation_input_digest"],
    }


def screen_results_template(manifest: dict[str, Any], domain_resolution: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        **_empty_identity(manifest, SCREEN_RESULTS_VERSION),
        "results": [
            {"canonical_id": entry["canonical_id"], "result": "CANDIDATE", "scope_complete": False, "evidence": []}
            for entry in selected_entries(manifest, domain_resolution=domain_resolution)
        ],
    }


def domain_resolution_template(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        **_empty_identity(manifest, DOMAIN_RESOLUTION_VERSION),
        "domains": {
            entry["domain"]: {"status": "UNKNOWN", "scope_complete": False, "evidence": []}
            for entry in manifest["deferred_domains"]
        },
    }


def domain_context_template(
    manifest: dict[str, Any],
    domain_resolution: dict[str, Any] | None = None,
) -> dict[str, Any]:
    eligible = {entry["domain"] for entry in manifest["selected_domains"]}
    if domain_resolution is not None:
        eligible |= {
            domain
            for domain, resolution in domain_resolution["domains"].items()
            if resolution["status"] == "PRESENT"
        }
    return {
        **_empty_identity(manifest),
        "schema_version": DOMAIN_CONTEXT_VERSION,
        "domains": {
            domain: {
                key: {"status": "UNKNOWN", "evidence": []}
                for key in manifest["required_context_requirements"].get(domain, {})
            }
            for domain in sorted(eligible)
            if domain in manifest["required_context_requirements"]
        },
    }


def validate_screen_results(root: Path, manifest: dict[str, Any], value: dict[str, Any], domain_resolution: dict[str, Any] | None = None) -> set[str]:
    validate_schema(root, "screen-results.schema.json", value)
    validate_artifact_identity(value, manifest)
    selected = {entry["canonical_id"] for entry in selected_entries(manifest, domain_resolution=domain_resolution)}
    routes = {entry["canonical_id"]: entry for entry in selected_entries(manifest, domain_resolution=domain_resolution)}
    results = value["results"]
    ids = [entry["canonical_id"] for entry in results]
    if len(ids) != len(set(ids)) or set(ids) != selected:
        raise ValueError("screen results must resolve every selected ID exactly once")
    for entry in results:
        if entry["result"] == "NOT_APPLICABLE_CONFIRMED":
            route = routes.get(entry["canonical_id"])
            errors = validate_non_applicability(
                evidence=entry["evidence"],
                scope_complete=entry.get("scope_complete"),
                trusted_absence_policy=trusted_absence_policy(manifest, route["owner_domain"]) if route else None,
                recon_quality=manifest.get("feature_map", {}).get("recon_context", {}).get("recon_quality"),
                label=entry["canonical_id"],
            )
            if errors:
                raise ValueError("; ".join(errors))
    return {entry["canonical_id"] for entry in results if entry["result"] == "CANDIDATE"}


def runtime_identity(
    manifest: dict[str, Any],
    profile: str,
    candidate_ids: list[str],
    owner_domain: str | None,
    review_snapshot: str | None,
    ledger_digest: str | None = None,
) -> dict[str, Any]:
    audit = manifest["audit_context"]
    identity = {
        "schema_version": RUNTIME_METADATA_VERSION,
        "profile": profile,
        "routing_snapshot_id": manifest["routing_snapshot_id"],
        "review_snapshot_id": review_snapshot,
        "candidate_set_sha256": canonical_sha256(candidate_ids),
        "candidate_count": len(candidate_ids),
        "owner_domain": owner_domain,
        "registry_sha256": audit["registry_sha256"],
        "source_digest": audit["source_digest"],
        "compilation_input_digest": audit["compilation_input_digest"],
    }
    if ledger_digest is not None:
        identity["ledger_digest"] = ledger_digest
    return identity


def runtime_metadata(
    manifest: dict[str, Any],
    profile: str,
    candidate_ids: list[str],
    owner_domain: str | None,
    review_snapshot: str | None,
    runtime_sha256: str,
    ledger_digest: str | None = None,
) -> dict[str, Any]:
    return {
        **runtime_identity(manifest, profile, candidate_ids, owner_domain, review_snapshot, ledger_digest),
        "runtime_sha256": runtime_sha256,
    }


def _render_evidence(evidence: Any) -> str:
    if not isinstance(evidence, list):
        return ""
    return "; ".join(
        f"{item.get('kind')}:{item.get('location')} — {item.get('reason')}"
        for item in evidence
        if isinstance(item, dict)
    )


def render(
    manifest: dict[str, Any],
    registry: dict[str, Any],
    profile: str,
    candidate_ids: set[str],
    owner_domain: str | None = None,
    domain_resolution: dict[str, Any] | None = None,
    review_snapshot: str | None = None,
    proof_records: dict[str, dict[str, Any]] | None = None,
) -> str:
    entries = {entry["canonical_id"]: entry for entry in selected_entries(manifest, owner_domain, domain_resolution)}
    checks = {
        check["canonical_id"]: check
        for check in registry["checks"]
        if check["canonical_id"] in entries and (profile == "screen" or check["canonical_id"] in candidate_ids)
    }
    ids = sorted(checks)
    snapshot_display = review_snapshot[:12] if review_snapshot else "not-yet-defined"
    lines = [
        "<!-- GENERATED RUNTIME ARTIFACT",
        f"artifact_type: runtime-{profile}",
        f"profile: {profile}",
        f"owner_domain: {owner_domain or 'all'}",
        f"candidate_count: {len(ids)}",
        f"review_snapshot: {snapshot_display}",
        "machine identity: adjacent .meta.json; source: data/canonical-checks.json; do not edit by hand. -->",
        "# Routed EVM Audit Checks",
        "",
        f"- **Profile:** `{profile}`",
        f"- **Candidate count:** `{len(ids)}`",
        "",
    ]
    for canonical_id in ids:
        check = checks[canonical_id]
        route = entries[canonical_id]
        lines.extend([f"## [{canonical_id}] {check['title']}"])
        if profile == "proof":
            record = (proof_records or {}).get(canonical_id, {})
            lines.extend([
                f"- **Latest review:** revision `{record.get('revision')}`; stage `{record.get('review_stage')}`; status `{record.get('status')}`",
                f"- **Review snapshot:** `{snapshot_display}` (full identity in the sidecar)",
                f"- **Trigger:** {one_line(check['trigger'])}",
                f"- **Detection:** {one_line(check['detection'])}",
                f"- **Code path:** {record.get('code_path', '')}",
                f"- **Unresolved reason:** {record.get('unresolved_reason', '')}",
            ])
            for key, label in (
                ("applicability", "Applicability"),
                ("preconditions", "Preconditions"),
                ("exploitability", "Exploitability"),
                ("impact", "Impact"),
                ("proof", "Existing proof"),
            ):
                if record.get(key):
                    lines.append(f"- **{label}:** {record[key]}")
            if record.get("suspected_preconditions"):
                lines.append(f"- **Suspected preconditions:** {record['suspected_preconditions']}")
            if record.get("suspected_impact"):
                lines.append(f"- **Suspected impact:** {record['suspected_impact']}")
            if check.get("proof_policy") == "specific":
                lines.append(f"- **Specific proof:** {one_line(check['proof'])}")
            if record.get("evidence"):
                lines.append(f"- **Latest evidence:** {_render_evidence(record['evidence'])}")
        elif profile == "deep":
            lines.extend([f"- **Routing basis:** {one_line(route['basis'])}"])
            lines.extend([f"- **Trigger:** {one_line(check['trigger'])}", f"- **Detection:** {one_line(check['detection'])}"])
            lines.extend([
                f"- **Risk:** {one_line(check['risk'])}",
                f"- **Applicability:** `{json.dumps(check.get('applicability'), ensure_ascii=False, sort_keys=True)}`",
            ])
            if check.get("fp_policy") == "specific":
                lines.append(f"- **Specific FP:** {one_line(check['false_positive_gates'])}")
            if check.get("proof_policy") == "specific":
                lines.append(f"- **Specific proof:** {one_line(check['proof'])}")
        elif profile == "screen":
            gate = check.get("screen_gate") or one_line((check.get("trigger") or [])[:1])
            gate = gate[:MAX_SCREEN_GATE_LENGTH]
            lines.append(f"- **Screen gate:** {gate}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write_json(path: Path, value: dict[str, Any], *, overwrite: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise ValueError(f"refusing to overwrite existing artifact: {path}")
    atomic_write_json(path, value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--registry", type=Path, default=ROOT / "data/canonical-checks.json")
    parser.add_argument("--profile", choices=("screen", "deep", "proof"), required=True)
    parser.add_argument("--screen-results", type=Path, help="validated Screen result artifact for Deep/Proof")
    parser.add_argument("--ledger", type=Path, action="append", default=[], help="review ledger for Proof")
    parser.add_argument("--domain-resolution", type=Path, help="resolved Deferred Domain artifact")
    parser.add_argument("--screen-results-out", type=Path, help="write a conservative Screen result template")
    parser.add_argument("--domain-resolution-out", type=Path, help="write an unresolved Deferred Domain template")
    parser.add_argument("--domain-context", type=Path, help="snapshot-bound required Domain context")
    parser.add_argument("--domain-context-out", type=Path, help="write an unresolved Domain Context template")
    parser.add_argument("--owner-domain", help="render only checks owned by this Domain")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--managed-output-root",
        type=Path,
        help="controller-owned audit output root; required when the run lives inside the audited project",
    )
    parser.add_argument("--quiet", action="store_true", help="suppress progress output")
    parser.add_argument("--verbose", action="store_true", help="include per-domain render details")
    args = parser.parse_args(argv)
    configure(quiet=args.quiet, verbose=args.verbose)
    try:
        manifest, registry = load_json(args.manifest), load_json(args.registry)
        validate_manifest(ROOT, manifest, registry)
        validate_target_snapshot(manifest, managed_output_root=args.managed_output_root)
        recon_context = manifest["feature_map"]["recon_context"]
        audit_root = Path(recon_context["target_root"])
        build_root = Path(recon_context["build_root"])
        outputs = (
            ("runtime view", args.output),
            ("screen results", args.screen_results_out),
            ("domain resolution", args.domain_resolution_out),
            ("domain context", args.domain_context_out),
        )
        require_distinct_paths(
            ("manifest", args.manifest),
            ("registry", args.registry),
            ("screen results input", args.screen_results),
            ("domain resolution input", args.domain_resolution),
            ("domain context input", args.domain_context),
            *outputs,
        )
        for label, output in outputs:
            if output is not None:
                validate_generated_artifact_path(
                    output,
                    audit_root=audit_root,
                    build_root=build_root,
                    label=label,
                    managed_output_root=args.managed_output_root,
                )
        domain_resolution = load_json(args.domain_resolution) if args.domain_resolution else None
        unresolved_domains: set[str] = set()
        if args.domain_resolution or args.domain_resolution_out:
            stage("DOMAIN_RESOLUTION", detail="Resolving deferred protocol context")
        if domain_resolution is not None:
            unresolved_domains = validate_domain_resolution(
                ROOT, manifest, domain_resolution
            )
            for domain, resolution in sorted(domain_resolution.get("domains", {}).items()):
                info(f"{domain} {resolution['status']}")
            if unresolved_domains:
                warning(f"{len(unresolved_domains)} Deferred Domain(s) remain UNKNOWN")
                if args.profile in {"deep", "proof"}:
                    blocked_stage = "PROOF" if args.profile == "proof" else "DEEP_REVIEW"
                    raise ValueError(f"{progress_metadata(blocked_stage)['label']} blocked: unresolved Deferred Domains")
            else:
                success(f"{progress_metadata('DOMAIN_RESOLUTION')['label']} routing resolved")
        elif args.domain_resolution_out and manifest["deferred_domains"]:
            warning(f"{len(manifest['deferred_domains'])} Deferred Domain(s) remain UNKNOWN")
        domain_context = load_json(args.domain_context) if args.domain_context else None
        if domain_context is not None:
            unresolved_context = validate_domain_context(
                ROOT,
                manifest,
                domain_context,
                domain_resolution,
                require_complete=args.profile in {"deep", "proof"},
            )
            if unresolved_context:
                warning(f"{len(unresolved_context)} required Domain context item(s) remain UNKNOWN")
            else:
                success(f"{progress_metadata('DOMAIN_CONTEXT')['label']} validated")
        review_snapshot: str | None = None
        screen_results: dict[str, Any] | None = None
        proof_records: dict[str, dict[str, Any]] | None = None
        ledger_digest: str | None = None
        if args.profile in {"deep", "proof"}:
            stage_name = "PROOF" if args.profile == "proof" else "DEEP_REVIEW"
            stage(stage_name, detail="Rendering the candidate-only runtime view")
            if not args.screen_results:
                raise ValueError(f"--profile {args.profile} requires --screen-results")
            if manifest["deferred_domains"] and not domain_resolution:
                raise ValueError(f"{progress_metadata(stage_name)['label']} blocked: --domain-resolution is required for Deferred Domains")
            if not args.domain_context:
                raise ValueError(f"--profile {args.profile} requires --domain-context")
            screen_results = load_json(args.screen_results)
            candidates = validate_screen_results(ROOT, manifest, screen_results, domain_resolution)
            review_snapshot = derive_review_snapshot_id(
                ROOT, manifest, domain_resolution, domain_context, screen_results
            )
            if args.profile == "proof":
                if not args.ledger:
                    raise ValueError("--profile proof requires at least one --ledger")
                try:
                    from review_ledger import collect_review_records, ledger_content_digest
                except ImportError:  # pragma: no cover - package-style import
                    from scripts.review_ledger import collect_review_records, ledger_content_digest
                # digest the ledger state before reading it for rendering so
                # the recorded digest can only match content that is
                # same-or-older; a concurrent append then forces a re-render
                ledger_digest = ledger_content_digest(args.ledger)
                records, errors = collect_review_records(
                    args.ledger, manifest, registry, candidates, domain_resolution, review_snapshot
                )
                if errors:
                    raise ValueError("; ".join(errors))
                proof_records = {
                    canonical_id: record
                    for canonical_id, record in records.items()
                    if record.get("status") == "SUSPICIOUS"
                }
                candidates = set(proof_records)
        else:
            stage("SCREEN", detail="Triaging routed checks")
            candidates = set()
            if args.screen_results or args.ledger:
                raise ValueError("--screen-results/--ledger are only used by Deep or Proof")
            if args.screen_results_out:
                write_json(args.screen_results_out, screen_results_template(manifest, domain_resolution))
                info(f"Screen result template written to {args.screen_results_out}")
            if args.domain_resolution_out:
                write_json(args.domain_resolution_out, domain_resolution_template(manifest))
                info(f"Domain Resolution template written to {args.domain_resolution_out}")
            if args.domain_context_out:
                write_json(args.domain_context_out, domain_context_template(manifest, domain_resolution))
                info(f"Domain Context template written to {args.domain_context_out}")
        rendered = render(
            manifest,
            registry,
            args.profile,
            candidates,
            args.owner_domain,
            domain_resolution,
            review_snapshot,
            proof_records,
        )
        atomic_write_text(args.output, rendered)
        entries = selected_entries(manifest, args.owner_domain, domain_resolution)
        rendered_ids = sorted(
            entry["canonical_id"] for entry in entries
            if args.profile == "screen" or entry["canonical_id"] in candidates
        )
        metadata = runtime_metadata(
            manifest,
            args.profile,
            rendered_ids,
            args.owner_domain,
            review_snapshot,
            hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
            ledger_digest,
        )
        validate_schema(ROOT, "runtime-metadata.schema.json", metadata)
        atomic_write_json(args.output.with_suffix(".meta.json"), metadata)
        if args.profile == "screen":
            info(f"Rendered checks: {len(entries)}")
            success("Screen runtime generated")
        elif args.profile == "proof":
            entries = [entry for entry in entries if entry["canonical_id"] in candidates]
            info(f"Suspicious records admitted: {len(entries)}")
            success("Proof runtime generated")
        else:
            entries = [entry for entry in entries if entry["canonical_id"] in candidates]
            info(f"Candidates admitted: {len(entries)}")
            info(f"Owner Domains: {len({entry['owner_domain'] for entry in entries})}")
            for domain in sorted({entry["owner_domain"] for entry in entries}):
                verbose_log(f"[DOMAIN] {domain} checks={sum(entry['owner_domain'] == domain for entry in entries)} rendered")
            success("Deep runtime generated")
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        error(exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
