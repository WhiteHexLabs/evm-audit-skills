#!/usr/bin/env python3
"""Synthesize a deterministic confirmed-only audit report."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_SUITE_ROOT = str(Path(__file__).resolve().parents[1])
if _SUITE_ROOT not in sys.path:
    sys.path.insert(0, _SUITE_ROOT)
from evm_audit_runtime.reporting import derive_issue_candidates, derive_poc_required_ids, poc_required
from evm_audit_runtime.routing import resolved_routes
from evm_audit_runtime.versions import ISSUE_CANDIDATES_VERSION

try:
    from audit_artifacts import (
        atomic_write_json,
        atomic_write_text,
        load_json,
        has_unresolved_marker,
        json_text,
        load_json_bytes,
        require_distinct_paths,
        report_bundle_metadata,
        validate_generated_artifact_path,
        review_state_digest,
        validate_poc_evidence,
        validate_artifact_identity,
        validate_domain_resolution,
        validate_review_state_binding,
        validate_schema,
        validate_target_snapshot,
    )
    from render_runtime import validate_manifest
    from review_ledger import collect_review_records
except ImportError:  # pragma: no cover
    from scripts.audit_artifacts import (
        atomic_write_json,
        atomic_write_text,
        load_json,
        has_unresolved_marker,
        json_text,
        load_json_bytes,
        require_distinct_paths,
        report_bundle_metadata,
        validate_generated_artifact_path,
        review_state_digest,
        validate_poc_evidence,
        validate_artifact_identity,
        validate_domain_resolution,
        validate_review_state_binding,
        validate_schema,
        validate_target_snapshot,
    )
    from scripts.render_runtime import validate_manifest
    from scripts.review_ledger import collect_review_records

try:
    from runtime_log import configure, error, success
except ImportError:  # pragma: no cover
    from scripts.runtime_log import configure, error, success


ROOT = Path(__file__).resolve().parents[1]

SEVERITY_DIMENSIONS = (
    "impact",
    "exploitability",
    "privileges",
    "capital_required",
    "repeatability",
    "user_interaction",
    "loss_bound",
    "protocol_exposure",
    "recoverability",
)


@dataclass(frozen=True)
class ReportSynthesisResult:
    """One current audit state and the outputs derived from it."""

    state: dict[str, Any]
    report: str
    issue_candidates: dict[str, Any]
    severity_decisions_bytes: bytes | None = None
    finding_details_bytes: bytes | None = None
    poc_evidence_bytes: bytes | None = None


def _consumed_input_bytes(
    value: dict[str, Any] | None,
    raw: bytes | None,
    label: str,
) -> bytes | None:
    if value is None:
        if raw is not None:
            raise ValueError(f"{label} bytes were supplied without an artifact")
        return None
    if raw is None:
        return json_text(value).encode("utf-8")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} bytes are not valid UTF-8 JSON") from error
    if parsed != value:
        raise ValueError(f"{label} bytes do not match the consumed artifact")
    return raw


def _provenance(check: dict[str, Any]) -> str:
    values: list[str] = []
    for item in check.get("provenance", []):
        if not isinstance(item, dict):
            continue
        label = str(item.get("label") or item.get("locator") or "").strip()
        url = str(item.get("url") or "").strip()
        if label and url:
            values.append(f"[{label}]({url})")
        elif label:
            values.append(label)
    return "; ".join(values) or "None recorded"


def _severity_decisions(value: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if value is None:
        return {}
    decisions = value.get("decisions")
    if not isinstance(decisions, dict):
        raise ValueError("severity decisions must contain a decisions object")
    return decisions


def _finding_details(value: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if value is None:
        return {}
    findings = value.get("findings")
    if not isinstance(findings, list):
        raise ValueError("finding details must contain a findings array")
    details: dict[str, dict[str, Any]] = {}
    for finding in findings:
        canonical_id = finding["canonical_id"]
        if canonical_id in details:
            raise ValueError(f"duplicate finding details: {canonical_id}")
        details[canonical_id] = finding
    return details


def _poc_projection(
    root: Path,
    value: dict[str, Any] | None,
    required_ids: list[str],
    decisions: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    if value is None:
        if required_ids:
            raise ValueError(f"INCOMPLETE_POC: runnable PoC required for {required_ids}")
        return {}
    try:
        validate_schema(root, "poc-evidence.schema.json", value)
        if value.get("artifact_state") == "TEMPLATE":
            raise ValueError("poc-evidence is still a TEMPLATE")
        findings = value.get("findings")
        if not isinstance(findings, list):
            raise ValueError("poc-evidence must contain a findings array")
        ids = [finding.get("canonical_id") for finding in findings]
        if ids != sorted(required_ids) or len(ids) != len(set(ids)):
            raise ValueError(
                "poc-evidence IDs do not match the current High/Critical projection: "
                f"expected={sorted(required_ids)} actual={ids}"
            )
        result: dict[str, dict[str, Any]] = {}
        for finding in findings:
            canonical_id = finding["canonical_id"]
            if finding["severity"] != decisions[canonical_id]["severity"] or not poc_required(finding["severity"]):
                raise ValueError(f"poc-evidence severity does not match current projection: {canonical_id}")
            result[canonical_id] = finding
        return result
    except (ValueError, KeyError, TypeError) as error:
        raise ValueError(f"INCOMPLETE_POC: {error}") from error


def _coverage_sets(state: dict[str, Any]) -> tuple[set[str], set[str], set[str]]:
    coverage = state["coverage"]
    selected = set(coverage["selected"])
    screen_not_applicable = set(coverage["screen_not_applicable"])
    candidates = set(coverage["deep_candidates"])
    if screen_not_applicable & candidates or screen_not_applicable | candidates != selected:
        raise ValueError("audit-state coverage equation failed")
    return selected, screen_not_applicable, candidates


def _issue_artifact(
    root: Path,
    manifest: dict[str, Any],
    state: dict[str, Any],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    identity = manifest["audit_context"]
    value = {
        "schema_version": ISSUE_CANDIDATES_VERSION,
        "routing_snapshot_id": manifest["routing_snapshot_id"],
        "review_snapshot_id": state["review_snapshot_id"],
        "review_state_digest": state["review_state_digest"],
        "registry_sha256": identity["registry_sha256"],
        "source_digest": identity["source_digest"],
        "compilation_input_digest": identity["compilation_input_digest"],
        "findings": findings,
    }
    validate_schema(root, "issue-candidates.schema.json", value)
    return value


def synthesize(
    root: Path,
    manifest: dict[str, Any],
    registry: dict[str, Any],
    state: dict[str, Any],
    ledger_paths: list[Path],
    severity_decisions: dict[str, Any] | None = None,
    *,
    finding_details: dict[str, Any] | None = None,
    severity_decisions_bytes: bytes | None = None,
    finding_details_bytes: bytes | None = None,
    poc_evidence: dict[str, Any] | None = None,
    poc_evidence_bytes: bytes | None = None,
    allow_incomplete: bool = False,
    domain_resolution: dict[str, Any] | None = None,
    screen_results: dict[str, Any] | None = None,
    domain_context: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
    managed_output_root: Path | None = None,
) -> ReportSynthesisResult:
    validate_manifest(root, manifest, registry)
    validate_target_snapshot(manifest, managed_output_root=managed_output_root)
    try:
        from validate_audit_run import validate_run
    except ImportError:  # pragma: no cover - package-style import
        from scripts.validate_audit_run import validate_run

    state = validate_run(
        root,
        manifest,
        registry,
        screen_results,
        domain_resolution,
        domain_context,
        context,
        ledger_paths,
        managed_output_root=managed_output_root,
    )
    validate_schema(root, "audit-state.schema.json", state)
    validate_artifact_identity(state, manifest)
    if state["recon_quality"] != manifest["feature_map"]["recon_context"]["recon_quality"]:
        raise ValueError("audit-state Recon quality does not match the routing manifest")
    selected, _, candidates = _coverage_sets(state)
    active_ids = {entry["canonical_id"] for entry in resolved_routes(manifest, domain_resolution)}
    if selected != active_ids:
        raise ValueError("audit-state selected coverage does not match the resolved routing manifest")
    latest, errors = collect_review_records(
        ledger_paths, manifest, registry, candidates, domain_resolution, state["review_snapshot_id"]
    )
    if errors:
        raise ValueError("; ".join(errors))
    confirmed = {canonical_id for canonical_id, record in latest.items() if record["status"] == "CONFIRMED"}
    suspicious = {canonical_id for canonical_id, record in latest.items() if record["status"] == "SUSPICIOUS"}
    reviewed = set(latest)
    declared_reviewed = set(state["coverage"]["deep_reviewed"])
    if reviewed != declared_reviewed:
        raise ValueError("audit-state deep_reviewed coverage does not match latest ledger state")
    if state["complete"] and reviewed != candidates:
        raise ValueError("complete audit-state requires a current review for every Deep candidate")
    declared_confirmed = set(state["coverage"]["confirmed"])
    if confirmed != declared_confirmed:
        raise ValueError("audit-state confirmed coverage does not match latest ledger state")
    if suspicious != set(state["coverage"]["suspicious"]):
        raise ValueError("audit-state suspicious coverage does not match latest ledger state")
    current_digest = None
    if not errors and candidates <= reviewed and state["review_snapshot_id"] is not None:
        current_digest = review_state_digest(latest, candidates)
    if current_digest != state["review_state_digest"]:
        raise ValueError("audit-state review_state_digest does not match latest ledger state")
    if state["complete"] and state["status"] not in {"COMPLETE_CLEAN", "COMPLETE_WITH_FINDINGS"}:
        raise ValueError("audit-state marks an invalid complete status")
    if state["complete"] and state["coverage"]["unresolved"]:
        raise ValueError("complete audit-state cannot contain unresolved review IDs")
    if state["status"] == "COMPLETE_CLEAN" and not state["clean"]:
        raise ValueError("COMPLETE_CLEAN must set clean=true")
    if state["status"] == "COMPLETE_WITH_FINDINGS" and state["clean"]:
        raise ValueError("COMPLETE_WITH_FINDINGS must set clean=false")

    severity_decisions_bytes = _consumed_input_bytes(
        severity_decisions, severity_decisions_bytes, "severity decisions"
    )
    finding_details_bytes = _consumed_input_bytes(
        finding_details, finding_details_bytes, "finding details"
    )
    poc_evidence_bytes = _consumed_input_bytes(
        poc_evidence, poc_evidence_bytes, "poc evidence"
    )
    decisions: dict[str, dict[str, Any]] = {}
    if severity_decisions is not None:
        try:
            validate_schema(root, "severity-decisions.schema.json", severity_decisions)
            validate_artifact_identity(severity_decisions, manifest)
            validate_review_state_binding(severity_decisions, current_digest)
            decisions = _severity_decisions(severity_decisions)
            if any(
                has_unresolved_marker(
                    decision.get("severity"),
                    decision.get("rationale"),
                    *(decision.get("dimensions", {}).values() if isinstance(decision.get("dimensions"), dict) else ()),
                )
                for decision in decisions.values()
            ):
                raise ValueError("severity artifact contains unresolved field markers")
        except (ValueError, KeyError, TypeError) as error:
            raise ValueError(f"INCOMPLETE_SEVERITY: {error}") from error
    for canonical_id in decisions:
        if canonical_id not in latest:
            raise ValueError(f"INCOMPLETE_SEVERITY: decision has no latest review record: {canonical_id}")
        if latest[canonical_id]["status"] != "CONFIRMED":
            raise ValueError(f"INCOMPLETE_SEVERITY: severity is only allowed for CONFIRMED records: {canonical_id}")

    if not state["complete"] and not allow_incomplete:
        raise ValueError("refusing to synthesize a final report from an incomplete audit")

    if not state["complete"]:
        report = "\n".join([
            "# INCOMPLETE AUDIT",
            "",
            f"- **Status:** `{state['status']}`",
            "- **Complete:** `false`",
            "- **Clean:** `false`",
            f"- **Recon quality:** `{state['recon_quality']['mode']}`",
            f"- **Routing snapshot:** `{manifest['routing_snapshot_id']}`",
            f"- **Review snapshot:** `{state['review_snapshot_id']}`",
            f"- **Review state digest:** `{state['review_state_digest']}`",
            f"- **Registry:** `{manifest['audit_context']['registry_sha256']}`",
            f"- **Source digest:** `{manifest['audit_context']['source_digest']}`",
            f"- **Compilation input digest:** `{manifest['audit_context']['compilation_input_digest']}`",
            "",
            "This artifact is not a final vulnerability report. Resolve the listed audit-state reasons before reporting findings.",
            "",
            "## Reasons",
            *[f"- {reason}" for reason in state["reasons"]],
            "",
        ])
        return ReportSynthesisResult(
            state,
            report,
            _issue_artifact(root, manifest, state, []),
            severity_decisions_bytes,
            finding_details_bytes,
            None,
        )

    if confirmed and severity_decisions is None:
        raise ValueError(f"INCOMPLETE_SEVERITY: missing severity decisions for {sorted(confirmed)}")
    missing_severity = confirmed - set(decisions)
    extra_severity = set(decisions) - confirmed
    if missing_severity:
        raise ValueError(f"INCOMPLETE_SEVERITY: missing severity decisions for {sorted(missing_severity)}")
    if extra_severity:
        raise ValueError(f"INCOMPLETE_SEVERITY: decisions are not for CONFIRMED records: {sorted(extra_severity)}")

    details: dict[str, dict[str, Any]] = {}
    if finding_details is not None:
        try:
            validate_schema(root, "finding-details.schema.json", finding_details)
            validate_artifact_identity(finding_details, manifest)
            validate_review_state_binding(finding_details, current_digest)
            details = _finding_details(finding_details)
            if any(
                has_unresolved_marker(
                    finding.get("location"), finding.get("description"), finding.get("recommendation")
                )
                for finding in details.values()
            ):
                raise ValueError("finding details contain unresolved field markers")
        except (ValueError, KeyError, TypeError) as error:
            raise ValueError(f"INCOMPLETE_REPORTING: {error}") from error
    if confirmed and finding_details is None:
        raise ValueError(f"INCOMPLETE_REPORTING: missing finding details for {sorted(confirmed)}")
    missing_details = confirmed - set(details)
    extra_details = set(details) - confirmed
    if missing_details:
        raise ValueError(f"INCOMPLETE_REPORTING: missing finding details for {sorted(missing_details)}")
    if extra_details:
        raise ValueError(f"INCOMPLETE_REPORTING: details are not for CONFIRMED records: {sorted(extra_details)}")

    required_poc_ids = derive_poc_required_ids(confirmed, decisions)
    poc_findings = _poc_projection(root, poc_evidence, required_poc_ids, decisions)
    if not required_poc_ids:
        poc_evidence_bytes = None

    if state["status"] == "COMPLETE_CLEAN" and confirmed:
        raise ValueError("COMPLETE_CLEAN cannot contain confirmed findings")
    if state["status"] == "COMPLETE_WITH_FINDINGS" and not confirmed:
        raise ValueError("COMPLETE_WITH_FINDINGS requires confirmed findings")

    checks = {check["canonical_id"]: check for check in registry.get("checks", [])}
    report_lines = [
        "# EVM Audit Report",
        "",
        f"- **Status:** `{state['status']}`",
        f"- **Complete:** `{str(state['complete']).lower()}`",
        f"- **Clean:** `{str(state['clean']).lower()}`",
        f"- **Routing snapshot:** `{manifest['routing_snapshot_id']}`",
        f"- **Review snapshot:** `{state['review_snapshot_id']}`",
        f"- **Review state digest:** `{state['review_state_digest']}`",
        f"- **Registry:** `{manifest['audit_context']['registry_sha256']}`",
        f"- **Source digest:** `{manifest['audit_context']['source_digest']}`",
        f"- **Compilation input digest:** `{manifest['audit_context']['compilation_input_digest']}`",
        f"- **Recon quality:** `{state['recon_quality']['mode']}`",
        "",
        "## Findings",
    ]
    if not confirmed:
        report_lines.extend(["", "No confirmed findings were established within the reviewed scope."])
    for canonical_id in sorted(confirmed):
        record = latest[canonical_id]
        check = checks.get(canonical_id)
        if check is None:
            raise ValueError(f"confirmed record is absent from registry: {canonical_id}")
        decision = decisions[canonical_id]
        severity = decision["severity"]
        detail = details[canonical_id]
        report_lines.extend([
            "",
            f"### [{canonical_id}] {check['title']}",
            "- **Status:** `CONFIRMED`",
            f"- **Checklist reference:** `{canonical_id}`",
            f"- **Provenance references:** {_provenance(check)}",
            f"- **Severity:** {severity}",
            f"- **Severity rationale:** {decision['rationale']}",
            "- **Severity dimensions:** " + "; ".join(
                f"{dimension}={decision['dimensions'][dimension]}" for dimension in SEVERITY_DIMENSIONS
            ),
            f"- **Category:** {record['owner_domain']}",
            f"- **Location:** {detail['location']}",
            f"- **Applicability:** {record['applicability']}",
            f"- **Code path:** {record['code_path']}",
            f"- **Preconditions:** {record['preconditions']}",
            f"- **Exploitability:** {record['exploitability']}",
            f"- **Impact:** {record['impact']}",
            f"- **Strong proof evidence:** {record['proof']}",
            f"- **Description:** {detail['description']}",
            f"- **Recommendation:** {detail['recommendation']}",
        ])
        if poc_required(severity):
            poc = poc_findings[canonical_id]
            sources = ", ".join(f"`{source['path']}`" for source in poc["sources"])
            report_lines.extend([
                f"- **PoC:** {sources}",
                f"- **Reproduce:** `{poc['command']}`",
            ])
        else:
            report_lines.append("- **PoC:** Not required by policy (severity below High)")
    report_lines.append("")
    return ReportSynthesisResult(
        state,
        "\n".join(report_lines),
        _issue_artifact(root, manifest, state, derive_issue_candidates(confirmed, decisions)),
        severity_decisions_bytes,
        finding_details_bytes,
        poc_evidence_bytes,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, help="audit run directory used to resolve durable PoC sources")
    parser.add_argument("--audit-state", type=Path, help="derived state cache; never used as report authority")
    parser.add_argument("--registry", type=Path, default=ROOT / "data/canonical-checks.json")
    parser.add_argument("--ledger", type=Path, action="append", default=[])
    parser.add_argument("--domain-resolution", type=Path)
    parser.add_argument("--screen-results", type=Path, required=True)
    parser.add_argument("--domain-context", type=Path, required=True)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--severity-decisions", type=Path)
    parser.add_argument("--finding-details", type=Path)
    parser.add_argument("--poc-evidence", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--issue-candidates-out", type=Path)
    parser.add_argument("--bundle-metadata-out", type=Path)
    parser.add_argument("--allow-incomplete", action="store_true", help="write an explicitly incomplete artifact")
    parser.add_argument(
        "--managed-output-root",
        type=Path,
        help="controller-owned audit output root; required when the run lives inside the audited project",
    )
    parser.add_argument("--quiet", action="store_true", help="suppress progress output")
    args = parser.parse_args(argv)
    configure(quiet=args.quiet)
    try:
        bundle_path = args.bundle_metadata_out or (args.output.with_name("report-bundle.json") if args.output and args.issue_candidates_out else None)
        require_distinct_paths(
            ("manifest", args.manifest),
            ("registry", args.registry),
            ("audit state", args.audit_state),
            ("screen results", args.screen_results),
            ("domain resolution", args.domain_resolution),
            ("domain context", args.domain_context),
            ("context", args.context),
            ("severity decisions", args.severity_decisions),
            ("finding details", args.finding_details),
            ("poc evidence", args.poc_evidence),
            ("report", args.output),
            ("issue-candidates", args.issue_candidates_out),
            ("report-bundle", bundle_path),
        )
        manifest = load_json(args.manifest)
        registry = load_json(args.registry)
        recon_context = manifest.get("feature_map", {}).get("recon_context", {})
        for label, output in (
            ("report", args.output),
            ("issue-candidates", args.issue_candidates_out),
            ("report-bundle", bundle_path),
        ):
            if output is not None:
                validate_generated_artifact_path(
                    output,
                    audit_root=Path(recon_context["target_root"]),
                    build_root=Path(recon_context["build_root"]),
                    label=label,
                    managed_output_root=args.managed_output_root,
                )
        state = load_json(args.audit_state) if args.audit_state else {}
        severity = severity_bytes = None
        if args.severity_decisions:
            severity, severity_bytes = load_json_bytes(args.severity_decisions)
        finding_details = finding_details_bytes = None
        if args.finding_details:
            finding_details, finding_details_bytes = load_json_bytes(args.finding_details)
        poc_evidence = poc_evidence_bytes = None
        if args.poc_evidence:
            if args.run_dir is None:
                raise ValueError("--run-dir is required when validating --poc-evidence")
            poc_evidence, poc_evidence_bytes = load_json_bytes(args.poc_evidence)
        domain_resolution = load_json(args.domain_resolution) if args.domain_resolution else None
        screen_results = load_json(args.screen_results)
        domain_context = load_json(args.domain_context)
        context = load_json(args.context)
        synthesis = synthesize(
            ROOT,
            manifest,
            registry,
            state,
            args.ledger,
            severity,
            finding_details=finding_details,
            severity_decisions_bytes=severity_bytes,
            finding_details_bytes=finding_details_bytes,
            poc_evidence=poc_evidence,
            poc_evidence_bytes=poc_evidence_bytes,
            allow_incomplete=args.allow_incomplete,
            domain_resolution=domain_resolution,
            screen_results=screen_results,
            domain_context=domain_context,
            context=context,
            managed_output_root=args.managed_output_root,
        )
        current_state = synthesis.state
        if poc_evidence is not None:
            validate_poc_evidence(
                ROOT,
                manifest,
                current_state,
                severity,
                severity_bytes,
                poc_evidence,
                run_dir=args.run_dir.resolve() if args.run_dir else None,
            )
        report = synthesis.report
        issues = synthesis.issue_candidates
        bundle = None
        if bundle_path is not None:
            if not args.output or not args.issue_candidates_out:
                raise ValueError("report bundle requires --output and --issue-candidates-out")
            bundle = report_bundle_metadata(
                manifest,
                current_state,
                report,
                issues,
                issue_candidates_bytes=json_text(issues).encode("utf-8"),
                severity_decisions_bytes=synthesis.severity_decisions_bytes,
                finding_details_bytes=synthesis.finding_details_bytes,
                severity_decisions=severity,
                poc_evidence_bytes=synthesis.poc_evidence_bytes,
                poc_evidence=poc_evidence,
            )
            validate_schema(ROOT, "report-bundle.schema.json", bundle)
        if args.output:
            atomic_write_text(args.output, report)
        else:
            print(report, end="")
        if args.issue_candidates_out:
            atomic_write_json(args.issue_candidates_out, issues)
        if bundle is not None:
            atomic_write_json(bundle_path, bundle)
        success("Confirmed-only report synthesized")
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        error(exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
