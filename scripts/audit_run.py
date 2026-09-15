#!/usr/bin/env python3
"""Advance an audit run through deterministic artifact stages."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from evm_audit_runtime.versions import POC_EVIDENCE_VERSION, POC_VERIFICATION_VERSION, REPORT_CURRENT_VERSION, REPORTING_VERSION, REPOSITORY_TRUST_VERSION
from evm_audit_runtime.reporting import derive_poc_required_ids
from evm_audit_runtime.repository_trust import copy_tree, prepare_repository
from evm_audit_runtime.controller_state import STAGE_PROGRESS, display_stage as _display_stage, progress_metadata

try:
    from runtime_log import configure, error, info, stage, success, warning
except ImportError:  # pragma: no cover
    from scripts.runtime_log import configure, error, info, stage, success, warning

try:
    from codex_model_profile import (
        PROVIDERS,
        default_profile,
        global_profile_path,
        init_global_profile,
        load_profile,
        load_global_profile,
        stage_model,
        write_profile,
    )
except ImportError:  # pragma: no cover
    from scripts.codex_model_profile import (
        PROVIDERS,
        default_profile,
        global_profile_path,
        init_global_profile,
        load_profile,
        load_global_profile,
        stage_model,
        write_profile,
    )

try:
    from audit_artifacts import (
        atomic_write_bytes,
        atomic_write_json,
        atomic_write_text,
        bound_code_index_status,
        canonical_sha256,
        derive_review_snapshot_id,
        durable_replace_directory,
        fsync_directory_tree,
        json_text,
        load_json,
        load_json_bytes,
        poc_source_snapshot_name,
        poc_error_code,
        report_bundle_metadata,
        reporting_inputs_digest,
        reporting_inputs_digest_from_hashes,
        restore_file,
        snapshot_file,
        validate_report_generation,
        validate_artifact_identity,
        validate_domain_context,
        validate_domain_resolution,
        validate_issue_candidates,
        validate_poc_evidence,
        validate_reporting_inputs,
        validate_schema,
        validate_target_snapshot,
    )
    from render_runtime import runtime_identity, selected_entries, validate_manifest, validate_screen_results
    from review_ledger import _ledger_lock, collect_review_records, ledger_content_digest
    from synthesize_report import synthesize
    from validate_audit_run import validate_run
except ImportError:  # pragma: no cover
    from scripts.audit_artifacts import (
        atomic_write_bytes,
        atomic_write_json,
        atomic_write_text,
        bound_code_index_status,
        canonical_sha256,
        derive_review_snapshot_id,
        durable_replace_directory,
        fsync_directory_tree,
        json_text,
        load_json,
        load_json_bytes,
        poc_source_snapshot_name,
        poc_error_code,
        report_bundle_metadata,
        reporting_inputs_digest,
        reporting_inputs_digest_from_hashes,
        restore_file,
        snapshot_file,
        validate_report_generation,
        validate_artifact_identity,
        validate_domain_context,
        validate_domain_resolution,
        validate_issue_candidates,
        validate_poc_evidence,
        validate_reporting_inputs,
        validate_schema,
        validate_target_snapshot,
    )
    from scripts.render_runtime import runtime_identity, selected_entries, validate_manifest, validate_screen_results
    from scripts.review_ledger import _ledger_lock, collect_review_records, ledger_content_digest
    from scripts.synthesize_report import synthesize
    from scripts.validate_audit_run import validate_run

try:
    from scope_context import resolve_build_root, validate_run_dir_isolation
except ImportError:  # pragma: no cover
    from scripts.scope_context import resolve_build_root, validate_run_dir_isolation


ROOT = Path(__file__).resolve().parents[1]
VERBOSE_CHILD_SCRIPTS = {"select_checks.py", "render_runtime.py"}
REPORTING_DIMENSIONS = (
    "impact", "exploitability", "privileges", "capital_required",
    "repeatability", "user_interaction", "loss_bound", "protocol_exposure",
    "recoverability",
)
REPORTING_IDENTITY_KEYS = (
    "schema_version", "routing_snapshot_id", "review_state_digest",
    "registry_sha256", "source_digest", "compilation_input_digest",
)
POC_IDENTITY_KEYS = REPORTING_IDENTITY_KEYS + ("severity_decisions_sha256",)
POC_WORKSPACE_POLICY_VERSION = "2"
POC_ENVIRONMENT_POLICY_VERSION = "1"
POC_NETWORK_POLICY = "NO_RPC_CREDENTIALS_OS_NETWORK_UNRESTRICTED"
POC_FFI_POLICY = "DISABLED"


@dataclass(frozen=True)
class CurrentReportingInputs:
    severity: dict[str, Any] | None
    severity_bytes: bytes | None
    finding_details: dict[str, Any] | None
    finding_details_bytes: bytes | None
    poc_evidence: dict[str, Any] | None
    poc_evidence_bytes: bytes | None
    required_poc_ids: tuple[str, ...]
    digest: str | None


@dataclass(frozen=True)
class ResolvedPocCommand:
    runner: str
    executable: Path
    argv: tuple[str, ...]
    entrypoint: str


@dataclass(frozen=True)
class PreparedReportPublication:
    state: dict[str, Any]
    publication_identity: dict[str, Any]
    reporting_inputs: CurrentReportingInputs
    reporting_inputs_digest: str | None
    report_bytes: bytes
    issue_candidates_bytes: bytes
    bundle_bytes: bytes
    generation_digest: str
    required_poc_ids: tuple[str, ...]
    report: str = ""
    issue_candidates: dict[str, Any] | None = None
    severity_decisions: dict[str, Any] | None = None
    finding_details: dict[str, Any] | None = None
    poc_evidence: dict[str, Any] | None = None
    write_severity: bool = False
    write_finding_details: bool = False
    write_poc_evidence: bool = False


def paths(run_dir: Path) -> dict[str, Any]:
    return {
        "feature_map": run_dir / "recon/feature-map.json",
        "code_index": run_dir / "recon/code-index.json",
        "manifest": run_dir / "routing/manifest.json",
        "context": run_dir / "context.json",
        "environment": run_dir / "routing/environment-context.json",
        "resolution": run_dir / "reviews/domain-resolution.json",
        "domain_context": run_dir / "reviews/domain-context.json",
        "screen": run_dir / "runtime/screen.md",
        "screen_results": run_dir / "reviews/screen-results.json",
        "audit_state": run_dir / "audit-state.json",
        "report": run_dir / "AUDIT-REPORT.md",
        "issue_candidates": run_dir / "issue-candidates.json",
        "report_bundle": run_dir / "report-bundle.json",
        "report_current": run_dir / "report-current.json",
        "report_generations": run_dir / "report-generations",
        "severity_decisions": run_dir / "reviews/severity-decisions.json",
        "finding_details": run_dir / "reviews/finding-details.json",
        "report_input_severity": run_dir / "report-inputs/severity-decisions.json",
        "report_input_details": run_dir / "report-inputs/finding-details.json",
        "poc_evidence": run_dir / "reviews/poc-evidence.json",
        "poc_verification": run_dir / "reviews/poc-verification.json",
        "model_profile": run_dir / "config/codex-model-profile.json",
        "repository_trust": run_dir / "config/repository-trust.json",
    }


def _compact_failure(output: str) -> str:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    for line in reversed(lines):
        if line.startswith("ERROR:"):
            return line.removeprefix("ERROR:").strip()
    return lines[-1] if lines else ""


def _run(root: Path, script: str, arguments: list[str], *, verbose: bool = False) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, str(root / "scripts" / script), *arguments]
    if verbose and script in VERBOSE_CHILD_SCRIPTS:
        command.append("--verbose")
    result = subprocess.run(
        command,
        cwd=root,
        capture_output=True,
        text=True,
    )
    if verbose and result.stderr:
        sys.stderr.write(result.stderr)
        if not result.stderr.endswith("\n"):
            sys.stderr.write("\n")
    if result.returncode:
        detail = _compact_failure(result.stderr or result.stdout) or f"exit={result.returncode}"
        raise ValueError(f"{script} failed: {detail}")
    return result


def _render_screen(root: Path, values: dict[str, Path], *extra: str, verbose: bool = False) -> None:
    values["screen"].parent.mkdir(parents=True, exist_ok=True)
    _run(
        root,
        "render_runtime.py",
        [
            "--manifest", str(values["manifest"]),
            "--profile", "screen",
            "--output", str(values["screen"]),
            "--managed-output-root", str(values["manifest"].parent.parent),
            *extra,
        ],
        verbose=verbose,
    )


def _emit_stage(stage_name: str, detail: str) -> None:
    stage(stage_name, detail=detail)


def _stage_label(stage_name: str) -> str:
    return progress_metadata(stage_name)["label"]


def _effective_model_profile(run_dir: Path) -> dict[str, Any]:
    profile_path = paths(run_dir.resolve())["model_profile"]
    return load_profile(profile_path) if profile_path.exists() else default_profile()


def recommended_execution(run_dir: Path, stage_name: str) -> dict[str, str]:
    profile = _effective_model_profile(run_dir)
    return {"provider": profile["provider"], **stage_model(profile, stage_name)}


def _log_model_guidance(run_dir: Path | None, stage_name: str) -> None:
    if run_dir is None:
        return
    execution = recommended_execution(run_dir, stage_name)
    label = "Codex" if execution["provider"] == "codex" else "Agent"
    info(f"{label} model: {execution['model']}")
    if execution["provider"] == "codex":
        info(f"Reasoning: {execution['reasoning_effort']}")
    else:
        info(f"Thought level: {execution['thought_level']}")
    if execution.get("agent") is not None:
        info(f"Worker agent: {execution['agent']}")
    if execution["provider"] == "codex":
        info("Handoff: controller does not switch the active Codex model")
    else:
        info("Handoff: controller does not switch its own model or thought level; workers run on their configured agent types")


def _stage_result(
    run_dir: Path,
    stage_name: str,
    *,
    summary: str | None = None,
    navigation: dict[str, Any] | None = None,
    **values: Any,
) -> dict[str, Any]:
    result = {
        "stage": stage_name,
        **values,
        "progress": progress_metadata(stage_name, summary=summary),
        "recommended_execution": recommended_execution(run_dir, stage_name),
    }
    if navigation is not None:
        result["navigation"] = navigation
    return result


def _progress_history_entry(
    run_dir: Path,
    stage_name: str,
    state: str,
    *,
    summary: str | None = None,
) -> dict[str, Any]:
    return {
        "stage": stage_name,
        "state": state,
        "progress": progress_metadata(stage_name, summary=summary),
        "recommended_execution": recommended_execution(run_dir, stage_name),
    }


def _recon_progress_summary(feature_map: dict[str, Any]) -> str:
    recon = feature_map["recon_context"]
    files_analyzed = recon.get("files_analyzed", [])
    file_count = len(files_analyzed) if isinstance(files_analyzed, list) else 0
    compilation = "COMPLETE" if recon.get("compilation_complete") else "INCOMPLETE"
    return f"{file_count} Solidity files analyzed; compilation {compilation}"


def _routing_progress_summary(manifest: dict[str, Any]) -> str:
    return (
        f"{len(manifest['selected_domains'])} selected domains; "
        f"{manifest['selected_count']} checks selected; "
        f"{len(manifest['deferred_domains'])} deferred domains; "
        f"{manifest['deferred_count']} checks deferred"
    )


def _unknown_domains(resolution: dict[str, Any] | None) -> set[str] | None:
    if resolution is None:
        return None
    return {
        domain
        for domain, value in resolution.get("domains", {}).items()
        if isinstance(value, dict) and value.get("status") == "UNKNOWN"
    }


def _unknown_context(domain_context: dict[str, Any] | None) -> set[str] | None:
    if domain_context is None:
        return None
    return {
        f"{domain}.{key}"
        for domain, requirements in domain_context.get("domains", {}).items()
        if isinstance(requirements, dict)
        for key, value in requirements.items()
        if isinstance(value, dict) and value.get("status") == "UNKNOWN"
    }


def _state_stage(
    state: dict[str, Any],
    manifest: dict[str, Any],
    resolution: dict[str, Any] | None,
    domain_context: dict[str, Any] | None,
) -> str | None:
    status = state.get("status")
    coverage = state.get("coverage", {})
    if status == "INCOMPLETE_DOMAIN_ROUTING":
        return "DOMAIN_RESOLUTION"
    if status == "INCOMPLETE_CONTEXT":
        return "DOMAIN_CONTEXT"
    if status == "INCOMPLETE_COVERAGE":
        unresolved_domains = _unknown_domains(resolution)
        if manifest.get("deferred_domains") and (unresolved_domains is None or unresolved_domains):
            return "DOMAIN_RESOLUTION"
        if domain_context is None or _unknown_context(domain_context):
            return "DOMAIN_CONTEXT"
        return "SCREEN"
    if status == "INCOMPLETE_REVIEW":
        candidates = coverage.get("deep_candidates", []) if isinstance(coverage, dict) else []
        reviewed = coverage.get("deep_reviewed", []) if isinstance(coverage, dict) else []
        if isinstance(candidates, list) and isinstance(reviewed, list) and set(candidates) - set(reviewed):
            return "DEEP_REVIEW"
        if isinstance(coverage, dict) and coverage.get("suspicious"):
            return "PROOF"
        return "DEEP_REVIEW"
    if status in {"COMPLETE_CLEAN", "COMPLETE_WITH_FINDINGS"}:
        return "REPORT"
    return None


def _log_recon(feature_map: dict[str, Any], target: Path, strict: bool, *, run_dir: Path | None = None) -> None:
    recon = feature_map["recon_context"]
    complete = recon["compilation_complete"]
    info(f"Audit scope: {target}")
    info(f"Compilation: {'COMPLETE' if complete else 'INCOMPLETE'}")
    _log_model_guidance(run_dir, "RECON")
    if complete:
        success(f"{_stage_label('RECON')} complete")
    else:
        warning(f"{_stage_label('RECON')} compilation coverage is incomplete")
        if strict:
            warning("Strict compilation policy rejected this scope")


def _log_routing(manifest: dict[str, Any], *, run_dir: Path | None = None) -> None:
    info(f"Selected domains: {len(manifest['selected_domains'])}")
    info(f"Deferred domains: {len(manifest['deferred_domains'])}")
    info(f"Filtered domains: {len(manifest['filtered_domains'])}")
    info(f"Selected checks: {manifest['selected_count']}")
    info(f"Deferred checks: {manifest['deferred_count']}")
    info(f"Filtered checks: {manifest['filtered_count']}")
    _log_model_guidance(run_dir, "ROUTING")
    success(f"{_stage_label('ROUTING')} snapshot created")


def _log_domain_resolution(
    manifest: dict[str, Any], unresolved: set[str] | None = None, *, run_dir: Path | None = None
) -> None:
    _emit_stage("DOMAIN_RESOLUTION", "Resolving deferred protocol context")
    _log_model_guidance(run_dir, "DOMAIN_RESOLUTION")
    total = len(manifest["deferred_domains"])
    remaining = unresolved if unresolved is not None else {entry["domain"] for entry in manifest["deferred_domains"]}
    info(f"Resolved: {total - len(remaining)} / {total}")
    if remaining:
        warning(f"{_stage_label('DOMAIN_RESOLUTION')} items remaining: {len(remaining)}")
    else:
        success(f"{_stage_label('DOMAIN_RESOLUTION')} routing resolved")


def _context_requirement_count(manifest: dict[str, Any]) -> int:
    return sum(
        len(requirements)
        for requirements in manifest.get("required_context_requirements", {}).values()
        if isinstance(requirements, dict)
    )


def _domain_resolution_summary(
    manifest: dict[str, Any], unresolved: set[str] | None = None
) -> str:
    remaining = (
        unresolved
        if unresolved is not None
        else {entry["domain"] for entry in manifest.get("deferred_domains", [])}
    )
    if remaining:
        suffix = "remain unresolved" if unresolved is not None else "require resolution"
        return f"{len(remaining)} {_stage_label('DOMAIN_RESOLUTION')} items {suffix}"
    return f"All {_stage_label('DOMAIN_RESOLUTION')} routing resolved"


def _domain_context_summary(
    manifest: dict[str, Any], unresolved: set[str] | None = None
) -> str:
    if unresolved is None:
        remaining = {
            f"{domain}.{key}"
            for domain, requirements in manifest.get("required_context_requirements", {}).items()
            if isinstance(requirements, dict)
            for key in requirements
        }
        suffix = "need resolution"
    else:
        remaining = unresolved
        suffix = "remain unresolved"
    if remaining:
        return f"{len(remaining)} required context fields {suffix}"
    return f"All {_stage_label('DOMAIN_CONTEXT')} resolved"


def _screen_summary(
    manifest: dict[str, Any],
    *,
    resolution: dict[str, Any] | None = None,
    coverage: dict[str, Any] | None = None,
) -> str:
    selected = (
        set(coverage.get("selected", []))
        if isinstance(coverage, dict) and isinstance(coverage.get("selected"), list)
        else {entry["canonical_id"] for entry in selected_entries(manifest, domain_resolution=resolution)}
    )
    if isinstance(coverage, dict):
        classified = set(coverage.get("screen_not_applicable", [])) | set(coverage.get("deep_candidates", []))
        remaining = selected - classified
    else:
        remaining = selected
    return f"{len(remaining)} checks require {_stage_label('SCREEN')} classification"


def _state_progress_summary(
    stage_name: str,
    state: dict[str, Any],
    manifest: dict[str, Any],
    resolution: dict[str, Any] | None,
    domain_context: dict[str, Any] | None,
) -> str:
    coverage = state.get("coverage", {})
    if stage_name == "DOMAIN_RESOLUTION":
        return _domain_resolution_summary(manifest, _unknown_domains(resolution))
    if stage_name == "DOMAIN_CONTEXT":
        return _domain_context_summary(manifest, _unknown_context(domain_context))
    if stage_name == "SCREEN":
        return _screen_summary(manifest, resolution=resolution, coverage=coverage)
    if stage_name == "DEEP_REVIEW":
        candidates = coverage.get("deep_candidates", []) if isinstance(coverage, dict) else []
        reviewed = coverage.get("deep_reviewed", []) if isinstance(coverage, dict) else []
        pending = set(candidates) - set(reviewed) if isinstance(candidates, list) and isinstance(reviewed, list) else set()
        return f"{len(pending)} {_stage_label(stage_name)} candidates remain"
    if stage_name == "PROOF":
        suspicious = coverage.get("suspicious", []) if isinstance(coverage, dict) else []
        return f"{len(suspicious) if isinstance(suspicious, list) else 0} suspicious findings require {_stage_label(stage_name)}"
    if stage_name == "REPORT":
        return f"Audit state: {state.get('status', 'UNKNOWN')}"
    return progress_metadata(stage_name)["summary"]


def _log_domain_context(
    manifest: dict[str, Any], unresolved: set[str] | None = None, *, run_dir: Path | None = None
) -> None:
    _emit_stage("DOMAIN_CONTEXT", "Resolving required protocol context")
    _log_model_guidance(run_dir, "DOMAIN_CONTEXT")
    total = _context_requirement_count(manifest)
    if unresolved is None:
        remaining = {
            f"{domain}.{key}"
            for domain, requirements in manifest.get("required_context_requirements", {}).items()
            if isinstance(requirements, dict)
            for key in requirements
        }
    else:
        remaining = unresolved
    info(f"Resolved: {total - len(remaining)} / {total}")
    if remaining:
        warning(f"{_stage_label('DOMAIN_CONTEXT')} items remaining: {len(remaining)}")
    else:
        success(f"{_stage_label('DOMAIN_CONTEXT')} complete")


def _log_screen(screen: dict[str, Any], candidates: set[str], *, run_dir: Path | None = None) -> None:
    results = screen.get("results", [])
    total = len(results) if isinstance(results, list) else 0
    _emit_stage("SCREEN", "Triaging routed checks")
    _log_model_guidance(run_dir, "SCREEN")
    info(f"{_stage_label('SCREEN')} checks: {total}")
    info(f"{_stage_label('DEEP_REVIEW')} candidates: {len(candidates)}")
    info(f"{_stage_label('SCREEN')} NOT_APPLICABLE: {total - len(candidates)}")
    success(f"{_stage_label('SCREEN')} complete")


def _log_deep(candidates: set[str], records: dict[str, dict[str, Any]], pending: set[str]) -> None:
    suspicious = sum(record.get("status") == "SUSPICIOUS" for record in records.values())
    confirmed = sum(record.get("status") == "CONFIRMED" for record in records.values())
    info(f"Reviewed: {len(records)} / {len(candidates)}")
    info(f"Remaining: {len(pending)}")
    info(f"Suspicious: {suspicious}")
    info(f"Confirmed: {confirmed}")


def _log_report(state: dict[str, Any], *, finished: bool, run_dir: Path | None = None) -> None:
    coverage = state.get("coverage", {})
    confirmed = coverage.get("confirmed", []) if isinstance(coverage, dict) else []
    suspicious = coverage.get("suspicious", []) if isinstance(coverage, dict) else []
    _emit_stage("REPORT", "Preparing the final report")
    _log_model_guidance(run_dir, "REPORT")
    info(f"Status: {state.get('status', 'UNKNOWN')}")
    info(f"Complete: {'yes' if state.get('complete') else 'no'}")
    info(f"Confirmed: {len(confirmed) if isinstance(confirmed, list) else 0}")
    info(f"Suspicious: {len(suspicious) if isinstance(suspicious, list) else 0}")
    info(f"Clean: {'yes' if state.get('clean') else 'no'}")
    if finished:
        if state.get("complete"):
            success("Audit complete")
        else:
            warning("Audit remains incomplete")


def _log_poc_policy(confirmed_count: int, required_ids: list[str], pending_ids: list[str] | None = None) -> None:
    info(f"Confirmed findings: {confirmed_count}")
    info(f"High/Critical requiring PoC: {len(required_ids)}")
    info(f"Below High, PoC skipped: {confirmed_count - len(required_ids)}")
    if pending_ids:
        warning(f"Report blocked: {len(pending_ids)} required High/Critical PoC missing")


def _log_current_state(
    state: dict[str, Any],
    manifest: dict[str, Any],
    resolution: dict[str, Any] | None,
    domain_context: dict[str, Any] | None,
    *,
    run_dir: Path | None = None,
) -> None:
    status = state.get("status")
    coverage = state.get("coverage", {})
    if status == "INCOMPLETE_DOMAIN_ROUTING":
        unresolved = None
        if resolution is not None:
            unresolved = _unknown_domains(resolution)
        _log_domain_resolution(manifest, unresolved, run_dir=run_dir)
        return
    if status == "INCOMPLETE_CONTEXT":
        unresolved = None
        if domain_context is not None:
            unresolved = _unknown_context(domain_context)
        _log_domain_context(manifest, unresolved, run_dir=run_dir)
        return
    if status == "INCOMPLETE_COVERAGE":
        if manifest["deferred_domains"]:
            unresolved_domains = None
            if resolution is not None:
                unresolved_domains = _unknown_domains(resolution)
            if resolution is None or unresolved_domains:
                _log_domain_resolution(manifest, unresolved_domains, run_dir=run_dir)
                return
        if domain_context is None:
            _log_domain_context(manifest, run_dir=run_dir)
            return
        unresolved_context = _unknown_context(domain_context) or set()
        if unresolved_context:
            _log_domain_context(manifest, unresolved_context, run_dir=run_dir)
            return
        _emit_stage("SCREEN", "Triaging routed checks")
        _log_model_guidance(run_dir, "SCREEN")
        selected = coverage.get("selected", []) if isinstance(coverage, dict) else []
        candidates = coverage.get("deep_candidates", []) if isinstance(coverage, dict) else []
        not_applicable = coverage.get("screen_not_applicable", []) if isinstance(coverage, dict) else []
        info(f"{_stage_label('SCREEN')} checks: {len(selected) if isinstance(selected, list) else 0}")
        info(f"{_stage_label('DEEP_REVIEW')} candidates: {len(candidates) if isinstance(candidates, list) else 0}")
        info(f"{_stage_label('SCREEN')} NOT_APPLICABLE: {len(not_applicable) if isinstance(not_applicable, list) else 0}")
        warning(f"{_stage_label('SCREEN')} coverage remains incomplete")
        return
    if status == "INCOMPLETE_REVIEW":
        suspicious = coverage.get("suspicious", []) if isinstance(coverage, dict) else []
        candidates = coverage.get("deep_candidates", []) if isinstance(coverage, dict) else []
        reviewed = coverage.get("deep_reviewed", []) if isinstance(coverage, dict) else []
        pending = set(candidates) - set(reviewed) if isinstance(candidates, list) and isinstance(reviewed, list) else set()
        if pending:
            _emit_stage("DEEP_REVIEW", "Auditing candidate paths")
            _log_model_guidance(run_dir, "DEEP_REVIEW")
            info(f"Reviewed: {len(reviewed) if isinstance(reviewed, list) else 0} / {len(candidates) if isinstance(candidates, list) else 0}")
            info(f"Remaining: {len(pending)}")
        elif suspicious:
            _emit_stage("PROOF", "Validating suspicious findings")
            _log_model_guidance(run_dir, "PROOF")
            info(f"Remaining proof items: {len(suspicious)}")
        else:
            _emit_stage("DEEP_REVIEW", "Auditing candidate paths")
            _log_model_guidance(run_dir, "DEEP_REVIEW")
            info(f"Reviewed: {len(reviewed) if isinstance(reviewed, list) else 0} / {len(candidates) if isinstance(candidates, list) else 0}")
            info(f"Remaining: {len(candidates) - len(reviewed) if isinstance(candidates, list) and isinstance(reviewed, list) else 0}")
        warning("Further review is required")
        return
    _log_report(state, finished=True, run_dir=run_dir)


def _init_model_profile(args: argparse.Namespace, run_dir: Path) -> None:
    provider = getattr(args, "provider", "codex")
    if args.model_profile:
        profile = load_profile(args.model_profile.resolve())
    elif args.accept_default_models:
        profile = default_profile(provider)
    else:
        profile = load_global_profile(global_profile_path(provider)) or default_profile(provider)
    write_profile(paths(run_dir)["model_profile"], profile)


def _relocate_paths(value: Any, source: Path, target: Path) -> Any:
    if isinstance(value, str):
        prefix = str(source)
        return str(target) + value[len(prefix):] if value.startswith(prefix) else value
    if isinstance(value, list):
        return [_relocate_paths(item, source, target) for item in value]
    if isinstance(value, dict):
        return {key: _relocate_paths(item, source, target) for key, item in value.items()}
    return value


def init_run(root: Path, args: argparse.Namespace) -> dict[str, Any]:
    run_dir = args.run_dir.resolve()
    original_target = args.target.resolve()
    original_audit_root = (args.audit_root or original_target).resolve()
    acquisition_root = (getattr(args, "acquisition_root", None) or original_audit_root).resolve()
    original_build_root = resolve_build_root(original_audit_root, args.build_root, boundary=acquisition_root)
    validate_run_dir_isolation(run_dir, audit_root=original_audit_root, build_root=original_build_root)
    if run_dir.exists():
        if not run_dir.is_dir() or any(run_dir.iterdir()):
            raise ValueError(f"refusing to initialize non-empty run directory: {run_dir}")
    sanitized_source: Path | None = None
    staging: Path | None = None
    publication: Path | None = None
    # Initialization never constructs run state inside the authoritative
    # trees: staging and sanitized sources live in the system temp area until
    # the complete, validated bundle is published next to its destination.
    external = Path(tempfile.mkdtemp(prefix="evm-audit-init-"))
    try:
        prepared = prepare_repository(
            original_target,
            original_audit_root,
            original_build_root,
            source_trust=getattr(args, "source_trust", "UNKNOWN"),
            acquisition_root=acquisition_root,
            snapshot_destination=external / "sanitized-source",
        )
        target, audit_root, build_root = prepared.target, prepared.audit_root, prepared.build_root
        if prepared.trust["sanitized"]:
            sanitized_source = build_root
        staging = external / "staging"
        staging.mkdir()
        _init_model_profile(args, staging)
        values = paths(staging)
        trust_artifact = {
            "artifact_type": "repository-trust",
            "schema_version": REPOSITORY_TRUST_VERSION,
            **prepared.trust,
        }
        validate_schema(root, "repository-trust.schema.json", trust_artifact)
        atomic_write_json(values["repository_trust"], trust_artifact)
        values["feature_map"].parent.mkdir(parents=True, exist_ok=True)
        values["manifest"].parent.mkdir(parents=True, exist_ok=True)
        recon_args = [str(target), "--root", str(root), "--output", str(values["feature_map"])]
        recon_args.extend(["--source-trust", getattr(args, "source_trust", "UNKNOWN")])
        if args.solc:
            recon_args.extend(["--solc", args.solc])
        recon_args.extend(["--code-index-out", str(values["code_index"])])
        # During initialization the staging directory is the effective output
        # root; the final managed root is still empty, so exclusion semantics
        # are identical for scope discovery and digests.
        recon_args.extend(["--managed-output-root", str(staging)])
        if args.audit_root:
            recon_args.extend(["--audit-root", str(audit_root)])
        if args.build_root or prepared.trust["sanitized"]:
            recon_args.extend(["--build-root", str(build_root)])
        elif getattr(args, "acquisition_root", None):
            recon_args.extend(["--acquisition-root", str(acquisition_root)])
        for exclusion in args.exclude:
            recon_args.extend(["--exclude", exclusion])
        for include in args.include:
            recon_args.extend(["--include", include])
        for dependency_root in args.dependency_root or []:
            recon_args.extend(["--dependency-root", dependency_root])
        if args.present_only:
            recon_args.append("--present-only")
        _emit_stage("RECON", "Building scope-bound Feature Map")
        try:
            _run(root, "recon.py", recon_args, verbose=args.verbose)
            feature_map = load_json(values["feature_map"])
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            warning("Recon failed")
            raise
        _log_recon(feature_map, audit_root, args.require_complete_compilation, run_dir=staging)

        selector_args = [
            "--root", str(root),
            "--feature-map", str(values["feature_map"]),
            "--target-root", str(audit_root),
            "--manifest-out", str(values["manifest"]),
            "--context-out", str(values["context"]),
            "--environment-out", str(values["environment"]),
            "--managed-output-root", str(staging),
        ]
        for exclusion in args.exclude:
            selector_args.extend(["--exclude", exclusion])
        if args.build_root or prepared.trust["sanitized"]:
            selector_args.extend(["--build-root", str(build_root)])
        elif getattr(args, "acquisition_root", None):
            selector_args.extend(["--acquisition-root", str(acquisition_root)])
        for include in args.include:
            selector_args.extend(["--include", include])
        for dependency_root in args.dependency_root or []:
            selector_args.extend(["--dependency-root", dependency_root])
        for option in ("domain", "domains", "target_commit", "chain_id", "chain_family", "execution_environment", "fork_block", "compiler_version", "evm_fork", "protocol_version", "audit_timestamp"):
            value = getattr(args, option, None)
            if value is not None:
                selector_args.extend([f"--{option.replace('_', '-')}", str(value)])
        if args.require_complete_compilation:
            selector_args.append("--require-complete-compilation")
        if args.environment_context:
            selector_args.extend(["--environment-context", str(args.environment_context.resolve())])
        _emit_stage("ROUTING", "Building immutable routing snapshot")
        try:
            _run(root, "select_checks.py", selector_args, verbose=args.verbose)
            manifest = load_json(values["manifest"])
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            warning("Routing failed")
            raise
        _log_routing(manifest, run_dir=staging)
        next_result = next_step(root, staging, verbose=args.verbose, emit=False)
        _load_run(root, staging)

        staged_run = staging
        if run_dir.exists():
            if not run_dir.is_dir() or any(run_dir.iterdir()):
                raise ValueError(f"run directory changed during initialization: {run_dir}")
            run_dir.rmdir()
        # Publish the validated bundle through a short-lived sibling so the
        # destination only ever appears via one atomic rename.
        run_dir.parent.mkdir(parents=True, exist_ok=True)
        publication = Path(tempfile.mkdtemp(prefix=f".{run_dir.name}.publish-", dir=run_dir.parent))
        copy_tree(staged_run, publication / "run")
        fsync_directory_tree(publication / "run")
        durable_replace_directory(publication / "run", run_dir)
        shutil.rmtree(publication)
        publication = None
        staging = None
        next_result = _relocate_paths(next_result, staged_run, run_dir)
        info(f"Next required phase: {_display_stage(next_result['stage'])}")
        _log_model_guidance(run_dir, next_result["stage"])
        values = paths(run_dir)
        progress_history = [
            _progress_history_entry(
                run_dir,
                "RECON",
                "COMPLETED",
                summary=_recon_progress_summary(feature_map),
            ),
            _progress_history_entry(
                run_dir,
                "ROUTING",
                "COMPLETED",
                summary=_routing_progress_summary(manifest),
            ),
            {
                "stage": next_result["stage"],
                "state": "CURRENT",
                "progress": next_result["progress"],
                "recommended_execution": next_result["recommended_execution"],
            },
        ]
        return {
            "stage": "INITIALIZED",
            "run_dir": str(run_dir),
            "manifest": str(values["manifest"]),
            "code_index": str(values["code_index"]),
            "progress_history": progress_history,
            "next": next_result,
            "recommended_execution": next_result["recommended_execution"],
        }
    finally:
        for temporary in (staging, publication, sanitized_source):
            if temporary is not None and temporary.exists():
                shutil.rmtree(temporary, ignore_errors=True)
        shutil.rmtree(external, ignore_errors=True)


def _optional_code_index_status(
    root: Path,
    values: dict[str, Any],
    manifest: dict[str, Any],
    registry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    run_dir = values["manifest"].parent.parent if "manifest" in values else None
    return bound_code_index_status(
        root, manifest, values["code_index"], registry=registry, managed_output_root=run_dir
    )


def _report_generation_paths(base: Path) -> dict[str, Path]:
    return {
        "report": base / "AUDIT-REPORT.md",
        "issue_candidates": base / "issue-candidates.json",
        "report_bundle": base / "report-bundle.json",
        "report_input_severity": base / "severity-decisions.json",
        "report_input_details": base / "finding-details.json",
        "poc_evidence": base / "poc-evidence.json",
        "poc_sources": base / "poc-sources",
    }


@contextmanager
def _report_publication_lock(run_dir: Path):
    """Serialize report publication using the ledger's portable lock protocol."""
    with _ledger_lock(run_dir / "report-publication", shared=False):
        yield


def _publication_identity(manifest: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    return {
        "routing_snapshot_id": manifest["routing_snapshot_id"],
        "review_snapshot_id": state.get("review_snapshot_id"),
        "review_state_digest": state.get("review_state_digest"),
        "status": state.get("status"),
    }


def _pointer_references_generation(path: Path, generation: str) -> bool:
    try:
        return load_json(path).get("generation") == generation
    except (OSError, ValueError, json.JSONDecodeError):
        return False


def _report_generation_inventory(
    values: dict[str, Any],
    current_generation: str | None = None,
) -> dict[str, list[str]]:
    staging_artifacts: list[str] = []
    orphaned_generations: list[str] = []
    generations = values["report_generations"]
    if generations.is_symlink():
        raise ValueError(f"report-generations must not be a symlink: {generations}")
    if generations.exists() and not generations.is_dir():
        raise ValueError(f"report-generations is not a directory: {generations}")
    if not generations.exists():
        return {"orphaned_generations": orphaned_generations, "staging_artifacts": staging_artifacts}
    for path in sorted(generations.iterdir(), key=lambda item: item.name):
        if path.is_symlink() or not path.is_dir():
            continue
        if path.name.startswith(".tmp-"):
            staging_artifacts.append(path.name)
        elif path.name.startswith("generation-") and path.name != current_generation:
            orphaned_generations.append(path.name)
    return {
        "orphaned_generations": orphaned_generations,
        "staging_artifacts": staging_artifacts,
    }


def _validate_existing_generation(
    staging: Path,
    generation: Path,
    *,
    finding_report: bool,
    poc_required: bool = False,
) -> None:
    expected = {path.name: path for path in staging.iterdir()}
    expected_names = {
        "AUDIT-REPORT.md",
        "issue-candidates.json",
        "report-bundle.json",
    }
    if finding_report:
        expected_names.update({"severity-decisions.json", "finding-details.json"})
        if poc_required:
            expected_names.update({"poc-evidence.json", "poc-sources"})
    if set(expected) != expected_names or any(
        path.is_symlink() or (not path.is_dir() if path.name == "poc-sources" else not path.is_file())
        for path in expected.values()
    ):
        raise ValueError(f"content-addressed generation has mismatched contents: {generation}")
    actual = {path.name: path for path in generation.iterdir()}
    if set(actual) != expected_names or any(
        path.is_symlink() or (not path.is_dir() if path.name == "poc-sources" else not path.is_file())
        for path in actual.values()
    ):
        raise ValueError(f"content-addressed generation has mismatched contents: {generation}")
    for name in expected_names:
        if name == "poc-sources":
            expected_sources = {
                path.relative_to(expected[name]).as_posix(): path
                for path in expected[name].rglob("*")
                if path.is_file()
            }
            actual_sources = {
                path.relative_to(actual[name]).as_posix(): path
                for path in actual[name].rglob("*")
                if path.is_file()
            }
            if set(expected_sources) != set(actual_sources) or any(
                actual_sources[relative].read_bytes() != expected_sources[relative].read_bytes()
                for relative in expected_sources
            ):
                raise ValueError(f"content-addressed generation has mismatched contents: {generation}")
        elif actual[name].read_bytes() != expected[name].read_bytes():
            raise ValueError(f"content-addressed generation has mismatched contents: {generation}")


def _poc_source_path(run_dir: Path, source_path: str) -> Path:
    candidate_path = Path(source_path)
    if candidate_path.is_absolute() or not candidate_path.parts or ".." in candidate_path.parts:
        raise ValueError(f"PoC source path is not relative to run-dir/poc: {source_path}")
    raw = run_dir / candidate_path
    if raw.is_symlink():
        raise ValueError(f"PoC source must be a regular file: {source_path}")
    poc_root = (run_dir / "poc").resolve()
    candidate = raw.resolve(strict=False)
    if candidate_path.parts[0] != "poc" or poc_root not in candidate.parents or candidate.is_symlink() or not candidate.is_file():
        raise ValueError(f"PoC source is not under run-dir/poc: {source_path}")
    return candidate


def _poc_source_snapshot_name(source: dict[str, Any]) -> str:
    return poc_source_snapshot_name(source)


def _capture_poc_sources(
    destination: Path,
    poc_evidence: dict[str, Any],
    run_dir: Path,
) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    expected: dict[str, bytes] = {}
    for finding in poc_evidence.get("findings", []):
        for source in finding.get("sources", []):
            source_path = _poc_source_path(run_dir, source["path"])
            content = source_path.read_bytes()
            if hashlib.sha256(content).hexdigest() != source["sha256"]:
                raise ValueError(f"PoC source changed while capturing generation: {source['path']}")
            name = _poc_source_snapshot_name(source)
            previous = expected.get(name)
            if previous is not None and previous != content:
                raise ValueError(f"PoC source snapshot hash collision: {source['path']}")
            expected[name] = content
    for name, content in expected.items():
        target = destination / name
        atomic_write_bytes(target, content)
        staged = target.read_bytes()
        if staged != content or hashlib.sha256(staged).hexdigest() != name.split(".", 1)[0]:
            raise ValueError(f"PoC source snapshot verification failed: {target}")


def _validate_poc_source_snapshots(
    root: Path,
    evidence: dict[str, Any],
    source_dir: Path,
) -> None:
    validate_schema(root, "poc-evidence.schema.json", evidence)
    expected: set[str] = set()
    for finding in evidence.get("findings", []):
        for source in finding.get("sources", []):
            name = _poc_source_snapshot_name(source)
            expected.add(name)
    if source_dir.is_symlink() or not source_dir.is_dir():
        raise ValueError("generation is missing poc-sources")
    actual = {path.name: path for path in source_dir.iterdir()}
    if set(actual) != expected or any(path.is_symlink() or not path.is_file() for path in actual.values()):
        raise ValueError("generation PoC source snapshots are incomplete")
    for name in expected:
        content = actual[name].read_bytes()
        if hashlib.sha256(content).hexdigest() != name.split(".", 1)[0]:
            raise ValueError(f"generation PoC source snapshot hash does not match: {name}")


def _current_report_generation(
    root: Path,
    values: dict[str, Any],
) -> tuple[dict[str, Path], dict[str, Any]] | None:
    pointer_path = values["report_current"]
    generations = values["report_generations"]
    if generations.is_symlink() or (generations.exists() and not generations.is_dir()):
        raise ValueError(f"report-generations is not a regular directory: {generations}")
    if not pointer_path.exists():
        return None
    pointer = load_json(pointer_path)
    validate_schema(root, "report-current.schema.json", pointer)
    generation = pointer["generation"]
    generation_root = values["report_generations"] / generation
    if generation_root.parent.resolve() != values["report_generations"].resolve() or not generation_root.is_dir():
        raise ValueError("report-current.json points outside report-generations")
    artifacts = _report_generation_paths(generation_root)
    bundle_bytes = artifacts["report_bundle"].read_bytes()
    if hashlib.sha256(bundle_bytes).hexdigest() != pointer["report_bundle_sha256"]:
        raise ValueError("report-current.json does not match its report bundle")
    bundle = load_json_bytes(artifacts["report_bundle"])[0]
    validate_schema(root, "report-bundle.schema.json", bundle)
    generation_reporting_digest = reporting_inputs_digest_from_hashes(
        severity_decisions_sha256=bundle["severity_decisions_sha256"],
        finding_details_sha256=bundle["finding_details_sha256"],
        poc_evidence_sha256=bundle["poc_evidence_sha256"],
    )
    if pointer["reporting_inputs_sha256"] != generation_reporting_digest:
        raise ValueError("report-current.json reporting inputs do not match its report bundle")
    if generation != f"generation-{pointer['report_bundle_sha256']}":
        raise ValueError("report-current.json generation does not match its bundle digest")
    return artifacts, pointer


def _sync_report_convenience_copies(
    values: dict[str, Any],
    artifacts: dict[str, Path],
    *,
    finding_report: bool,
    poc_required: bool = False,
) -> dict[str, Any]:
    # ponytail: convenience copies are best-effort; report-current.json is the commit boundary.
    copies = (
        (values["report"], artifacts["report"]),
        (values["issue_candidates"], artifacts["issue_candidates"]),
        (values["report_bundle"], artifacts["report_bundle"]),
    )
    if finding_report:
        copies += (
            (values["report_input_severity"], artifacts["report_input_severity"]),
            (values["report_input_details"], artifacts["report_input_details"]),
        )
        if poc_required:
            copies += ((values["poc_evidence"], artifacts["poc_evidence"]),)
    failed_paths: list[str] = []
    warnings: list[str] = []
    for destination, source in copies:
        try:
            atomic_write_bytes(destination, source.read_bytes())
        except OSError as exc:
            message = f"could not refresh convenience report copy {destination}: {exc}"
            failed_paths.append(str(destination))
            warnings.append(message)
            warning(message)
    return {"synced": not failed_paths, "failed_paths": failed_paths, "warnings": warnings}


def _convenience_copies_current(
    values: dict[str, Any],
    artifacts: dict[str, Path],
    *,
    finding_report: bool,
    poc_required: bool = False,
) -> bool:
    copies = (
        (values["report"], artifacts["report"]),
        (values["issue_candidates"], artifacts["issue_candidates"]),
        (values["report_bundle"], artifacts["report_bundle"]),
    )
    if finding_report:
        copies += (
            (values["report_input_severity"], artifacts["report_input_severity"]),
            (values["report_input_details"], artifacts["report_input_details"]),
        )
        if poc_required:
            copies += ((values["poc_evidence"], artifacts["poc_evidence"]),)
    try:
        return all(destination.exists() and destination.read_bytes() == source.read_bytes() for destination, source in copies)
    except OSError:
        return False


def _report_bundle_status(
    root: Path,
    values: dict[str, Any],
    manifest: dict[str, Any],
    state: dict[str, Any],
) -> dict[str, Any]:
    try:
        current = _current_report_generation(root, values)
        artifacts, pointer = current if current is not None else (values, None)
        inventory = _report_generation_inventory(values, pointer["generation"] if pointer else None)
        if pointer is None and values["report_bundle"].exists():
            return {
                "status": "ABSENT",
                "current": False,
                "message": "legacy report outputs are uncommitted; rerun report to republish",
                **inventory,
            }
        marker = artifacts["report_bundle"]
        if not marker.exists():
            if pointer is not None:
                raise ValueError("current report generation has no report bundle")
            return {
                "status": "ABSENT",
                "current": False,
                "message": "report bundle has not been committed",
                **inventory,
            }
        metadata = load_json(marker)
        validate_schema(root, "report-bundle.schema.json", metadata)
        if pointer is not None:
            _validate_generation_snapshot(root, artifacts["report"].parent)
        issue_candidates, issue_candidates_bytes = load_json_bytes(artifacts["issue_candidates"])
        severity_decisions_bytes = finding_details_bytes = poc_evidence_bytes = None
        severity_decisions = finding_details = poc_evidence = None
        required_poc_ids: list[str] = []
        run_dir = values["manifest"].parent.parent
        current_inputs = CurrentReportingInputs(None, None, None, None, None, None, (), None)
        if pointer is not None:
            current_inputs = load_current_reporting_inputs(
                root, values, manifest, state, require_complete=True
            )
        if state.get("status") == "COMPLETE_WITH_FINDINGS":
            severity_decisions, severity_decisions_bytes = load_json_bytes(artifacts["report_input_severity"])
            finding_details, finding_details_bytes = load_json_bytes(artifacts["report_input_details"])
            validate_reporting_inputs(
                root,
                manifest,
                state,
                severity_decisions,
                finding_details,
            )
            required_poc_ids = derive_poc_required_ids(
                state["coverage"]["confirmed"], severity_decisions["decisions"]
            )
            if required_poc_ids:
                poc_path = artifacts["poc_evidence"]
                if poc_path.is_symlink() or not poc_path.is_file():
                    raise ValueError(f"INCOMPLETE_POC: generation is missing {poc_path.name}")
                poc_evidence, poc_evidence_bytes = load_json_bytes(poc_path)
                validate_poc_evidence(
                    root,
                    manifest,
                    state,
                    severity_decisions,
                    severity_decisions_bytes,
                    poc_evidence,
                    run_dir=run_dir,
                    source_dir=artifacts["poc_sources"],
                )
        validate_issue_candidates(
            root,
            manifest,
            state,
            issue_candidates,
            severity_decisions,
        )
        if pointer is not None:
            run_dir = values["manifest"].parent.parent
            resolution = load_json(values["resolution"]) if values["resolution"].exists() else None
            screen = load_json(values["screen_results"]) if values["screen_results"].exists() else None
            domain_context = load_json(values["domain_context"]) if values["domain_context"].exists() else None
            context = load_json(values["context"]) if values["context"].exists() else None
            synthesis = synthesize(
                root,
                manifest,
                load_json(root / "data/canonical-checks.json"),
                state,
                _ledger_paths(run_dir),
                severity_decisions,
                finding_details=finding_details,
                severity_decisions_bytes=severity_decisions_bytes,
                finding_details_bytes=finding_details_bytes,
                poc_evidence=poc_evidence,
                poc_evidence_bytes=poc_evidence_bytes,
                allow_incomplete=not state["complete"],
                domain_resolution=resolution,
                screen_results=screen,
                domain_context=domain_context,
                context=context,
                managed_output_root=run_dir,
            )
            if synthesis.state != state:
                raise ValueError("report generation state differs from current audit state")
            validate_report_generation(
                synthesis.report,
                synthesis.issue_candidates,
                artifacts["report"].read_bytes(),
                issue_candidates,
                issue_candidates_bytes,
            )
        expected = report_bundle_metadata(
            manifest,
            state,
            artifacts["report"].read_bytes(),
            issue_candidates,
            issue_candidates_bytes=issue_candidates_bytes,
            severity_decisions_bytes=severity_decisions_bytes,
            finding_details_bytes=finding_details_bytes,
            severity_decisions=severity_decisions,
            poc_evidence=poc_evidence,
            poc_evidence_bytes=poc_evidence_bytes,
        )
        if metadata != expected:
            raise ValueError("report bundle marker or body hashes do not match current audit state")
        if pointer is not None and pointer["reporting_inputs_sha256"] != current_inputs.digest:
            raise ValueError("reporting inputs differ from the committed generation")
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        return {"status": "STALE", "current": False, "message": f"report bundle is not current: {error}"}
    finding_report = state.get("status") == "COMPLETE_WITH_FINDINGS"
    convenience_synced = _convenience_copies_current(
        values,
        artifacts,
        finding_report=finding_report,
        poc_required=bool(required_poc_ids),
    )
    result = {
        "status": "CURRENT",
        "current": True,
        "message": "report bundle matches current audit state",
        "convenience_synced": convenience_synced,
        **inventory,
    }
    if pointer is not None:
        result.update(
            {
                "generation": pointer["generation"],
                "report": str(artifacts["report"]),
                "issue_candidates": str(artifacts["issue_candidates"]),
                "bundle": str(artifacts["report_bundle"]),
            }
        )
        if required_poc_ids:
            result["poc_evidence"] = str(artifacts["poc_evidence"])
    return result


def _report_generation_status(values: dict[str, Any], bundle_status: dict[str, Any]) -> dict[str, Any]:
    result = {
        "status": bundle_status["status"],
        "current": bundle_status["current"],
        "current_pointer": str(values["report_current"]),
        "convenience_synced": bundle_status.get("convenience_synced", False),
    }
    for key in ("generation", "report", "issue_candidates", "bundle", "poc_evidence", "message", "orphaned_generations", "staging_artifacts"):
        if key in bundle_status:
            result[key] = bundle_status[key]
    return result


def _validate_generation_snapshot(root: Path, generation: Path) -> dict[str, Any]:
    if generation.is_symlink() or not generation.is_dir():
        raise ValueError(f"generation is not a regular directory: {generation}")
    files = {path.name: path for path in generation.iterdir()}
    bundle_path = files.get("report-bundle.json")
    report_path = files.get("AUDIT-REPORT.md")
    issue_path = files.get("issue-candidates.json")
    if any(path is None or path.is_symlink() or not path.is_file() for path in (bundle_path, report_path, issue_path)):
        raise ValueError("generation is missing required report artifacts")
    bundle_bytes = bundle_path.read_bytes()
    bundle = json.loads(bundle_bytes.decode("utf-8"))
    validate_schema(root, "report-bundle.schema.json", bundle)
    issue_bytes = issue_path.read_bytes()
    issues = json.loads(issue_bytes.decode("utf-8"))
    validate_schema(root, "issue-candidates.schema.json", issues)
    if hashlib.sha256(report_path.read_bytes()).hexdigest() != bundle["report_sha256"]:
        raise ValueError("generation report hash does not match its bundle")
    if hashlib.sha256(issue_bytes).hexdigest() != bundle["issue_candidates_sha256"]:
        raise ValueError("generation issue-candidates hash does not match its bundle")
    expected = {"AUDIT-REPORT.md", "issue-candidates.json", "report-bundle.json"}
    for filename, digest_key in (
        ("severity-decisions.json", "severity_decisions_sha256"),
        ("finding-details.json", "finding_details_sha256"),
        ("poc-evidence.json", "poc_evidence_sha256"),
    ):
        digest = bundle[digest_key]
        path = files.get(filename)
        if digest is None:
            if path is not None:
                raise ValueError(f"generation has unexpected {filename}")
            continue
        if path is None or path.is_symlink() or not path.is_file():
            raise ValueError(f"generation is missing {filename}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError(f"generation {filename} hash does not match its bundle")
        expected.add(filename)
        if filename == "poc-evidence.json":
            _validate_poc_source_snapshots(root, json.loads(path.read_bytes().decode("utf-8")), generation / "poc-sources")
            expected.add("poc-sources")
    if set(files) != expected or any(
        path.is_symlink()
        or (not path.is_dir() if name == "poc-sources" else not path.is_file())
        for name, path in files.items()
    ):
        raise ValueError("generation contains unexpected artifacts")
    bundle_digest = hashlib.sha256(bundle_bytes).hexdigest()
    suffix = generation.name.removeprefix("generation-")
    content_addressed = bool(re.fullmatch(r"[0-9a-f]{64}", suffix))
    if content_addressed and suffix != bundle_digest:
        raise ValueError("content-addressed generation name does not match its bundle")
    return {"bundle_sha256": bundle_digest, "content_addressed": content_addressed}


def reports_run(
    root: Path,
    run_dir: Path,
    *,
    list_only: bool = False,
    gc: bool = False,
    dry_run: bool = False,
    apply: bool = False,
) -> dict[str, Any]:
    if list_only == gc:
        raise ValueError("reports requires exactly one of --list or --gc")
    if apply and not gc:
        raise ValueError("--apply requires --gc")
    if dry_run and not gc:
        raise ValueError("--dry-run requires --gc")
    values, _, _ = _load_run(root, run_dir)
    report_generations = values["report_generations"]
    if report_generations.is_symlink() or (report_generations.exists() and not report_generations.is_dir()):
        raise ValueError(f"report-generations is not a regular directory: {report_generations}")
    with _report_publication_lock(values["manifest"].parent.parent):
        current_generation: str | None = None
        try:
            current = _current_report_generation(root, values)
            if current is not None:
                current_generation = current[1]["generation"]
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            warning(f"current report pointer is not valid: {exc}")
        if gc and current_generation is None:
            # Fail closed: without a validated current generation, every verified
            # generation looks like an orphan and GC would destroy the last
            # committed deliverable. Only allow GC when nothing was ever published.
            has_generations = report_generations.exists() and any(
                entry.name.startswith("generation-") for entry in report_generations.iterdir()
            )
            if values["report_current"].exists() or has_generations:
                raise ValueError(
                    "refusing report GC because the current report generation cannot be validated; "
                    "inspect or repair the run with `reports --list` before collecting old generations"
                )
        inventory = _report_generation_inventory(values, current_generation)
        generation_records: list[dict[str, Any]] = []
        by_bundle: dict[str, list[dict[str, Any]]] = {}
        if report_generations.exists():
            for generation in sorted(report_generations.iterdir(), key=lambda item: item.name):
                if not generation.name.startswith("generation-") or generation.is_symlink() or not generation.is_dir():
                    continue
                record: dict[str, Any] = {
                    "generation": generation.name,
                    "current": generation.name == current_generation,
                    "verified": False,
                    "content_addressed": False,
                    "safe_to_remove": False,
                }
                try:
                    verified = _validate_generation_snapshot(root, generation)
                    record.update(verified, verified=True)
                    by_bundle.setdefault(verified["bundle_sha256"], []).append(record)
                except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
                    record["message"] = str(exc)
                generation_records.append(record)
        content_generations = {
            bundle_sha256
            for bundle_sha256, records in by_bundle.items()
            if any(record["content_addressed"] for record in records)
        }
        candidates: list[str] = []
        for record in generation_records:
            if record["current"]:
                record["message"] = "current generation is protected"
                continue
            if not record["verified"]:
                continue
            if record["content_addressed"] or record["bundle_sha256"] in content_generations:
                record["safe_to_remove"] = True
                candidates.append(record["generation"])
                record["message"] = "verified orphan generation"
            else:
                record["message"] = "verified legacy generation retained without content-addressed duplicate"
        candidates.extend(inventory["staging_artifacts"])
        removed: list[str] = []
        if gc and apply:
            for name in candidates:
                target = report_generations / name
                if target.parent.resolve() != report_generations.resolve() or target.is_symlink() or not target.is_dir():
                    continue
                shutil.rmtree(target)
                removed.append(name)
        return {
            "stage": "REPORTS",
            "run_dir": str(values["manifest"].parent.parent),
            "current_generation": current_generation,
            "generations": generation_records,
            "orphaned_generations": inventory["orphaned_generations"],
            "staging_artifacts": inventory["staging_artifacts"],
            "gc": {
                "requested": gc,
                "dry_run": gc and not apply,
                "applied": gc and apply,
                "candidates": candidates,
                "removed": removed,
            },
        }


def _load_run(root: Path, run_dir: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    values = paths(run_dir.resolve())
    if not values["manifest"].exists():
        raise ValueError(f"run has no routing manifest: {values['manifest']}")
    manifest = load_json(values["manifest"])
    recon_context = manifest.get("feature_map", {}).get("recon_context", {})
    try:
        audit_root = Path(recon_context["target_root"])
        build_root = Path(recon_context["build_root"])
    except (KeyError, TypeError) as error:
        raise ValueError("routing manifest has no auditable target/build roots") from error
    validate_run_dir_isolation(run_dir, audit_root=audit_root, build_root=build_root)
    registry = load_json(root / "data/canonical-checks.json")
    validate_manifest(root, manifest, registry)
    validate_target_snapshot(manifest, managed_output_root=run_dir)
    values["code_index_status"] = _optional_code_index_status(root, values, manifest, registry)
    if values["code_index_status"]["status"] not in {"ABSENT", "CURRENT"}:
        warning(values["code_index_status"]["message"])
    return values, manifest, registry


def _ledger_paths(run_dir: Path) -> list[Path]:
    return sorted((run_dir / "reviews").glob("review-*.jsonl"))


def _runtime_view_current(output: Path, expected: dict[str, Any]) -> bool:
    metadata = output.with_suffix(".meta.json")
    if not output.exists() or not metadata.exists():
        return False
    try:
        value = load_json(metadata)
        validate_schema(ROOT, "runtime-metadata.schema.json", value)
        identity = {key: item for key, item in value.items() if key != "runtime_sha256"}
        return identity == expected and value["runtime_sha256"] == hashlib.sha256(output.read_bytes()).hexdigest()
    except (OSError, ValueError, json.JSONDecodeError):
        return False


def _prune_runtime_views(run_dir: Path, profile: str, keep: set[Path]) -> None:
    for output in (run_dir / "runtime").glob(f"{profile}-*.md"):
        if output.resolve() in keep:
            continue
        output.unlink()
        metadata = output.with_suffix(".meta.json")
        if metadata.exists():
            metadata.unlink()


def _render_owner_view(
    root: Path,
    values: dict[str, Path],
    *,
    profile: str,
    owner: str,
    ids: set[str],
    review_snapshot: str,
    resolution: Path | None = None,
    ledger_paths: list[Path] | None = None,
    verbose: bool = False,
) -> tuple[Path, bool]:
    output = values["manifest"].parent.parent / "runtime" / f"{profile}-{owner}.md"
    # proof views embed ledger record content, so their identity must bind the
    # ledger state or a follow-up revision would be served from a stale view
    ledger_digest = ledger_content_digest(ledger_paths) if profile == "proof" else None
    expected = runtime_identity(
        load_json(values["manifest"]), profile, sorted(ids), owner, review_snapshot, ledger_digest
    )
    if _runtime_view_current(output, expected):
        return output, True
    extra = [
        "--domain-context", str(values["domain_context"]),
        "--screen-results", str(values["screen_results"]),
        "--owner-domain", owner,
        "--output", str(output),
    ]
    if resolution is not None:
        extra[0:0] = ["--domain-resolution", str(resolution)]
    if profile == "proof":
        for ledger in ledger_paths or []:
            extra.extend(["--ledger", str(ledger)])
    _run(
        root,
        "render_runtime.py",
        [
            "--manifest", str(values["manifest"]),
            "--profile", profile,
            "--managed-output-root", str(values["manifest"].parent.parent),
            *extra,
        ],
        verbose=verbose,
    )
    if not _runtime_view_current(output, expected):
        raise ValueError(f"renderer produced an invalid runtime view: {output}")
    return output, False


def _reporting_identity(manifest: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    audit = manifest["audit_context"]
    return {
        "schema_version": REPORTING_VERSION,
        "routing_snapshot_id": manifest["routing_snapshot_id"],
        "review_state_digest": state["review_state_digest"],
        "registry_sha256": audit["registry_sha256"],
        "source_digest": audit["source_digest"],
        "compilation_input_digest": audit["compilation_input_digest"],
    }


def _reporting_payloads(manifest: dict[str, Any], state: dict[str, Any]) -> dict[str, dict[str, Any]]:
    identity = _reporting_identity(manifest, state)
    confirmed = sorted(state["coverage"]["confirmed"])
    return {
        "severity": {
            **identity,
            "artifact_state": "TEMPLATE",
            "decisions": {
                canonical_id: {
                    "severity": "TODO",
                    "rationale": "TODO: provide proof-bound severity rationale",
                    "dimensions": {dimension: "TODO" for dimension in REPORTING_DIMENSIONS},
                }
                for canonical_id in confirmed
            },
        },
        "finding_details": {
            **identity,
            "artifact_state": "TEMPLATE",
            "findings": [
                {
                    "canonical_id": canonical_id,
                    "location": "TODO",
                    "description": "TODO: describe the confirmed defect",
                    "recommendation": "TODO: provide a concrete remediation",
                }
                for canonical_id in confirmed
            ],
        },
    }


def _poc_evidence_template(
    manifest: dict[str, Any],
    state: dict[str, Any],
    severity_decisions: dict[str, Any],
    severity_decisions_bytes: bytes,
    required_ids: list[str],
) -> dict[str, Any]:
    identity = _reporting_identity(manifest, state)
    return {
        "artifact_type": "poc-evidence",
        "schema_version": POC_EVIDENCE_VERSION,
        "artifact_state": "TEMPLATE",
        "routing_snapshot_id": identity["routing_snapshot_id"],
        "review_snapshot_id": state["review_snapshot_id"],
        "review_state_digest": identity["review_state_digest"],
        "registry_sha256": identity["registry_sha256"],
        "source_digest": identity["source_digest"],
        "compilation_input_digest": identity["compilation_input_digest"],
        "severity_decisions_sha256": hashlib.sha256(severity_decisions_bytes).hexdigest(),
        "findings": [
            {"canonical_id": canonical_id, "severity": severity_decisions["decisions"][canonical_id]["severity"]}
            for canonical_id in required_ids
        ],
    }


def load_current_reporting_inputs(
    root: Path,
    values: dict[str, Any],
    manifest: dict[str, Any],
    state: dict[str, Any],
    *,
    require_complete: bool,
) -> CurrentReportingInputs:
    """Load and validate the current authoring inputs used by report status."""
    empty = CurrentReportingInputs(None, None, None, None, None, None, (), None)
    if state.get("status") != "COMPLETE_WITH_FINDINGS":
        return empty
    try:
        severity, severity_bytes = load_json_bytes(values["severity_decisions"])
        finding_details, finding_details_bytes = load_json_bytes(values["finding_details"])
        validate_reporting_inputs(root, manifest, state, severity, finding_details)
        required_ids = tuple(
            derive_poc_required_ids(state["coverage"]["confirmed"], severity["decisions"])
        )
        poc_evidence = poc_evidence_bytes = None
        if required_ids:
            poc_evidence, poc_evidence_bytes = load_json_bytes(values["poc_evidence"])
            validate_poc_evidence(
                root,
                manifest,
                state,
                severity,
                severity_bytes,
                poc_evidence,
                run_dir=values["manifest"].parent.parent,
            )
        return CurrentReportingInputs(
            severity,
            severity_bytes,
            finding_details,
            finding_details_bytes,
            poc_evidence,
            poc_evidence_bytes,
            required_ids,
            reporting_inputs_digest(
                severity_bytes=severity_bytes,
                finding_details_bytes=finding_details_bytes,
                poc_evidence_bytes=poc_evidence_bytes,
            ),
        )
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        if require_complete:
            raise ValueError(f"current reporting inputs are incomplete: {exc}") from exc
        return empty


def _current_severity_for_poc(
    root: Path,
    manifest: dict[str, Any],
    state: dict[str, Any],
    path: Path,
) -> tuple[dict[str, Any], bytes, list[str]] | None:
    if not path.exists():
        return None
    try:
        value, raw = load_json_bytes(path)
        validate_schema(root, "severity-decisions.schema.json", value)
        validate_artifact_identity(value, manifest)
        if value.get("artifact_state") == "TEMPLATE":
            return None
        if value.get("review_state_digest") != state.get("review_state_digest"):
            return None
        decisions = value.get("decisions")
        confirmed = state.get("coverage", {}).get("confirmed", [])
        if not isinstance(decisions, dict) or not isinstance(confirmed, list):
            return None
        required = derive_poc_required_ids(confirmed, decisions)
        return value, raw, required
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


def _reporting_ids(value: dict[str, Any], kind: str) -> tuple[set[str] | None, bool]:
    if kind == "severity":
        decisions = value.get("decisions")
        if not isinstance(decisions, dict) or any(not isinstance(canonical_id, str) for canonical_id in decisions):
            return None, False
        return set(decisions), True
    if kind == "poc":
        findings = value.get("findings")
        if not isinstance(findings, list):
            return None, False
        ids = [item.get("canonical_id") for item in findings if isinstance(item, dict)]
        if len(ids) != len(findings) or any(not isinstance(canonical_id, str) for canonical_id in ids):
            return None, False
        return set(ids), len(ids) == len(set(ids))
    findings = value.get("findings")
    if not isinstance(findings, list):
        return None, False
    ids = [item.get("canonical_id") for item in findings if isinstance(item, dict)]
    if len(ids) != len(findings) or any(not isinstance(canonical_id, str) for canonical_id in ids):
        return None, False
    return set(ids), len(ids) == len(set(ids))


def _is_generated_reporting_template(value: dict[str, Any], kind: str) -> bool:
    if value.get("artifact_state") == "COMPLETED":
        return False
    return value.get("artifact_state") == "TEMPLATE"


def _reporting_matches(
    value: dict[str, Any],
    expected: dict[str, Any],
    confirmed_ids: set[str],
    kind: str,
    identity_keys: tuple[str, ...] = REPORTING_IDENTITY_KEYS,
) -> bool:
    if any(value.get(key) != expected[key] for key in identity_keys):
        return False
    actual_ids, unique = _reporting_ids(value, kind)
    return unique and actual_ids == confirmed_ids


def _archive_stale_reporting(path: Path, value: dict[str, Any], expected: dict[str, Any]) -> Path:
    digest = value.get("review_state_digest")
    prefix = digest[:12] if isinstance(digest, str) and digest else expected["review_state_digest"][:12]
    archived = path.with_name(f"{path.stem}.stale-{prefix}{path.suffix}")
    counter = 1
    while archived.exists():
        archived = path.with_name(f"{path.stem}.stale-{prefix}-{counter}{path.suffix}")
        counter += 1
    path.replace(archived)
    return archived


def _ensure_reporting_template(
    path: Path,
    payload: dict[str, Any],
    kind: str,
    *,
    identity_keys: tuple[str, ...] = REPORTING_IDENTITY_KEYS,
) -> tuple[str, Path | None]:
    if not path.exists():
        atomic_write_json(path, payload)
        return "GENERATED_TEMPLATE", None

    try:
        existing = load_json(path)
    except ValueError:
        existing = {}
    expected = {key: payload[key] for key in identity_keys}
    confirmed_ids, _ = _reporting_ids(payload, kind)
    if _reporting_matches(existing, expected, confirmed_ids or set(), kind, identity_keys=identity_keys):
        status = "CURRENT_TEMPLATE" if _is_generated_reporting_template(existing, kind) else "CURRENT_COMPLETED"
        return status, None
    if _is_generated_reporting_template(existing, kind):
        atomic_write_json(path, payload)
        return "REGENERATED_STALE_TEMPLATE", None
    archived = _archive_stale_reporting(path, existing, expected)
    atomic_write_json(path, payload)
    return "ARCHIVED_STALE_ARTIFACT", archived


def _retire_unneeded_poc(path: Path) -> str | None:
    if not path.exists():
        return None
    try:
        existing = load_json(path)
    except (OSError, ValueError, json.JSONDecodeError):
        existing = {}
    if _is_generated_reporting_template(existing, "poc"):
        path.unlink()
        return "REMOVED_UNNEEDED_TEMPLATE"
    archived = _archive_stale_reporting(path, existing, {"review_state_digest": "0" * 64})
    return f"ARCHIVED_STALE_ARTIFACT:{archived}"


def _ensure_reporting_templates(manifest: dict[str, Any], state: dict[str, Any], run_dir: Path) -> dict[str, Any]:
    payloads = _reporting_payloads(manifest, state)
    paths_by_kind = {
        "severity": run_dir / "reviews/severity-decisions.json",
        "finding_details": run_dir / "reviews/finding-details.json",
    }
    statuses: dict[str, str] = {}
    archives: dict[str, str] = {}
    for kind, path in paths_by_kind.items():
        status, archived = _ensure_reporting_template(path, payloads[kind], kind)
        statuses[kind] = status
        if archived is not None:
            archives[kind] = str(archived)
    result = {
        "templates": {kind: str(path) for kind, path in paths_by_kind.items()},
        "template_status": statuses,
    }
    if archives:
        result["archived_templates"] = archives
    current_severity = _current_severity_for_poc(
        ROOT, manifest, state, paths(run_dir)["severity_decisions"]
    )
    if current_severity is not None:
        severity, severity_bytes, required_ids = current_severity
        poc_path = paths(run_dir)["poc_evidence"]
        result["poc_policy"] = {
            "minimum_severity": "High",
            "required_count": len(required_ids),
            "skipped_below_high_count": len(state["coverage"]["confirmed"]) - len(required_ids),
            "required_ids": required_ids,
        }
        if required_ids:
            poc_payload = _poc_evidence_template(
                manifest, state, severity, severity_bytes, required_ids
            )
            status, archived = _ensure_reporting_template(
                poc_path,
                poc_payload,
                "poc",
                identity_keys=POC_IDENTITY_KEYS,
            )
            if status == "CURRENT_COMPLETED":
                try:
                    current_poc, _ = load_json_bytes(poc_path)
                    validate_poc_evidence(
                        ROOT,
                        manifest,
                        state,
                        severity,
                        severity_bytes,
                        current_poc,
                        run_dir=run_dir,
                    )
                except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
                    status = "INVALID_COMPLETED"
            result["templates"]["poc_evidence"] = str(poc_path)
            result["template_status"]["poc_evidence"] = status
            if archived is not None:
                result.setdefault("archived_templates", {})["poc_evidence"] = str(archived)
        else:
            retired = _retire_unneeded_poc(poc_path)
            if retired is not None:
                result["poc_evidence_status"] = retired
        policy_status = _poc_policy_status(ROOT, paths(run_dir), manifest, state)
        if policy_status is not None:
            result["poc_policy"].update(
                complete_ids=policy_status["complete_ids"],
                pending_ids=policy_status["pending_ids"],
            )
    return result


def _poc_policy_status(
    root: Path,
    values: dict[str, Any],
    manifest: dict[str, Any],
    state: dict[str, Any],
) -> dict[str, Any] | None:
    current = _current_severity_for_poc(root, manifest, state, values["severity_decisions"])
    if current is None:
        return None
    severity, severity_bytes, required_ids = current
    complete_ids: list[str] = []
    poc_errors: list[dict[str, str]] = []
    if required_ids and values["poc_evidence"].is_file() and not values["poc_evidence"].is_symlink():
        poc: dict[str, Any] | None = None
        try:
            poc, _ = load_json_bytes(values["poc_evidence"])
            validate_poc_evidence(
                root,
                manifest,
                state,
                severity,
                severity_bytes,
                poc,
                run_dir=values["manifest"].parent.parent,
            )
            complete_ids = required_ids
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
            complete_ids = []
            code = poc_error_code(error)
            poc_ids_by_source = {
                source.get("path"): finding.get("canonical_id")
                for finding in (poc.get("findings", []) if isinstance(poc, dict) else [])
                for source in (finding.get("sources", []) if isinstance(finding, dict) else [])
                if isinstance(source, dict)
            }
            matched_id = next(
                (canonical_id for path, canonical_id in poc_ids_by_source.items() if path and path in str(error)),
                None,
            )
            for canonical_id in required_ids:
                if matched_id is None or matched_id == canonical_id:
                    poc_errors.append({"canonical_id": canonical_id, "code": code})
    elif required_ids:
        poc_errors = [
            {"canonical_id": canonical_id, "code": "POC_METADATA_MISSING"}
            for canonical_id in required_ids
        ]
    return {
        "minimum_severity": "High",
        "required_count": len(required_ids),
        "skipped_below_high_count": len(state["coverage"]["confirmed"]) - len(required_ids),
        "required_ids": required_ids,
        "complete_ids": complete_ids,
        "pending_ids": [canonical_id for canonical_id in required_ids if canonical_id not in complete_ids],
        "poc_errors": poc_errors,
    }


def status_run(
    root: Path,
    run_dir: Path,
    *,
    emit: bool = True,
    include_execution: bool = False,
) -> dict[str, Any]:
    values, manifest, registry = _load_run(root, run_dir)
    screen = load_json(values["screen_results"]) if values["screen_results"].exists() else None
    resolution = load_json(values["resolution"]) if values["resolution"].exists() else None
    domain_context = load_json(values["domain_context"]) if values["domain_context"].exists() else None
    context = load_json(values["context"]) if values["context"].exists() else None
    state = validate_run(
        root,
        manifest,
        registry,
        screen,
        resolution,
        domain_context,
        context,
        _ledger_paths(run_dir),
        managed_output_root=run_dir,
    )
    atomic_write_json(values["audit_state"], state)
    if emit:
        _log_current_state(state, manifest, resolution, domain_context, run_dir=run_dir)
    if not include_execution:
        return state
    bundle_status = _report_bundle_status(root, values, manifest, state)
    stage_name = _state_stage(state, manifest, resolution, domain_context)
    if stage_name is None:
        return state
    result = {
        **state,
        "stage": stage_name,
        "progress": progress_metadata(
            stage_name,
            summary=_state_progress_summary(
                stage_name, state, manifest, resolution, domain_context
            ),
        ),
        "recommended_execution": recommended_execution(run_dir, stage_name),
        "navigation": values["code_index_status"],
        "report_bundle": bundle_status,
        "report_generation": _report_generation_status(values, bundle_status),
    }
    poc_policy = _poc_policy_status(root, values, manifest, state)
    if poc_policy is not None:
        result["poc_policy"] = poc_policy
        result["required_inputs"] = ["severity-decisions", "finding-details"]
        if poc_policy["required_count"]:
            result["required_inputs"].append("poc-evidence")
            result["pending_poc"] = poc_policy["pending_ids"]
    return result


def next_step(root: Path, run_dir: Path, *, verbose: bool = False, emit: bool = True) -> dict[str, Any]:
    values, manifest, registry = _load_run(root, run_dir)
    resolution: dict[str, Any] | None = None
    if manifest["deferred_domains"]:
        if not values["resolution"].exists():
            if emit:
                _log_domain_resolution(manifest, run_dir=run_dir)
            _render_screen(
                root,
                values,
                "--domain-resolution-out",
                str(values["resolution"]),
                verbose=verbose,
            )
            if emit:
                info(f"Resolution template required: {values['resolution']}")
            return _stage_result(
                run_dir,
                "DOMAIN_RESOLUTION",
                summary=_domain_resolution_summary(manifest),
                navigation=values["code_index_status"],
                template=str(values["resolution"]),
            )
        resolution = load_json(values["resolution"])
        unresolved = validate_domain_resolution(root, manifest, resolution)
        if emit:
            _log_domain_resolution(manifest, unresolved, run_dir=run_dir)
        if unresolved:
            return _stage_result(
                run_dir,
                "DOMAIN_RESOLUTION",
                summary=_domain_resolution_summary(manifest, unresolved),
                navigation=values["code_index_status"],
                unresolved_domains=sorted(unresolved),
            )

    if not values["domain_context"].exists():
        if emit:
            _emit_stage("DOMAIN_CONTEXT", "Resolving required protocol context")
            _log_model_guidance(run_dir, "DOMAIN_CONTEXT")
            info(f"Resolved: 0 / {_context_requirement_count(manifest)}")
            warning(f"{_stage_label('DOMAIN_CONTEXT')} template required")
        extra = []
        if resolution is not None:
            extra.extend(["--domain-resolution", str(values["resolution"])])
        _render_screen(
            root,
            values,
            *extra,
            "--domain-context-out",
            str(values["domain_context"]),
            verbose=verbose,
        )
        if emit:
            info(f"{_stage_label('DOMAIN_CONTEXT')} template required: {values['domain_context']}")
        return _stage_result(
            run_dir,
            "DOMAIN_CONTEXT",
            summary=_domain_context_summary(manifest),
            navigation=values["code_index_status"],
            template=str(values["domain_context"]),
        )
    domain_context = load_json(values["domain_context"])
    unresolved_context = validate_domain_context(root, manifest, domain_context, resolution)
    if emit:
        _log_domain_context(manifest, unresolved_context, run_dir=run_dir)
    if unresolved_context:
        return _stage_result(
            run_dir,
            "DOMAIN_CONTEXT",
            summary=_domain_context_summary(manifest, unresolved_context),
            navigation=values["code_index_status"],
            unresolved_context=sorted(unresolved_context),
        )

    if not values["screen_results"].exists():
        if emit:
            _emit_stage("SCREEN", "Triaging routed checks")
            _log_model_guidance(run_dir, "SCREEN")
            info(f"{_stage_label('SCREEN')} checks: {len(selected_entries(manifest, domain_resolution=resolution))}")
        extra = ["--domain-context", str(values["domain_context"]), "--screen-results-out", str(values["screen_results"])]
        if resolution is not None:
            extra[0:0] = ["--domain-resolution", str(values["resolution"])]
        _render_screen(root, values, *extra, verbose=verbose)
        if emit:
            info(f"{_stage_label('SCREEN')} result template required: {values['screen_results']}")
        return _stage_result(
            run_dir,
            "SCREEN",
            summary=_screen_summary(manifest, resolution=resolution),
            navigation=values["code_index_status"],
            template=str(values["screen_results"]),
        )
    screen = load_json(values["screen_results"])
    candidates = validate_screen_results(root, manifest, screen, resolution)
    if emit:
        _log_screen(screen, candidates, run_dir=run_dir)
    review_snapshot = derive_review_snapshot_id(
        root, manifest, resolution, domain_context, screen
    )
    if candidates:
        if emit:
            _emit_stage("DEEP_REVIEW", "Auditing candidate paths")
            _log_model_guidance(run_dir, "DEEP_REVIEW")
        deep_views: set[Path] = set()
        for owner in sorted({entry["owner_domain"] for entry in selected_entries(manifest, domain_resolution=resolution) if entry["canonical_id"] in candidates}):
            output, _ = _render_owner_view(
                root,
                values,
                profile="deep",
                owner=owner,
                ids={entry["canonical_id"] for entry in selected_entries(manifest, owner, resolution) if entry["canonical_id"] in candidates},
                review_snapshot=review_snapshot,
                resolution=values["resolution"] if resolution is not None else None,
                verbose=verbose,
            )
            deep_views.add(output.resolve())
        _prune_runtime_views(run_dir, "deep", deep_views)
        records, errors = collect_review_records(
            _ledger_paths(run_dir), manifest, registry, candidates, resolution, review_snapshot,
            managed_output_root=run_dir,
        )
        if errors:
            raise ValueError("; ".join(errors))
        pending = candidates - set(records)
        if emit:
            _log_deep(candidates, records, pending)
        if pending:
            return _stage_result(
                run_dir,
                "DEEP_REVIEW",
                summary=f"{len(pending)} {_stage_label('DEEP_REVIEW')} candidates remain",
                navigation=values["code_index_status"],
                pending=sorted(pending),
            )
        suspicious = {
            canonical_id
            for canonical_id, record in records.items()
            if record["status"] == "SUSPICIOUS"
        }
        if suspicious:
            proof_views: set[Path] = set()
            ledgers = _ledger_paths(run_dir)
            for owner in sorted({record["owner_domain"] for record in records.values() if record.get("status") == "SUSPICIOUS"}):
                output, _ = _render_owner_view(
                    root,
                    values,
                    profile="proof",
                    owner=owner,
                    ids={canonical_id for canonical_id, record in records.items() if record.get("status") == "SUSPICIOUS" and record.get("owner_domain") == owner},
                    review_snapshot=review_snapshot,
                    resolution=values["resolution"] if resolution is not None else None,
                    ledger_paths=ledgers,
                    verbose=verbose,
                )
                proof_views.add(output.resolve())
            _prune_runtime_views(run_dir, "proof", proof_views)
            if emit:
                success(f"{_stage_label('DEEP_REVIEW')} complete")
                _emit_stage("PROOF", "Validating suspicious findings")
                _log_model_guidance(run_dir, "PROOF")
                info(f"Remaining proof items: {len(suspicious)}")
            return _stage_result(
                run_dir,
                "PROOF",
                summary=f"{len(suspicious)} suspicious findings require {_stage_label('PROOF')}",
                navigation=values["code_index_status"],
                pending=sorted(suspicious),
                runtime_views=[str(path) for path in sorted(proof_views)],
            )
        if emit:
            success(f"{_stage_label('DEEP_REVIEW')} complete")

    if not candidates:
        _prune_runtime_views(run_dir, "deep", set())
    _prune_runtime_views(run_dir, "proof", set())
    state = status_run(root, run_dir, emit=False)
    if emit:
        _log_report(state, finished=True, run_dir=run_dir)
    result: dict[str, Any] = _stage_result(
        run_dir,
        "REPORT",
        summary=f"Audit state: {state['status']}",
        navigation=values["code_index_status"],
        status=state["status"],
        audit_state=str(values["audit_state"]),
    )
    if state["status"] == "COMPLETE_WITH_FINDINGS":
        reporting = _ensure_reporting_templates(manifest, state, run_dir)
        result.update(reporting)
        required_inputs = ["severity-decisions", "finding-details"]
        policy = reporting.get("poc_policy")
        if isinstance(policy, dict) and policy.get("required_count"):
            required_inputs.append("poc-evidence")
            result["pending_poc"] = policy.get("pending_ids", policy["required_ids"])
        result["required_inputs"] = required_inputs
    return result


def models_run(
    root: Path,
    run_dir: Path | None,
    *,
    model_profile_path: Path | None = None,
    reset_defaults: bool = False,
    init_global: bool = False,
    provider: str = "codex",
) -> dict[str, Any]:
    if init_global:
        if run_dir is not None or model_profile_path is not None or reset_defaults:
            raise ValueError("--init-global cannot be combined with run-scoped model options")
        if provider not in PROVIDERS:
            raise ValueError(f"unsupported provider {provider!r}; expected one of {', '.join(PROVIDERS)}")
        profile = init_global_profile(global_profile_path(provider), provider)
        return {
            "stage": "MODELS",
            "scope": "global",
            "profile_path": str(global_profile_path(provider)),
            "persisted": True,
            "profile": profile,
        }
    if model_profile_path is not None and reset_defaults:
        raise ValueError("--model-profile and --reset-defaults are mutually exclusive")
    if run_dir is None:
        raise ValueError("--run-dir is required unless --init-global is used")
    run_dir = run_dir.resolve()
    values, _, _ = _load_run(root, run_dir)
    if model_profile_path is not None:
        profile = load_profile(model_profile_path.resolve())
        write_profile(values["model_profile"], profile)
    elif reset_defaults:
        current = load_profile(values["model_profile"]) if values["model_profile"].exists() else None
        target_provider = current["provider"] if current is not None else provider
        profile = default_profile(target_provider)
        write_profile(values["model_profile"], profile)
    elif values["model_profile"].exists():
        profile = load_profile(values["model_profile"])
    else:
        profile = default_profile(provider)
    return {
        "stage": "MODELS",
        "profile_path": str(values["model_profile"]),
        "persisted": values["model_profile"].exists(),
        "profile": profile,
    }


def prepare_report_publication(
    root: Path,
    run_dir: Path,
    severity_path: Path | None = None,
    finding_details_path: Path | None = None,
    poc_evidence_path: Path | None = None,
) -> PreparedReportPublication:
    """Validate and serialize a report without changing canonical authoring state."""
    values, manifest, registry = _load_run(root, run_dir)
    state = status_run(root, run_dir, emit=False)
    _log_report(state, finished=False, run_dir=run_dir)
    requested_severity = severity_path.resolve() if severity_path is not None else None
    requested_details = finding_details_path.resolve() if finding_details_path is not None else None
    requested_poc = poc_evidence_path.resolve() if poc_evidence_path is not None else None
    severity = severity_bytes = None
    finding_details = finding_details_bytes = None
    poc_evidence = poc_evidence_bytes = None
    required_poc_ids: list[str] = []
    if state["complete"]:
        if state["status"] == "COMPLETE_WITH_FINDINGS":
            severity_path = severity_path or values["severity_decisions"]
            finding_details_path = finding_details_path or values["finding_details"]
        if severity_path is not None:
            severity, severity_bytes = load_json_bytes(severity_path)
        if finding_details_path is not None:
            finding_details, finding_details_bytes = load_json_bytes(finding_details_path)
        if severity is not None and state["status"] == "COMPLETE_WITH_FINDINGS":
            decisions = severity.get("decisions")
            confirmed = state.get("coverage", {}).get("confirmed", [])
            if isinstance(decisions, dict) and isinstance(confirmed, list):
                try:
                    required_poc_ids = derive_poc_required_ids(confirmed, decisions)
                except ValueError:
                    required_poc_ids = []
        if poc_evidence_path is None and required_poc_ids and values["poc_evidence"].exists():
            poc_evidence_path = values["poc_evidence"]
        if poc_evidence_path is not None:
            poc_evidence, poc_evidence_bytes = load_json_bytes(poc_evidence_path)
        if state["status"] == "COMPLETE_WITH_FINDINGS" and severity is not None:
            _log_poc_policy(
                len(state.get("coverage", {}).get("confirmed", [])),
                required_poc_ids,
                required_poc_ids if required_poc_ids and poc_evidence is None else [],
            )
    resolution = load_json(values["resolution"]) if values["resolution"].exists() else None
    screen = load_json(values["screen_results"]) if values["screen_results"].exists() else None
    domain_context = load_json(values["domain_context"]) if values["domain_context"].exists() else None
    context = load_json(values["context"]) if values["context"].exists() else None
    synthesis = synthesize(
        root,
        manifest,
        registry,
        state,
        _ledger_paths(run_dir),
        severity,
        finding_details=finding_details,
        severity_decisions_bytes=severity_bytes,
        finding_details_bytes=finding_details_bytes,
        poc_evidence=poc_evidence,
        poc_evidence_bytes=poc_evidence_bytes,
        allow_incomplete=not state["complete"],
        domain_resolution=resolution,
        screen_results=screen,
        domain_context=domain_context,
        context=context,
        managed_output_root=run_dir,
    )
    current_state = synthesis.state
    if poc_evidence is not None:
        validate_poc_evidence(
            root,
            manifest,
            current_state,
            severity,
            severity_bytes,
            poc_evidence,
            run_dir=run_dir,
        )
    required_poc_ids = derive_poc_required_ids(
        current_state["coverage"]["confirmed"],
        severity["decisions"],
    ) if current_state["status"] == "COMPLETE_WITH_FINDINGS" else []
    report = synthesis.report
    issues = synthesis.issue_candidates
    severity_bytes = synthesis.severity_decisions_bytes
    finding_details_bytes = synthesis.finding_details_bytes
    if current_state["status"] == "COMPLETE_WITH_FINDINGS" and (
        severity_bytes is None or finding_details_bytes is None
    ):
        raise ValueError("finding report is missing exact reporting input bytes")
    consumed_digest = reporting_inputs_digest(
        severity_bytes=(severity_bytes if current_state["status"] == "COMPLETE_WITH_FINDINGS" else None),
        finding_details_bytes=(finding_details_bytes if current_state["status"] == "COMPLETE_WITH_FINDINGS" else None),
        poc_evidence_bytes=(synthesis.poc_evidence_bytes if required_poc_ids else None),
    )
    bundle = report_bundle_metadata(
        manifest,
        current_state,
        report,
        issues,
        issue_candidates_bytes=json_text(issues).encode("utf-8"),
        severity_decisions_bytes=severity_bytes,
        finding_details_bytes=finding_details_bytes,
        severity_decisions=severity,
        poc_evidence=poc_evidence,
        poc_evidence_bytes=synthesis.poc_evidence_bytes,
    )
    validate_schema(root, "report-bundle.schema.json", bundle)
    issue_bytes = json_text(issues).encode("utf-8")
    bundle_bytes = json_text(bundle).encode("utf-8")
    reporting_inputs = CurrentReportingInputs(
        severity,
        severity_bytes,
        finding_details,
        finding_details_bytes,
        poc_evidence,
        synthesis.poc_evidence_bytes if required_poc_ids else None,
        tuple(required_poc_ids),
        consumed_digest,
    )
    return PreparedReportPublication(
        state=current_state,
        publication_identity=_publication_identity(manifest, current_state),
        reporting_inputs=reporting_inputs,
        reporting_inputs_digest=consumed_digest,
        report_bytes=report.encode("utf-8"),
        issue_candidates_bytes=issue_bytes,
        bundle_bytes=bundle_bytes,
        generation_digest=hashlib.sha256(bundle_bytes).hexdigest(),
        required_poc_ids=tuple(required_poc_ids),
        report=report,
        issue_candidates=issues,
        severity_decisions=severity,
        finding_details=finding_details,
        poc_evidence=poc_evidence,
        write_severity=(requested_severity is not None and requested_severity != values["severity_decisions"].resolve()),
        write_finding_details=(requested_details is not None and requested_details != values["finding_details"].resolve()),
        write_poc_evidence=(requested_poc is not None and requested_poc != values["poc_evidence"].resolve()),
    )


def commit_report_publication(
    root: Path,
    run_dir: Path,
    prepared: PreparedReportPublication,
) -> dict[str, Any]:
    """Commit one prepared report under the publication lock."""
    values, manifest, registry = _load_run(root, run_dir)
    report_generations = values["report_generations"]
    if report_generations.is_symlink() or (report_generations.exists() and not report_generations.is_dir()):
        raise ValueError(f"report-generations is not a regular directory: {report_generations}")
    report_generations.mkdir(parents=True, exist_ok=True)
    generation_id = uuid.uuid4().hex
    generation: Path | None = None
    staging: Path | None = None
    generation_created = False
    pointer_committed = False
    generation_parent_fsync = None
    convenience: dict[str, Any] = {"synced": False, "failed_paths": [], "warnings": []}
    with _report_publication_lock(values["manifest"].parent.parent):
        authoring_snapshots = {
            key: snapshot_file(values[key])
            for key in ("severity_decisions", "finding_details", "poc_evidence", "report_current")
        }
        try:
            fresh_state = status_run(root, run_dir, emit=False)
            if _publication_identity(manifest, fresh_state) != prepared.publication_identity:
                raise ValueError("audit state changed during report publication; retry the report")
            try:
                _current_report_generation(root, values)
            except ValueError as exc:
                warning(f"replacing stale or legacy report pointer: {exc}")
            staging = Path(tempfile.mkdtemp(prefix=f".tmp-{generation_id}-", dir=report_generations))
            artifacts = _report_generation_paths(staging)
            if prepared.state["status"] == "COMPLETE_WITH_FINDINGS":
                atomic_write_bytes(artifacts["report_input_severity"], prepared.reporting_inputs.severity_bytes or b"")
                atomic_write_bytes(artifacts["report_input_details"], prepared.reporting_inputs.finding_details_bytes or b"")
                if prepared.required_poc_ids:
                    atomic_write_bytes(artifacts["poc_evidence"], prepared.reporting_inputs.poc_evidence_bytes or b"")
                    if prepared.poc_evidence is None:
                        raise ValueError("generation PoC evidence is unavailable for source snapshotting")
                    _capture_poc_sources(artifacts["poc_sources"], prepared.poc_evidence, run_dir)
            atomic_write_text(artifacts["report"], prepared.report)
            atomic_write_json(artifacts["issue_candidates"], prepared.issue_candidates or {})
            atomic_write_json(artifacts["report_bundle"], json.loads(prepared.bundle_bytes.decode("utf-8")))
            candidate_issues, issue_bytes = load_json_bytes(artifacts["issue_candidates"])
            candidate_severity = None
            if prepared.state["status"] == "COMPLETE_WITH_FINDINGS":
                candidate_severity = load_json(artifacts["report_input_severity"])
            validate_issue_candidates(root, manifest, prepared.state, candidate_issues, candidate_severity)
            validate_report_generation(
                prepared.report,
                prepared.issue_candidates or {},
                artifacts["report"].read_bytes(),
                candidate_issues,
                issue_bytes,
            )
            validate_schema(root, "report-bundle.schema.json", load_json(artifacts["report_bundle"]))
            if prepared.state["status"] == "COMPLETE_WITH_FINDINGS":
                if prepared.write_severity:
                    atomic_write_bytes(values["severity_decisions"], prepared.reporting_inputs.severity_bytes or b"")
                if prepared.write_finding_details:
                    atomic_write_bytes(values["finding_details"], prepared.reporting_inputs.finding_details_bytes or b"")
                if prepared.write_poc_evidence and prepared.required_poc_ids:
                    atomic_write_bytes(values["poc_evidence"], prepared.reporting_inputs.poc_evidence_bytes or b"")
            fresh_state = status_run(root, run_dir, emit=False)
            if _publication_identity(manifest, fresh_state) != prepared.publication_identity:
                raise ValueError("audit state changed during report publication; retry the report")
            fresh_inputs = load_current_reporting_inputs(root, values, manifest, fresh_state, require_complete=True)
            if fresh_inputs.digest != prepared.reporting_inputs_digest:
                raise ValueError("reporting inputs changed during report publication; retry the report")
            generation = report_generations / f"generation-{prepared.generation_digest}"
            if generation.exists():
                if not generation.is_dir() or generation.is_symlink():
                    raise ValueError(f"content-addressed generation is not a directory: {generation}")
                _validate_existing_generation(
                    artifacts["report"].parent,
                    generation,
                    finding_report=prepared.state["status"] == "COMPLETE_WITH_FINDINGS",
                    poc_required=bool(prepared.required_poc_ids),
                )
                shutil.rmtree(staging)
                staging = None
            else:
                generation_parent_fsync = durable_replace_directory(staging, generation)
                staging = generation
                generation_created = True
                if not generation_parent_fsync:
                    warning("generation parent-directory durability barrier is unavailable; pointer remains atomic")
            pointer = {
                "artifact_type": "report-current",
                "schema_version": REPORT_CURRENT_VERSION,
                "generation": generation.name,
                "report_bundle_sha256": prepared.generation_digest,
                "reporting_inputs_sha256": prepared.reporting_inputs_digest,
            }
            validate_schema(root, "report-current.schema.json", pointer)
            existing_pointer = None
            try:
                existing_pointer = _current_report_generation(root, values)
            except ValueError:
                pass
            if existing_pointer is None or existing_pointer[1] != pointer:
                atomic_write_json(values["report_current"], pointer)
            pointer_committed = True
            bundle_status = _report_bundle_status(root, values, manifest, fresh_state)
            if not bundle_status["current"]:
                raise ValueError(f"report publication is stale: {bundle_status.get('message', 'validation failed')}")
            convenience = _sync_report_convenience_copies(
                values,
                _report_generation_paths(generation),
                finding_report=prepared.state["status"] == "COMPLETE_WITH_FINDINGS",
                poc_required=bool(prepared.required_poc_ids),
            )
            bundle_status = _report_bundle_status(root, values, manifest, fresh_state)
            if not bundle_status["current"]:
                raise ValueError(f"report publication is stale: {bundle_status.get('message', 'validation failed')}")
        except Exception:
            for key, snapshot in authoring_snapshots.items():
                try:
                    restore_file(values[key], snapshot)
                except Exception as error:
                    warning(f"could not roll back {key}: {error}")
            raise
        finally:
            if staging is not None and staging.exists():
                if generation is not None and staging == generation and pointer_committed:
                    pass
                else:
                    shutil.rmtree(staging)
            if (
                generation is not None
                and generation_created
                and not pointer_committed
                and generation.exists()
                and not _pointer_references_generation(values["report_current"], generation.name)
            ):
                shutil.rmtree(generation)
    if prepared.state["status"] == "COMPLETE_WITH_FINDINGS" and not prepared.required_poc_ids:
        try:
            _retire_unneeded_poc(values["poc_evidence"])
        except OSError as error:
            warning(f"could not retire obsolete PoC evidence: {error}")
    if prepared.state["complete"]:
        success("Audit complete")
    else:
        warning("Audit remains incomplete")
    generation_artifacts = _report_generation_paths(generation)
    bundle_status = _report_bundle_status(root, values, manifest, prepared.state)
    result = _stage_result(
        run_dir,
        "REPORT",
        summary=f"Audit state: {prepared.state['status']}",
        navigation=values["code_index_status"],
        status=prepared.state["status"],
        complete=prepared.state["complete"],
        generation=generation.name,
        report=str(generation_artifacts["report"]),
        issue_candidates=str(generation_artifacts["issue_candidates"]),
        report_bundle_path=str(generation_artifacts["report_bundle"]),
        report_current=str(values["report_current"]),
        generation_parent_fsync=generation_parent_fsync,
        convenience={
            **convenience,
            "report": str(values["report"]),
            "issue_candidates": str(values["issue_candidates"]),
            "report_bundle": str(values["report_bundle"]),
        },
        report_bundle=bundle_status,
        report_generation=_report_generation_status(values, bundle_status),
    )
    poc_policy = _poc_policy_status(root, values, manifest, prepared.state)
    if poc_policy is not None:
        result["poc_policy"] = poc_policy
    if prepared.required_poc_ids:
        result["poc_evidence_path"] = str(generation_artifacts["poc_evidence"])
    return result


def report_run(
    root: Path,
    run_dir: Path,
    severity_path: Path | None = None,
    finding_details_path: Path | None = None,
    poc_evidence_path: Path | None = None,
) -> dict[str, Any]:
    prepared = prepare_report_publication(
        root,
        run_dir,
        severity_path,
        finding_details_path,
        poc_evidence_path,
    )
    return commit_report_publication(root, run_dir, prepared)


def _trusted_executable(names: tuple[str, ...]) -> Path:
    for name in names:
        candidate = shutil.which(name)
        if candidate:
            executable = Path(candidate).resolve()
            if executable.is_file() and os.access(executable, os.X_OK):
                return executable
    raise ValueError(f"trusted executable is unavailable: {'/'.join(names)}")


def _bare_runner(value: str, names: set[str], label: str) -> None:
    if value.lower() not in names or "/" in value or "\\" in value:
        raise ValueError(f"{label} PoC command must use the bare trusted runner name")


def _option_values(arguments: list[str], option: str) -> list[str]:
    values: list[str] = []
    for index, token in enumerate(arguments):
        if token == option:
            if index + 1 >= len(arguments) or arguments[index + 1].startswith("-"):
                raise ValueError(f"PoC command option {option} requires a value")
            values.append(arguments[index + 1])
        elif token.startswith(f"{option}="):
            value = token.removeprefix(f"{option}=")
            if not value:
                raise ValueError(f"PoC command option {option} requires a value")
            values.append(value)
    return values


def _reject_poc_options(arguments: list[str], unsafe: set[str]) -> None:
    for token in arguments:
        if token in unsafe or any(token.startswith(f"{option}=") for option in unsafe):
            raise ValueError(f"PoC command option is not permitted: {token}")


def _reject_unexpected_positionals(arguments: list[str], value_options: set[str]) -> None:
    skip_value = False
    for token in arguments:
        if skip_value:
            skip_value = False
            continue
        if token in value_options:
            skip_value = True
        elif token.startswith("-"):
            continue
        else:
            raise ValueError(f"PoC command contains an unbound positional argument: {token}")
    if skip_value:
        raise ValueError("PoC command option requires a value")


def _hardhat_local_executable(workspace: Path) -> Path:
    workspace = workspace.resolve()
    for name in ("hardhat", "hardhat.cmd", "hardhat.exe"):
        candidate = workspace / "node_modules" / ".bin" / name
        if not os.path.lexists(candidate):
            continue
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise ValueError(f"local Hardhat executable is invalid: {candidate}") from error
        if resolved != workspace and workspace not in resolved.parents:
            raise ValueError(f"local Hardhat executable escapes verification workspace: {candidate}")
        if resolved.is_file() and os.access(resolved, os.X_OK):
            return resolved
    raise ValueError("local Hardhat executable is unavailable in the copied dependency snapshot")


def _staged_entrypoint(finding: dict[str, Any], staged_sources: list[dict[str, str]]) -> dict[str, str]:
    entrypoint = finding.get("entrypoint")
    if not isinstance(entrypoint, str) or not entrypoint.strip():
        raise ValueError("PoC entrypoint is empty")
    for source, staged in zip(finding.get("sources", []), staged_sources):
        path = source["path"]
        relative = path.removeprefix("poc/")
        if entrypoint in {path, relative}:
            return staged
    raise ValueError(f"PoC entrypoint is not one of the validated sources: {entrypoint}")


def _resolve_poc_command(
    finding: dict[str, Any],
    workspace: Path,
    staged_sources: list[dict[str, str]],
) -> ResolvedPocCommand:
    runner = finding["runner"]
    command = finding["command"]
    try:
        raw = shlex.split(command, posix=os.name != "nt")
    except ValueError as error:
        raise ValueError(f"PoC command cannot be parsed: {error}") from error
    if not raw:
        raise ValueError("PoC command is empty")
    if any(any(character in token for character in ";|><`\n\r") for token in raw):
        raise ValueError("PoC command contains shell syntax")
    if runner == "foundry":
        if not staged_sources:
            raise ValueError("foundry PoC has no staged source")
        ordered_sources = sorted(staged_sources, key=lambda item: item["staged_path"])
        test_sources = [item for item in ordered_sources if item["staged_path"].lower().endswith(".t.sol")]
        if len(test_sources) > 1:
            raise ValueError("Foundry PoC must identify exactly one staged test source")
        staged = test_sources[0] if test_sources else ordered_sources[0]
        _bare_runner(raw[0], {"forge", "forge.exe"}, "foundry")
        if len(raw) < 2 or raw[1].lower() != "test":
            raise ValueError("foundry PoC command must invoke forge test")
        arguments = raw[2:]
        _reject_poc_options(
            arguments,
            {
                "--allow-failure", "--rerun", "--ffi", "--fork-url", "--rpc-url", "--root",
                "--config-path", "--match-path", "--no-match-path", "--no-match-test",
            },
        )
        _reject_unexpected_positionals(
            arguments,
            {
                "--match-test", "--match-contract", "--no-match-contract", "--color", "--threads", "--jobs",
                "--fuzz-seed", "--fuzz-runs", "--fuzz-timeout", "--gas-snapshot-check", "--gas-snapshot-emit",
                "--etherscan-api-key", "--dump", "--fork-block-number", "--code-size-limit", "--sender",
                "--initial-balance", "--evm-version",
            },
        )
        match_tests = _option_values(arguments, "--match-test")
        if len(match_tests) > 1:
            raise ValueError("foundry PoC command may specify only one --match-test")
        entrypoint = finding["entrypoint"]
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", entrypoint):
            raise ValueError("foundry PoC entrypoint must be an exact test name")
        if match_tests and match_tests[0] != entrypoint:
            raise ValueError("foundry PoC --match-test does not match entrypoint")
        executable = _trusted_executable(("forge", "forge.exe"))
        normalized = [str(executable), "test", *arguments]
        if not match_tests:
            normalized.extend(["--match-test", entrypoint])
        normalized.extend(["--match-path", staged["staged_path"]])
        return ResolvedPocCommand(
            runner="foundry",
            executable=executable,
            argv=tuple(normalized),
            entrypoint=f"{staged['staged_path']}::{entrypoint}",
        )

    if runner != "hardhat":
        raise ValueError(f"unsupported PoC runner: {runner}")
    staged = _staged_entrypoint(finding, staged_sources)
    if raw[0].lower() in {"hardhat", "hardhat.cmd", "hardhat.exe"}:
        _bare_runner(raw[0], {"hardhat", "hardhat.cmd", "hardhat.exe"}, "hardhat")
        executable = _hardhat_local_executable(workspace)
        prefix: list[str] = []
        arguments = raw[1:]
    elif raw[0].lower() in {"npx", "npx.cmd", "npx.exe"}:
        _bare_runner(raw[0], {"npx", "npx.cmd", "npx.exe"}, "Hardhat npx")
        if len(raw) < 3 or raw[1] != "--no-install" or raw[2].lower() not in {"hardhat", "hardhat.cmd", "hardhat.exe"}:
            raise ValueError("Hardhat npx command must be exactly npx --no-install hardhat")
        executable = _trusted_executable(("npx", "npx.cmd", "npx.exe"))
        _hardhat_local_executable(workspace)
        prefix = ["--no-install", "hardhat"]
        arguments = raw[3:]
    else:
        raise ValueError("hardhat PoC command must use hardhat or npx --no-install hardhat")
    _reject_poc_options(
        arguments,
        {"-p", "--package", "--yes", "--install", "--config", "--network", "--no-install"},
    )
    if any("@" in token and not token.startswith("@") for token in arguments):
        raise ValueError("Hardhat PoC command cannot select a package version")
    entrypoint = finding["entrypoint"]
    if Path(entrypoint).is_absolute() or ".." in Path(entrypoint).parts:
        raise ValueError("Hardhat PoC entrypoint must be a relative validated source path")
    original_path = next(
        source["path"]
        for source, source_staged in zip(finding["sources"], staged_sources)
        if source_staged == staged
    )
    aliases = {entrypoint, original_path, original_path.removeprefix("poc/")}
    matches = [index for index, token in enumerate(arguments) if token in aliases]
    if len(matches) != 1:
        raise ValueError("Hardhat PoC command must name its exact validated entrypoint path")
    arguments[matches[0]] = staged["staged_path"]
    for token in arguments:
        if token.endswith((".js", ".cjs", ".mjs", ".ts")) and token != staged["staged_path"]:
            raise ValueError("Hardhat PoC command contains an unrelated script path")
    return ResolvedPocCommand(
        runner="hardhat",
        executable=executable,
        argv=tuple([str(executable), *prefix, *arguments]),
        entrypoint=staged["staged_path"],
    )


def _poc_command_argv(runner: str, command: str) -> list[str]:
    """Retain the old parser entry point while rejecting untrusted paths."""
    try:
        argv = shlex.split(command, posix=os.name != "nt")
    except ValueError as error:
        raise ValueError(f"PoC command cannot be parsed: {error}") from error
    if not argv:
        raise ValueError("PoC command is empty")
    if runner == "foundry":
        _bare_runner(argv[0], {"forge", "forge.exe"}, "foundry")
    elif runner == "hardhat":
        _bare_runner(argv[0], {"hardhat", "hardhat.cmd", "hardhat.exe", "npx", "npx.cmd", "npx.exe"}, "hardhat")
        if Path(argv[0]).name.lower().startswith("npx") and (len(argv) < 3 or argv[1] != "--no-install"):
            raise ValueError("Hardhat npx command must use --no-install")
    else:
        raise ValueError(f"unsupported PoC runner: {runner}")
    if any(any(character in token for character in ";|><`\n\r") for token in argv):
        raise ValueError("PoC command contains shell syntax")
    return argv


def _poc_source_manifest_sha256(finding: dict[str, Any]) -> str:
    return canonical_sha256(
        {
            "sources": [
                {"path": source["path"], "sha256": source["sha256"]}
                for source in finding.get("sources", [])
            ]
        }
    )


def _staged_source_manifest_sha256(staged_sources: list[dict[str, str]]) -> str:
    return canonical_sha256({"sources": staged_sources})


def _output_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    return str(value or "").encode("utf-8")


# Volatile build outputs are never copied into the disposable PoC workspace.
_POC_WORKSPACE_EXCLUDED_DIRS = {
    "out", "cache", "artifacts", "broadcast", "coverage", "typechain-types", ".git", "poc-evidence",
}


def _isolated_poc_workspace(build_root: Path, run_dir: Path) -> Path:
    """Create a disposable copy of the build tree for recorded PoC commands.

    Recorded commands must never mutate the authoritative target/build tree;
    tool default artifact outputs (out/, cache/, artifacts/) land in the copy.
    """
    parent = Path(tempfile.mkdtemp(prefix=".verify-poc-", dir=str(run_dir.parent)))
    try:
        project = parent / "project"
        copy_tree(
            build_root,
            project,
            excluded_names=_POC_WORKSPACE_EXCLUDED_DIRS,
            allow_internal_symlinks=True,
        )
    except BaseException:
        shutil.rmtree(parent, ignore_errors=True)
        raise
    return project


def _stage_poc_sources(workspace: Path, finding: dict[str, Any], run_dir: Path) -> list[dict[str, str]]:
    staged: list[dict[str, str]] = []
    for source in finding.get("sources", []):
        source_path = _poc_source_path(run_dir, source["path"])
        content = source_path.read_bytes()
        if hashlib.sha256(content).hexdigest() != source["sha256"]:
            raise ValueError(f"PoC source changed while staging: {source['path']}")
        relative = Path(*Path(source["path"]).parts[1:])
        target = workspace / "poc-evidence" / relative
        if target.exists() or target.is_symlink():
            raise ValueError(f"duplicate staged PoC source path: {source['path']}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        if target.read_bytes() != content or hashlib.sha256(target.read_bytes()).hexdigest() != source["sha256"]:
            raise ValueError(f"staged PoC source hash mismatch: {source['path']}")
        staged.append({
            "path": source["path"],
            "staged_path": target.relative_to(workspace).as_posix(),
            "sha256": source["sha256"],
        })
    return staged


def _validate_workspace_links(workspace: Path) -> None:
    for directory, names, files in os.walk(workspace, followlinks=False):
        for name in (*names, *files):
            path = Path(directory) / name
            if not path.is_symlink():
                continue
            try:
                resolved = path.resolve(strict=True)
            except (OSError, RuntimeError) as error:
                raise ValueError(f"verification workspace contains an invalid symlink: {path}") from error
            if resolved != workspace and workspace not in resolved.parents:
                raise ValueError(f"verification workspace symlink escapes workspace: {path}")


def _validate_poc_capabilities(workspace: Path) -> None:
    for config in workspace.rglob("foundry.toml"):
        if config.is_symlink():
            raise ValueError(f"verification workspace config is a symlink: {config}")
        if re.search(r"(?im)^\s*ffi\s*=\s*true\b", config.read_text(encoding="utf-8")):
            raise ValueError("Foundry FFI is not permitted during PoC verification")


def _poc_environment(
    workspace: Path,
    executable: Path,
    compiler_version: str | None = None,
) -> dict[str, str]:
    directories = {
        "HOME": workspace / ".poc-home",
        "TMPDIR": workspace / ".poc-tmp",
        "TMP": workspace / ".poc-tmp",
        "TEMP": workspace / ".poc-tmp",
        "XDG_CACHE_HOME": workspace / ".poc-cache",
        "XDG_CONFIG_HOME": workspace / ".poc-config",
        "XDG_DATA_HOME": workspace / ".poc-data",
        "FOUNDRY_HOME": workspace / ".poc-foundry",
        "NPM_CONFIG_CACHE": workspace / ".poc-npm",
        "npm_config_cache": workspace / ".poc-npm",
    }
    for directory in directories.values():
        directory.mkdir(parents=True, exist_ok=True)
    path_entries = [workspace / "node_modules" / ".bin", executable.parent]
    node = shutil.which("node")
    if node:
        path_entries.append(Path(node).resolve().parent)
    solc = shutil.which("solc")
    if solc:
        path_entries.append(Path(solc).resolve().parent)
    path_entries.extend(Path(item) for item in os.defpath.split(os.pathsep) if item)
    path_value = os.pathsep.join(dict.fromkeys(str(path) for path in path_entries if path.is_dir()))
    environment = {"PATH": path_value, **{key: str(value) for key, value in directories.items()}}
    environment.update({key: os.environ[key] for key in ("LANG", "LC_ALL", "TZ") if key in os.environ})
    if os.name == "nt":
        for key in ("SystemRoot", "PATHEXT"):
            if key in os.environ:
                environment[key] = os.environ[key]
        environment["USERPROFILE"] = environment["HOME"]
    environment.update({
        "CI": "1",
        "NO_COLOR": "1",
        "FOUNDRY_OFFLINE": "true",
        "FOUNDRY_FFI": "false",
        "NPM_CONFIG_OFFLINE": "true",
        "npm_config_offline": "true",
    })
    return environment


def _stage_solc(workspace: Path, compiler_version: str | None) -> Path | None:
    if not compiler_version:
        return None
    version = compiler_version.removeprefix("v")
    for candidate in (
        Path.home() / ".solc-select" / "artifacts" / f"solc-{version}" / f"solc-{version}",
        Path.home() / ".svm" / version / f"solc-{version}",
    ):
        if candidate.is_file() and not candidate.is_symlink():
            selected = workspace / ".poc-tools" / f"solc-{version}"
            selected.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(candidate, selected)
            os.chmod(selected, stat.S_IMODE(candidate.stat().st_mode))
            return selected
    return None


def verify_poc(
    root: Path,
    run_dir: Path,
    *,
    timeout: float = 300,
) -> dict[str, Any]:
    """Explicitly execute supported recorded PoCs and write a non-gating receipt."""
    if timeout <= 0:
        raise ValueError("PoC verification timeout must be positive")
    values, manifest, _ = _load_run(root, run_dir)
    state = status_run(root, run_dir, emit=False)
    identity = {
        "artifact_type": "poc-verification",
        "schema_version": POC_VERIFICATION_VERSION,
        "routing_snapshot_id": manifest["routing_snapshot_id"],
        "review_snapshot_id": state.get("review_snapshot_id"),
        "review_state_digest": state.get("review_state_digest"),
    }
    if state.get("status") != "COMPLETE_WITH_FINDINGS":
        return {"stage": "VERIFY_POC", "state": "UNVERIFIED", "reason": "audit is not COMPLETE_WITH_FINDINGS"}
    inputs = load_current_reporting_inputs(root, values, manifest, state, require_complete=True)
    if not inputs.required_poc_ids or inputs.poc_evidence is None or inputs.poc_evidence_bytes is None:
        return {"stage": "VERIFY_POC", "state": "UNVERIFIED", "reason": "no High/Critical PoC is required"}
    poc_hash = hashlib.sha256(inputs.poc_evidence_bytes).hexdigest()
    build_root = Path(manifest["feature_map"]["recon_context"]["build_root"]).resolve()
    if not build_root.is_dir():
        raise ValueError(f"PoC verification build workspace is not a directory: {build_root}")
    results: list[dict[str, Any]] = []
    empty_hash = hashlib.sha256(b"").hexdigest()
    for finding in inputs.poc_evidence.get("findings", []):
        runner = finding["runner"]
        result: dict[str, Any] = {
            "canonical_id": finding["canonical_id"],
            "state": "UNVERIFIED",
            "runner": runner,
            "normalized_argv": ["<unparsed>"],
            "entrypoint": str(finding.get("entrypoint", "<missing>")),
            "executable": "<unresolved>",
            "executable_sha256": empty_hash,
            "source_manifest_sha256": _poc_source_manifest_sha256(finding),
            "staged_manifest_sha256": empty_hash,
            "staged_sources": [],
            "exit_code": None,
            "stdout_sha256": empty_hash,
            "stderr_sha256": empty_hash,
        }
        workspace: Path | None = None
        try:
            workspace = _isolated_poc_workspace(build_root, run_dir)
            _validate_workspace_links(workspace)
            _validate_poc_capabilities(workspace)
            staged_sources = _stage_poc_sources(workspace, finding, run_dir)
            result["staged_sources"] = staged_sources
            result["staged_manifest_sha256"] = _staged_source_manifest_sha256(staged_sources)
            if runner == "custom":
                result["reason"] = "custom PoC runners are not executed automatically"
                result["error_code"] = "POC_VERIFICATION_FAILED"
                # the loop-tail append is unreachable past `continue`; record
                # the UNVERIFIED outcome so the receipt never overstates
                # verification coverage
                results.append(result)
                continue
            resolved = _resolve_poc_command(finding, workspace, staged_sources)
            staged_solc = _stage_solc(
                workspace,
                manifest.get("feature_map", {}).get("recon_context", {}).get("solc_version"),
            )
            if staged_solc is not None and resolved.runner == "foundry":
                resolved = ResolvedPocCommand(
                    runner=resolved.runner,
                    executable=resolved.executable,
                    argv=(*resolved.argv, "--use", str(staged_solc)),
                    entrypoint=resolved.entrypoint,
                )
            result.update(
                normalized_argv=list(resolved.argv),
                entrypoint=resolved.entrypoint,
                executable=str(resolved.executable),
                executable_sha256=hashlib.sha256(resolved.executable.read_bytes()).hexdigest(),
            )
            completed = subprocess.run(
                list(resolved.argv),
                shell=False,
                cwd=str(workspace),
                env=_poc_environment(
                    workspace,
                    resolved.executable,
                    manifest.get("feature_map", {}).get("recon_context", {}).get("solc_version"),
                ),
                capture_output=True,
                timeout=timeout,
                check=False,
            )
            stdout = _output_bytes(completed.stdout)
            stderr = _output_bytes(completed.stderr)
            result.update(
                state="PASSED" if completed.returncode == 0 else "FAILED",
                exit_code=completed.returncode,
                stdout_sha256=hashlib.sha256(stdout).hexdigest(),
                stderr_sha256=hashlib.sha256(stderr).hexdigest(),
            )
            if completed.returncode != 0:
                result["reason"] = "PoC runner exited non-zero"
                result["error_code"] = "POC_VERIFICATION_FAILED"
        except subprocess.TimeoutExpired as error:
            result.update(state="FAILED", reason="PoC runner timed out")
            result["error_code"] = "POC_VERIFICATION_FAILED"
            result["stderr_sha256"] = hashlib.sha256(_output_bytes(error.stderr)).hexdigest()
        except (OSError, ValueError) as error:
            result["reason"] = str(error)
            result["error_code"] = "POC_VERIFICATION_FAILED"
        finally:
            if workspace is not None:
                shutil.rmtree(workspace.parent, ignore_errors=True)
        results.append(result)
    overall = (
        "UNVERIFIED" if any(item["state"] == "UNVERIFIED" for item in results)
        else "FAILED" if any(item["state"] == "FAILED" for item in results)
        else "PASSED"
    )
    receipt = {
        **identity,
        "state": overall,
        "severity_decisions_sha256": hashlib.sha256(inputs.severity_bytes or b"").hexdigest(),
        "poc_evidence_sha256": poc_hash,
        "workspace_policy_version": POC_WORKSPACE_POLICY_VERSION,
        "environment_policy_version": POC_ENVIRONMENT_POLICY_VERSION,
        "network_policy": POC_NETWORK_POLICY,
        "ffi_policy": POC_FFI_POLICY,
        "results": results,
    }
    if len(results) == 1:
        receipt.update(
            runner=results[0]["runner"],
            normalized_argv=results[0]["normalized_argv"],
            entrypoint=results[0]["entrypoint"],
            executable=results[0]["executable"],
            executable_sha256=results[0]["executable_sha256"],
            source_manifest_sha256=results[0]["source_manifest_sha256"],
            staged_manifest_sha256=results[0]["staged_manifest_sha256"],
            staged_sources=results[0]["staged_sources"],
            exit_code=results[0]["exit_code"],
            stdout_sha256=results[0]["stdout_sha256"],
            stderr_sha256=results[0]["stderr_sha256"],
        )
    validate_schema(root, "poc-verification.schema.json", receipt)
    atomic_write_json(values["poc_verification"], receipt)
    return {
        "stage": "VERIFY_POC",
        "state": overall,
        "receipt": str(values["poc_verification"]),
        "results": results,
    }


def _add_logging_flags(parser: argparse.ArgumentParser) -> None:
    logging = parser.add_mutually_exclusive_group()
    logging.add_argument("--quiet", action="store_true", help="suppress progress output")
    logging.add_argument("--verbose", action="store_true", help="forward child diagnostics")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init")
    init.add_argument("target", type=Path)
    init.add_argument("--run-dir", type=Path, required=True)
    init.add_argument("--audit-root", type=Path)
    init.add_argument("--build-root", type=Path)
    init.add_argument("--acquisition-root", type=Path, help="stop automatic build-root discovery above this source boundary")
    init.add_argument("--source-trust", type=str.upper, choices=("TRUSTED", "UNTRUSTED", "UNKNOWN"), default="UNKNOWN")
    init.add_argument("--root", type=Path, default=ROOT)
    init.add_argument("--solc")
    init.add_argument("--present-only", action="store_true")
    init.add_argument("--exclude", action="append", default=[])
    init.add_argument("--include", action="append", default=[])
    init.add_argument("--dependency-root", action="append", default=None)
    init.add_argument("--domain")
    init.add_argument("--domains")
    init.add_argument("--target-commit")
    init.add_argument("--chain-id", type=int)
    init.add_argument("--chain-family")
    init.add_argument("--execution-environment")
    init.add_argument("--fork-block", type=int)
    init.add_argument("--compiler-version")
    init.add_argument("--evm-fork")
    init.add_argument("--protocol-version")
    init.add_argument("--audit-timestamp")
    init.add_argument("--environment-context", type=Path)
    init.add_argument("--require-complete-compilation", action="store_true")
    init.add_argument(
        "--provider",
        choices=PROVIDERS,
        default="codex",
        help="agent provider whose default/global model profile is used when no explicit profile is given",
    )
    model_options = init.add_mutually_exclusive_group()
    model_options.add_argument(
        "--accept-default-models",
        action="store_true",
        help="persist the canonical stage-model profile for the selected provider",
    )
    model_options.add_argument(
        "--model-profile",
        type=Path,
        help="validate and persist a stage-model profile",
    )
    _add_logging_flags(init)

    for name in ("next", "status"):
        command = subparsers.add_parser(name)
        command.add_argument("--run-dir", type=Path, required=True)
        command.add_argument("--root", type=Path, default=ROOT)
        _add_logging_flags(command)

    report = subparsers.add_parser("report")
    report.add_argument("--run-dir", type=Path, required=True)
    report.add_argument("--root", type=Path, default=ROOT)
    report.add_argument("--severity-decisions", type=Path)
    report.add_argument("--finding-details", type=Path)
    report.add_argument("--poc-evidence", type=Path)
    _add_logging_flags(report)

    verify = subparsers.add_parser("verify-poc")
    verify.add_argument("--run-dir", type=Path, required=True)
    verify.add_argument("--root", type=Path, default=ROOT)
    verify.add_argument("--timeout", type=float, default=300)
    _add_logging_flags(verify)

    reports = subparsers.add_parser("reports")
    reports.add_argument("--run-dir", type=Path, required=True)
    reports.add_argument("--root", type=Path, default=ROOT)
    reports_mode = reports.add_mutually_exclusive_group(required=True)
    reports_mode.add_argument("--list", action="store_true", help="list report generations and recovery artifacts")
    reports_mode.add_argument("--gc", action="store_true", help="preview safe report-generation cleanup")
    reports_gc_mode = reports.add_mutually_exclusive_group()
    reports_gc_mode.add_argument("--dry-run", action="store_true", help="do not remove cleanup candidates")
    reports_gc_mode.add_argument("--apply", action="store_true", help="remove verified cleanup candidates")
    _add_logging_flags(reports)

    models = subparsers.add_parser("models")
    models.add_argument("--run-dir", type=Path)
    models.add_argument("--root", type=Path, default=ROOT)
    models.add_argument(
        "--provider",
        choices=PROVIDERS,
        default="codex",
        help="agent provider for --init-global and for runs without a persisted profile",
    )
    models.add_argument(
        "--init-global",
        action="store_true",
        help="create the user-level profile for the selected provider if it does not exist",
    )
    model_options = models.add_mutually_exclusive_group()
    model_options.add_argument(
        "--reset-defaults",
        action="store_true",
        help="replace the run-scoped profile with the canonical defaults of its provider",
    )
    model_options.add_argument(
        "--model-profile",
        type=Path,
        help="validate and replace the run-scoped profile",
    )
    _add_logging_flags(models)

    args = parser.parse_args(argv)
    configure(quiet=args.quiet, verbose=args.verbose)
    try:
        root = args.root.resolve()
        if args.command == "init":
            result = init_run(root, args)
        elif args.command == "next":
            result = next_step(root, args.run_dir, verbose=args.verbose)
        elif args.command == "status":
            result = status_run(root, args.run_dir, include_execution=True)
        elif args.command == "models":
            result = models_run(
                root,
                args.run_dir,
                model_profile_path=args.model_profile,
                reset_defaults=args.reset_defaults,
                init_global=args.init_global,
                provider=args.provider,
            )
        elif args.command == "verify-poc":
            result = verify_poc(root, args.run_dir, timeout=args.timeout)
        elif args.command == "reports":
            result = reports_run(
                root,
                args.run_dir,
                list_only=args.list,
                gc=args.gc,
                dry_run=args.dry_run,
                apply=args.apply,
            )
        else:
            result = report_run(
                root,
                args.run_dir,
                args.severity_decisions,
                args.finding_details,
                args.poc_evidence,
            )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 1 if args.command == "report" and result.get("complete") is False else 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        error(exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
