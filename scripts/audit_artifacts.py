#!/usr/bin/env python3
"""Shared hashing and schema checks for immutable audit-run artifacts."""

from __future__ import annotations

import hashlib
import json
import errno
import os
import re
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_SUITE_ROOT = str(Path(__file__).resolve().parents[1])
if _SUITE_ROOT not in sys.path:
    sys.path.insert(0, _SUITE_ROOT)
from evm_audit_runtime.routing import effective_owner_domain, resolved_routes
from evm_audit_runtime.code_index import validate_code_index
from evm_audit_runtime.reporting import derive_issue_candidates, derive_poc_required_ids
from evm_audit_runtime.versions import REPORT_BUNDLE_VERSION


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# Only treat a field explicitly marked unresolved as unresolved.  Completed
# prose may legitimately mention words such as "unknown".
UNRESOLVED_MARKERS = ("UNKNOWN", "UNRESOLVED", "TODO", "TBD")
ABSENCE_EVIDENCE_KINDS = {
    "source",
    "inheritance",
    "interface",
    "dependency",
    "deployment",
    "environment",
    "compiler-ast",
}
POC_ERROR_CODES = {
    "POC_METADATA_MISSING",
    "POC_TEMPLATE_INCOMPLETE",
    "POC_SOURCE_MISSING",
    "POC_SOURCE_HASH_MISMATCH",
    "POC_SEVERITY_STALE",
    "POC_PATH_INVALID",
    "POC_VERIFICATION_FAILED",
}


def poc_error_code(error: BaseException | str) -> str:
    """Map a PoC validation failure to a stable, user-facing reason code."""
    message = str(error).lower()
    if "template" in message:
        return "POC_TEMPLATE_INCOMPLETE"
    if "source is missing" in message or "missing source" in message:
        return "POC_SOURCE_MISSING"
    if "source hash" in message or "changed while capturing" in message:
        return "POC_SOURCE_HASH_MISMATCH"
    if "path" in message or "escape" in message:
        return "POC_PATH_INVALID"
    if "severity" in message or "review_state" in message or "snapshot" in message:
        return "POC_SEVERITY_STALE"
    if "runner" in message or "verification" in message:
        return "POC_VERIFICATION_FAILED"
    return "POC_METADATA_MISSING"


def load_json(path: Path) -> dict[str, Any]:
    value, _ = load_json_bytes(path)
    return value


def load_json_bytes(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain an object")
    return value, raw


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(canonicalize_json(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class FileSnapshot:
    existed: bool
    content: bytes | None


def snapshot_file(path: Path) -> FileSnapshot:
    if not path.exists():
        return FileSnapshot(False, None)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"snapshot target is not a regular file: {path}")
    return FileSnapshot(True, path.read_bytes())


def restore_file(path: Path, snapshot: FileSnapshot) -> None:
    if snapshot.existed:
        if snapshot.content is None:
            raise ValueError(f"snapshot has no content for existing file: {path}")
        atomic_write_bytes(path, snapshot.content)
    else:
        path.unlink(missing_ok=True)


def reporting_inputs_digest(
    *,
    severity_bytes: bytes | None,
    finding_details_bytes: bytes | None,
    poc_evidence_bytes: bytes | None,
) -> str | None:
    """Hash the exact current reporting-input bytes with stable field names."""
    return reporting_inputs_digest_from_hashes(
        severity_decisions_sha256=(sha256_bytes(severity_bytes) if severity_bytes is not None else None),
        finding_details_sha256=(sha256_bytes(finding_details_bytes) if finding_details_bytes is not None else None),
        poc_evidence_sha256=(sha256_bytes(poc_evidence_bytes) if poc_evidence_bytes is not None else None),
    )


def reporting_inputs_digest_from_hashes(
    *,
    severity_decisions_sha256: str | None,
    finding_details_sha256: str | None,
    poc_evidence_sha256: str | None,
) -> str | None:
    """Hash already-derived reporting input identities without reading files."""
    for label, value in (
        ("severity_decisions_sha256", severity_decisions_sha256),
        ("finding_details_sha256", finding_details_sha256),
        ("poc_evidence_sha256", poc_evidence_sha256),
    ):
        if value is not None and (not isinstance(value, str) or not SHA256_RE.fullmatch(value)):
            raise ValueError(f"{label} must be a SHA-256 hex digest")
    if severity_decisions_sha256 is None and finding_details_sha256 is None and poc_evidence_sha256 is None:
        return None
    if severity_decisions_sha256 is None or finding_details_sha256 is None:
        raise ValueError("finding reports require severity and finding-details bytes")
    return canonical_sha256(
        {
            "artifact_type": "reporting-inputs",
            "schema_version": 1,
            "severity_decisions_sha256": severity_decisions_sha256,
            "finding_details_sha256": finding_details_sha256,
            "poc_evidence_sha256": poc_evidence_sha256,
        }
    )


def require_distinct_paths(*paths: tuple[str, Path | None]) -> None:
    seen: dict[Path, str] = {}
    for label, path in paths:
        if path is None:
            continue
        resolved = path.resolve()
        previous = seen.get(resolved)
        if previous is not None:
            raise ValueError(f"output paths for {previous} and {label} must be distinct: {resolved}")
        seen[resolved] = label


def validate_generated_artifact_path(
    path: Path,
    *,
    audit_root: Path,
    build_root: Path,
    label: str,
    managed_output_root: Path | None = None,
) -> None:
    """Keep security-sensitive generated artifacts inside the managed boundary.

    With a ``managed_output_root`` (already accepted by the output-layout
    validator) the artifact must resolve strictly inside that one subtree and
    must not escape it through ``..`` or symlinks. Standalone low-level use
    without a managed root keeps the legacy strict rule: the artifact must
    live outside both authoritative trees.
    """
    requested = Path(path)
    resolved = requested.resolve()
    if managed_output_root is None:
        for root_label, root in (("audit_root", audit_root), ("build_root", build_root)):
            resolved_root = root.resolve()
            if resolved == resolved_root or resolved_root in resolved.parents:
                raise ValueError(f"{label} must be outside {root_label}: {resolved}")
        return
    managed = managed_output_root.resolve()
    if requested.is_symlink():
        raise ValueError(f"{label} must not be a symlink: {resolved}")
    if managed not in resolved.parents:
        raise ValueError(f"{label} must stay inside the managed output root {managed}: {resolved}")


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def report_bundle_metadata(
    manifest: dict[str, Any],
    state: dict[str, Any],
    report: str | bytes,
    issue_candidates: dict[str, Any],
    *,
    issue_candidates_bytes: bytes | None = None,
    severity_decisions_bytes: bytes | None = None,
    finding_details_bytes: bytes | None = None,
    severity_decisions: dict[str, Any] | None = None,
    poc_evidence: dict[str, Any] | None = None,
    poc_evidence_bytes: bytes | None = None,
) -> dict[str, Any]:
    audit = manifest["audit_context"]
    expected_identity = {
        "routing_snapshot_id": manifest["routing_snapshot_id"],
        "review_snapshot_id": state.get("review_snapshot_id"),
        "review_state_digest": state.get("review_state_digest"),
        "registry_sha256": audit["registry_sha256"],
        "source_digest": audit["source_digest"],
        "compilation_input_digest": audit["compilation_input_digest"],
    }
    if any(issue_candidates.get(key) != value for key, value in expected_identity.items()):
        raise ValueError("report bundle inputs do not match current audit state")
    if issue_candidates_bytes is not None:
        _validate_json_bytes(issue_candidates, issue_candidates_bytes, "issue candidates")
    required_poc_ids: list[str] = []
    if state.get("status") == "COMPLETE_WITH_FINDINGS":
        if severity_decisions_bytes is None or finding_details_bytes is None:
            raise ValueError("report bundle requires exact severity and finding-details inputs")
        if severity_decisions is None:
            try:
                severity_decisions = json.loads(severity_decisions_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ValueError("severity decisions bytes are not valid UTF-8 JSON") from error
        _validate_json_bytes(severity_decisions, severity_decisions_bytes, "severity decisions")
        if poc_evidence is not None and poc_evidence_bytes is not None:
            _validate_json_bytes(poc_evidence, poc_evidence_bytes, "poc evidence")
        decisions = severity_decisions.get("decisions") if isinstance(severity_decisions, dict) else None
        confirmed = state.get("coverage", {}).get("confirmed", [])
        if not isinstance(decisions, dict) or not isinstance(confirmed, list):
            raise ValueError("report bundle requires current severity decisions")
        required_poc_ids = derive_poc_required_ids(confirmed, decisions)
        if required_poc_ids and poc_evidence_bytes is None:
            raise ValueError(f"INCOMPLETE_POC: runnable PoC required for {required_poc_ids}")
    else:
        severity_decisions_bytes = None
        finding_details_bytes = None
        poc_evidence_bytes = None
    return {
        "artifact_type": "report-bundle",
        "schema_version": REPORT_BUNDLE_VERSION,
        "routing_snapshot_id": manifest["routing_snapshot_id"],
        "review_snapshot_id": state.get("review_snapshot_id"),
        "review_state_digest": state.get("review_state_digest"),
        "registry_sha256": audit["registry_sha256"],
        "source_digest": audit["source_digest"],
        "compilation_input_digest": audit["compilation_input_digest"],
        "report_sha256": sha256_bytes(report if isinstance(report, bytes) else report.encode("utf-8")),
        "issue_candidates_sha256": sha256_bytes(
            issue_candidates_bytes
            if issue_candidates_bytes is not None
            else json_text(issue_candidates).encode("utf-8")
        ),
        "severity_decisions_sha256": (
            sha256_bytes(severity_decisions_bytes) if severity_decisions_bytes is not None else None
        ),
        "finding_details_sha256": (
            sha256_bytes(finding_details_bytes) if finding_details_bytes is not None else None
        ),
        "poc_evidence_sha256": (
            sha256_bytes(poc_evidence_bytes) if poc_evidence_bytes is not None and required_poc_ids else None
        ),
    }


def validate_report_generation(
    expected_report: str,
    expected_issue_candidates: dict[str, Any],
    report_bytes: bytes,
    issue_candidates: dict[str, Any],
    issue_candidates_bytes: bytes,
) -> None:
    """Validate committed report bodies against one pure synthesis result."""
    if report_bytes != expected_report.encode("utf-8"):
        raise ValueError("report body is not the deterministic current synthesis")
    expected_issue_bytes = json_text(expected_issue_candidates).encode("utf-8")
    if issue_candidates != expected_issue_candidates or issue_candidates_bytes != expected_issue_bytes:
        raise ValueError("issue candidates are not the deterministic current synthesis")


def _validate_json_bytes(value: dict[str, Any], raw: bytes, label: str) -> None:
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} bytes are not valid UTF-8 JSON") from error
    if parsed != value:
        raise ValueError(f"{label} bytes do not match the consumed artifact")


def canonicalize_json(value: Any) -> Any:
    """Canonicalize object keys while preserving the order of every array."""
    if isinstance(value, dict):
        return {key: canonicalize_json(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [canonicalize_json(item) for item in value]
    return value


def _sorted_json_items(value: Any) -> Any:
    """Sort only schema-defined set-like collections such as evidence."""
    if not isinstance(value, list):
        return value
    normalized = [canonicalize_json(item) for item in value]
    return sorted(
        normalized,
        key=lambda item: json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
    )


def _canonical_domain_resolution(value: Any) -> Any:
    normalized = canonicalize_json(value)
    if isinstance(normalized, dict) and isinstance(normalized.get("domains"), dict):
        for resolution in normalized["domains"].values():
            if isinstance(resolution, dict) and "evidence" in resolution:
                resolution["evidence"] = _sorted_json_items(resolution["evidence"])
    return normalized


def _canonical_domain_context(value: Any) -> Any:
    normalized = canonicalize_json(value)
    if isinstance(normalized, dict) and isinstance(normalized.get("domains"), dict):
        for requirements in normalized["domains"].values():
            if isinstance(requirements, dict):
                for context_entry in requirements.values():
                    if isinstance(context_entry, dict) and "evidence" in context_entry:
                        context_entry["evidence"] = _sorted_json_items(context_entry["evidence"])
    return normalized


def _canonical_screen_results(value: Any) -> Any:
    normalized = canonicalize_json(value)
    if isinstance(normalized, dict) and isinstance(normalized.get("results"), list):
        for result in normalized["results"]:
            if isinstance(result, dict) and "evidence" in result:
                result["evidence"] = _sorted_json_items(result["evidence"])
        normalized["results"] = sorted(
            normalized["results"],
            key=lambda result: result.get("canonical_id", "") if isinstance(result, dict) else json.dumps(result, ensure_ascii=False, sort_keys=True),
        )
    return normalized


def _canonical_review_record(value: Any) -> Any:
    normalized = canonicalize_json(value)
    if isinstance(normalized, dict) and "evidence" in normalized:
        normalized["evidence"] = _sorted_json_items(normalized["evidence"])
    return normalized


def check_body_hash(check: dict[str, Any]) -> str:
    return canonical_sha256(check)


def registry_sha256(registry: dict[str, Any]) -> str:
    return canonical_sha256(registry)


def routing_snapshot_id(manifest: dict[str, Any]) -> str:
    payload = {key: value for key, value in manifest.items() if key != "routing_snapshot_id"}
    audit_context = payload.get("audit_context")
    if isinstance(audit_context, dict):
        payload["audit_context"] = {
            key: value for key, value in audit_context.items() if key != "audit_timestamp"
        }
    return canonical_sha256(payload)


def bind_routing_snapshot(manifest: dict[str, Any]) -> dict[str, Any]:
    result = dict(manifest)
    result["routing_snapshot_id"] = routing_snapshot_id(result)
    return result


def review_snapshot_id(
    manifest: dict[str, Any],
    domain_resolution: dict[str, Any] | None,
    domain_context: dict[str, Any],
    screen_results: dict[str, Any],
) -> str:
    """Hash the exact post-routing inputs consumed by Deep Review."""
    snapshot = manifest.get("routing_snapshot_id")
    if not isinstance(snapshot, str) or not SHA256_RE.fullmatch(snapshot):
        raise ValueError("review snapshot requires a valid routing_snapshot_id")
    # A no-op empty resolution artifact is semantically identical to no Deferred Domains.
    normalized_resolution = None if not manifest.get("deferred_domains") else domain_resolution
    return canonical_sha256(
        {
            "routing_snapshot_id": snapshot,
            "domain_resolution": _canonical_domain_resolution(normalized_resolution),
            "domain_context": _canonical_domain_context(domain_context),
            "screen_results": _canonical_screen_results(screen_results),
        }
    )


def review_state_digest(records: dict[str, dict[str, Any]], candidate_ids: set[str]) -> str:
    """Hash the current latest review record for every Deep candidate."""
    missing = sorted(candidate_ids - set(records))
    if missing:
        raise ValueError(f"cannot derive review_state_digest; missing review records: {missing}")
    return canonical_sha256(
        {
            "candidates": [
                {"canonical_id": canonical_id, "record": _canonical_review_record(records[canonical_id])}
                for canonical_id in sorted(candidate_ids)
            ]
        }
    )


def validate_review_state_binding(value: dict[str, Any], digest: str | None) -> None:
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise ValueError("current review_state_digest is unavailable")
    if value.get("review_state_digest") != digest:
        raise ValueError("artifact has mismatched review_state_digest")


def fsync_parent_directory(path: Path) -> bool:
    """Fsync a parent directory, tolerating only unsupported operations."""
    if os.name == "nt":
        return False
    unsupported = {errno.EINVAL, errno.ENOTSUP, getattr(errno, "EOPNOTSUPP", errno.ENOTSUP)}
    try:
        descriptor = os.open(path.parent, os.O_RDONLY)
    except OSError as error:
        if error.errno in unsupported:
            return False
        raise
    try:
        try:
            os.fsync(descriptor)
        except OSError as error:
            if error.errno in unsupported:
                return False
            raise
    finally:
        os.close(descriptor)
    return True


# Windows raises PermissionError with these codes from os.replace when the
# destination is held open by another handle (no FILE_SHARE_DELETE); POSIX
# replaces succeed in the same situation. Retry only these, boundedly.
_WINDOWS_SHARING_VIOLATIONS = frozenset({32, 33})  # ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION
ATOMIC_REPLACE_RETRY_SECONDS = 5.0
ATOMIC_REPLACE_RETRY_INTERVAL = 0.05


def _replace_boundedly(temporary: str, path: Path) -> None:
    """os.replace with a bounded retry for Windows sharing violations.

    Concurrent processes may briefly hold the destination open (for example
    two report workers re-deriving ``audit-state.json`` outside the
    publication lock). The retry keeps each attempt a full atomic replace
    and always propagates the original error once the budget is exhausted;
    permission problems other than sharing violations fail immediately.
    """
    deadline = time.monotonic() + ATOMIC_REPLACE_RETRY_SECONDS
    while True:
        try:
            os.replace(temporary, path)
            return
        except PermissionError as error:
            if getattr(error, "winerror", None) not in _WINDOWS_SHARING_VIOLATIONS:
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(ATOMIC_REPLACE_RETRY_INTERVAL)


def atomic_write_bytes(path: Path, content: bytes) -> None:
    """Replace a file atomically, leaving no stale partial output."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: str | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        _replace_boundedly(temporary, path)
        temporary = None
        fsync_parent_directory(path)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def atomic_write_text(path: Path, content: str) -> None:
    atomic_write_bytes(path, content.encode("utf-8"))


def atomic_write_json(path: Path, value: Any) -> None:
    atomic_write_text(path, json_text(value))


def durable_replace_directory(source: Path, destination: Path) -> bool:
    """Rename a generation and fsync its parent when the platform supports it."""
    source.replace(destination)
    return fsync_parent_directory(destination)


def invalidate_final_outputs(*paths: Path) -> None:
    for path in paths:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def validate_routing_snapshot(manifest: dict[str, Any]) -> str:
    snapshot = manifest.get("routing_snapshot_id")
    if not isinstance(snapshot, str) or not SHA256_RE.fullmatch(snapshot):
        raise ValueError("routing manifest has no valid routing_snapshot_id")
    expected = routing_snapshot_id(manifest)
    if snapshot != expected:
        raise ValueError("routing manifest snapshot hash is stale or invalid")
    return snapshot


def validate_schema(root: Path, schema_name: str, value: Any) -> None:
    try:
        from jsonschema import Draft202012Validator
    except ImportError as error:  # pragma: no cover - dependency failure is operational
        raise ValueError("jsonschema is required; install requirements-runtime.txt") from error
    schema = load_json(root / "schemas" / schema_name)
    Draft202012Validator.check_schema(schema)
    errors = sorted(Draft202012Validator(schema).iter_errors(value), key=lambda item: list(item.path))
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        raise ValueError(f"{schema_name}:{location}: {error.message}")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{number} must contain an object")
        records.append(value)
    return records


def is_unresolved_value(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.strip().upper()
    return any(
        normalized == marker or normalized.startswith(f"{marker} ") or normalized.startswith(f"{marker}:")
        or normalized.startswith(f"{marker}-") or normalized.startswith(f"{marker}—")
        for marker in UNRESOLVED_MARKERS
    )


def has_unresolved_marker(*values: Any) -> bool:
    return any(is_unresolved_value(value) for value in values)


def artifact_identity(manifest: dict[str, Any]) -> dict[str, Any]:
    """Return the hashes every post-routing artifact must carry."""
    audit = manifest["audit_context"]
    return {
        "routing_snapshot_id": manifest["routing_snapshot_id"],
        "registry_sha256": audit["registry_sha256"],
        "source_digest": audit["source_digest"],
        "compilation_input_digest": audit["compilation_input_digest"],
    }


def validate_artifact_identity(value: dict[str, Any], manifest: dict[str, Any]) -> None:
    expected = artifact_identity(manifest)
    for key, wanted in expected.items():
        if value.get(key) != wanted:
            raise ValueError(f"artifact has mismatched {key}")


def validate_issue_candidates(
    root: Path,
    manifest: dict[str, Any],
    state: dict[str, Any],
    value: dict[str, Any],
    severity_decisions: dict[str, Any] | None = None,
) -> set[str]:
    """Validate an issue artifact against the current reporting projection."""
    validate_schema(root, "issue-candidates.schema.json", value)
    validate_artifact_identity(value, manifest)
    for key in ("review_snapshot_id", "review_state_digest"):
        if value.get(key) != state.get(key):
            raise ValueError(f"issue candidates have mismatched {key}")
    findings = value["findings"]
    ids = [finding["canonical_id"] for finding in findings]
    if len(ids) != len(set(ids)):
        raise ValueError("issue candidates contain duplicate canonical IDs")
    coverage = state.get("coverage")
    confirmed = coverage.get("confirmed") if isinstance(coverage, dict) else None
    if not isinstance(confirmed, list):
        raise ValueError("current confirmed coverage is unavailable")
    unknown = set(ids) - set(confirmed)
    if unknown:
        raise ValueError(f"issue candidates contain non-confirmed canonical IDs: {sorted(unknown)}")
    if state.get("status") == "COMPLETE_WITH_FINDINGS":
        if not isinstance(severity_decisions, dict):
            raise ValueError("issue candidates require current severity decisions")
        decisions = severity_decisions.get("decisions")
        if not isinstance(decisions, dict):
            raise ValueError("issue candidates require a severity decisions object")
        expected = derive_issue_candidates(confirmed, decisions)
    else:
        expected = []
    if findings != expected:
        raise ValueError("issue candidates are not the exact severity projection")
    return set(ids)


def validate_reporting_inputs(
    root: Path,
    manifest: dict[str, Any],
    state: dict[str, Any],
    severity_decisions: dict[str, Any],
    finding_details: dict[str, Any],
) -> None:
    """Validate snapshot copies of the exact reporting inputs for a finding report."""
    for kind, value in (
        ("severity-decisions.schema.json", severity_decisions),
        ("finding-details.schema.json", finding_details),
    ):
        validate_schema(root, kind, value)
        validate_artifact_identity(value, manifest)
        for key in ("review_state_digest",):
            if value.get(key) != state.get(key):
                raise ValueError(f"{kind} has mismatched {key}")
        if value.get("artifact_state") == "TEMPLATE":
            raise ValueError(f"{kind} is still a TEMPLATE")
    coverage = state.get("coverage")
    confirmed = coverage.get("confirmed") if isinstance(coverage, dict) else None
    if not isinstance(confirmed, list):
        raise ValueError("current confirmed coverage is unavailable")
    decisions = severity_decisions.get("decisions")
    findings = finding_details.get("findings")
    if not isinstance(decisions, dict) or not isinstance(findings, list):
        raise ValueError("reporting inputs have invalid ID collections")
    finding_ids = [finding["canonical_id"] for finding in findings]
    if len(finding_ids) != len(set(finding_ids)):
        raise ValueError("finding-details contains duplicate canonical IDs")
    if set(decisions) != set(confirmed) or set(finding_ids) != set(confirmed):
        raise ValueError("reporting input IDs do not match current confirmed coverage")
    if has_unresolved_marker(
        *[
            field
            for item in decisions.values()
            if isinstance(item, dict)
            for field in (
                item.get("severity"),
                item.get("rationale"),
                *(
                    item.get("dimensions", {}).values()
                    if isinstance(item.get("dimensions"), dict)
                    else ()
                ),
            )
        ],
        *[
            field
            for finding in findings
            for field in (
                finding.get("location"),
                finding.get("description"),
                finding.get("recommendation"),
            )
        ],
    ):
        raise ValueError("reporting inputs contain unresolved field markers")




def _poc_allowed_roots(manifest: dict[str, Any], run_dir: Path | None) -> list[Path]:
    del manifest
    return [(run_dir / "poc").resolve()] if run_dir is not None else []


def _resolve_poc_source(path: str, manifest: dict[str, Any], run_dir: Path | None) -> Path:
    candidate_path = Path(path)
    if candidate_path.is_absolute():
        raise ValueError(f"PoC source path must be relative to run-dir/poc: {path}")
    if not candidate_path.parts or ".." in candidate_path.parts:
        raise ValueError(f"PoC source path traversal is not allowed: {path}")
    roots = _poc_allowed_roots(manifest, run_dir)
    if not roots:
        raise ValueError("PoC source validation requires run-dir/poc")
    if candidate_path.parts[0] != "poc":
        raise ValueError(f"PoC source must be stored under run-dir/poc: {path}")
    poc_root = roots[0]
    if (run_dir / "poc").is_symlink():
        raise ValueError(f"PoC source escapes allowed roots: {path}")
    raw = run_dir / candidate_path
    if raw.is_symlink():
        raise ValueError(f"PoC source escapes allowed roots or is not a regular file: {path}")
    candidate = raw.resolve(strict=False)
    if candidate != poc_root and poc_root not in candidate.parents:
        raise ValueError(f"PoC source escapes allowed roots: {path}")
    if candidate.exists() and candidate.is_file():
        return candidate
    raise ValueError(f"PoC source is missing: {path}")


def poc_source_snapshot_name(source: dict[str, Any]) -> str:
    suffix = Path(source["path"]).suffix
    if not suffix or not re.fullmatch(r"\.[A-Za-z0-9_-]+", suffix):
        suffix = ".source"
    return f"{source['sha256']}{suffix}"


def validate_poc_evidence(
    root: Path,
    manifest: dict[str, Any],
    state: dict[str, Any],
    severity_decisions: dict[str, Any],
    severity_decisions_bytes: bytes,
    poc_evidence: dict[str, Any],
    *,
    run_dir: Path | None = None,
    source_dir: Path | None = None,
) -> list[str]:
    """Validate completed, lineage-bound runnable PoC evidence."""
    if not isinstance(severity_decisions_bytes, bytes):
        raise ValueError("severity decisions bytes are required for PoC lineage")
    validate_schema(root, "poc-evidence.schema.json", poc_evidence)
    if state.get("status") != "COMPLETE_WITH_FINDINGS":
        raise ValueError("PoC evidence is only valid for COMPLETE_WITH_FINDINGS")
    if poc_evidence.get("artifact_state") != "COMPLETED":
        raise ValueError("poc-evidence is still a TEMPLATE")
    validate_artifact_identity(poc_evidence, manifest)
    validate_review_state_binding(poc_evidence, state.get("review_state_digest"))
    if poc_evidence.get("review_snapshot_id") != state.get("review_snapshot_id"):
        raise ValueError("poc-evidence has mismatched review_snapshot_id")

    validate_schema(root, "severity-decisions.schema.json", severity_decisions)
    validate_artifact_identity(severity_decisions, manifest)
    validate_review_state_binding(severity_decisions, state.get("review_state_digest"))
    if severity_decisions.get("artifact_state") == "TEMPLATE":
        raise ValueError("severity-decisions is still a TEMPLATE")
    _validate_json_bytes(severity_decisions, severity_decisions_bytes, "severity decisions")
    if poc_evidence["severity_decisions_sha256"] != sha256_bytes(severity_decisions_bytes):
        raise ValueError("poc-evidence has mismatched severity_decisions_sha256")

    coverage = state.get("coverage")
    confirmed = coverage.get("confirmed") if isinstance(coverage, dict) else None
    if not isinstance(confirmed, list):
        raise ValueError("current confirmed coverage is unavailable")
    decisions = severity_decisions.get("decisions")
    if not isinstance(decisions, dict):
        raise ValueError("severity decisions must contain a decisions object")
    required = derive_poc_required_ids(confirmed, decisions)
    findings = poc_evidence.get("findings")
    if not isinstance(findings, list):
        raise ValueError("poc-evidence must contain a findings array")
    ids = [item.get("canonical_id") for item in findings if isinstance(item, dict)]
    if len(ids) != len(findings) or len(ids) != len(set(ids)):
        raise ValueError("poc-evidence contains duplicate or malformed canonical IDs")
    if ids != sorted(required):
        raise ValueError(
            "poc-evidence IDs do not match the current High/Critical projection: "
            f"expected={sorted(required)} actual={ids}"
        )

    for finding in findings:
        canonical_id = finding["canonical_id"]
        if finding["severity"] != decisions[canonical_id]["severity"]:
            raise ValueError(f"poc-evidence severity does not match severity decisions: {canonical_id}")
        if not isinstance(finding.get("command"), str) or not finding["command"].strip():
            raise ValueError(f"poc-evidence command is empty: {canonical_id}")
        if has_unresolved_marker(
            finding.get("command"), finding.get("entrypoint"),
            finding.get("expected_result"), finding.get("result_summary"),
        ):
            raise ValueError(f"poc-evidence contains unresolved fields: {canonical_id}")
        sources = finding.get("sources")
        if not isinstance(sources, list) or not sources:
            raise ValueError(f"poc-evidence has no source: {canonical_id}")
        for source in sources:
            if not SHA256_RE.fullmatch(source["sha256"]):
                raise ValueError(f"poc-evidence source has a bad SHA-256: {source['path']}")
            if source_dir is None:
                source_path = _resolve_poc_source(source["path"], manifest, run_dir)
                source_bytes = source_path.read_bytes()
            else:
                snapshot_name = poc_source_snapshot_name(source)
                source_path = source_dir / snapshot_name
                if (
                    source_path.parent.resolve() != source_dir.resolve()
                    or source_path.is_symlink()
                    or not source_path.is_file()
                ):
                    raise ValueError(f"poc-evidence source snapshot is missing: {source['path']}")
                source_bytes = source_path.read_bytes()
            if sha256_bytes(source_bytes) != source["sha256"]:
                raise ValueError(f"poc-evidence source hash does not match: {source['path']}")
    return required


def validate_context(root: Path, manifest: dict[str, Any], value: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    try:
        validate_schema(root, "audit-context.schema.json", value)
    except ValueError as error:
        errors.append(str(error))
        return errors
    expected = {**manifest["audit_context"], "routing_snapshot_id": manifest["routing_snapshot_id"]}
    for key in sorted(set(expected) | set(value)):
        if value.get(key) != expected.get(key):
            errors.append(f"context.{key} differs from routing snapshot")
    return errors


def absence_evidence_errors(
    evidence: Any,
    scope_complete: Any,
    label: str,
) -> list[str]:
    errors: list[str] = []
    if scope_complete is not True:
        errors.append(f"{label}: NOT_APPLICABLE_CONFIRMED requires scope_complete=true")
    if not isinstance(evidence, list) or not evidence:
        return errors + [f"{label}: non-applicability requires typed evidence"]
    kinds = {item.get("kind") for item in evidence if isinstance(item, dict)}
    if "scope" not in kinds:
        errors.append(f"{label}: non-applicability requires scope evidence")
    if not kinds & (ABSENCE_EVIDENCE_KINDS - {"scope"}):
        errors.append(f"{label}: non-applicability requires evidence for an exclusion dimension")
    return errors


def validate_non_applicability(
    *,
    evidence: Any,
    scope_complete: Any,
    trusted_absence_policy: dict[str, Any] | None,
    recon_quality: dict[str, Any] | None,
    label: str,
    values: tuple[Any, ...] = (),
) -> list[str]:
    """Apply the same fail-closed absence policy to every review stage."""
    errors = absence_evidence_errors(evidence, scope_complete, label)
    if (recon_quality or {}).get("absence_filtering_complete") is not True:
        errors.append(f"{label}: NOT_APPLICABLE requires complete compilation")
    if not isinstance(trusted_absence_policy, dict):
        errors.append(f"{label}: trusted_absence_policy is unavailable")
    else:
        allowed = set(trusted_absence_policy.get("allowed_evidence", []))
        kinds = {item.get("kind") for item in evidence if isinstance(item, dict)} if isinstance(evidence, list) else set()
        if not kinds or not kinds <= allowed:
            errors.append(f"{label}: non-applicability evidence violates trusted_absence_policy")
        if trusted_absence_policy.get("requires_complete_scope") is True and "scope" not in kinds:
            errors.append(f"{label}: complete-scope absence requires scope evidence")
    if has_unresolved_marker(*values):
        errors.append(f"{label}: non-applicability cannot contain unresolved field markers")
    return errors


def _domain_route(manifest: dict[str, Any], domain: str) -> dict[str, Any] | None:
    return next(
        (
            entry
            for entry in [*manifest.get("selected_domains", []), *manifest.get("deferred_domains", [])]
            if entry.get("domain") == domain
        ),
        None,
    )


def trusted_absence_policy(manifest: dict[str, Any], domain: str) -> dict[str, Any] | None:
    route = _domain_route(manifest, domain)
    policy = route.get("trusted_absence_policy") if route else None
    return policy if isinstance(policy, dict) else None


def validate_domain_resolution(
    root: Path,
    manifest: dict[str, Any],
    value: dict[str, Any],
    *,
    require_terminal: bool = False,
) -> set[str]:
    validate_schema(root, "domain-resolution.schema.json", value)
    validate_artifact_identity(value, manifest)
    expected = {entry["domain"] for entry in manifest["deferred_domains"]}
    actual = set(value["domains"])
    if actual != expected:
        raise ValueError(
            "domain resolution must contain exactly Deferred Domains: "
            f"expected={sorted(expected)} actual={sorted(actual)}"
        )

    unresolved: set[str] = set()
    for domain, resolution in value["domains"].items():
        route = _domain_route(manifest, domain)
        if route is None:
            raise ValueError(f"unknown resolved Domain: {domain}")
        status = resolution["status"]
        evidence = resolution["evidence"]
        if status == "PRESENT" and not evidence:
            raise ValueError(f"{domain}: PRESENT requires evidence")
        if status == "ABSENT_CONFIRMED":
            quality = manifest.get("feature_map", {}).get("recon_context", {}).get("recon_quality", {})
            if quality.get("absence_filtering_complete") is not True:
                raise ValueError(f"{domain}: ABSENT_CONFIRMED is unavailable with incomplete compilation")
            errors = validate_non_applicability(
                evidence=evidence,
                scope_complete=resolution["scope_complete"],
                trusted_absence_policy=route.get("trusted_absence_policy"),
                recon_quality=manifest.get("feature_map", {}).get("recon_context", {}).get("recon_quality"),
                label=domain,
            )
            if errors:
                raise ValueError("; ".join(errors))
        if status == "UNKNOWN":
            unresolved.add(domain)
            if require_terminal:
                raise ValueError(
                    f"Deferred Domain {domain} is unresolved; resolve Domain screening before Deep."
                )
    return unresolved


def _non_empty_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict)):
        return bool(value)
    return True


def _eligible_context_domains(
    manifest: dict[str, Any],
    domain_resolution: dict[str, Any] | None,
) -> set[str]:
    domains = {entry["domain"] for entry in manifest.get("selected_domains", [])}
    if domain_resolution is not None:
        domains |= {
            domain
            for domain, resolution in domain_resolution.get("domains", {}).items()
            if resolution.get("status") == "PRESENT"
        }
    return domains


def validate_domain_context(
    root: Path,
    manifest: dict[str, Any],
    value: dict[str, Any],
    domain_resolution: dict[str, Any] | None = None,
    *,
    require_complete: bool = False,
) -> set[str]:
    validate_schema(root, "domain-context.schema.json", value)
    validate_artifact_identity(value, manifest)
    if domain_resolution is not None:
        validate_domain_resolution(root, manifest, domain_resolution)
    requirements = manifest.get("required_context_requirements")
    if not isinstance(requirements, dict):
        raise ValueError("routing manifest has no required_context_requirements")
    expected_domains = _eligible_context_domains(manifest, domain_resolution)
    expected_domains &= set(requirements)
    actual_domains = set(value["domains"])
    if actual_domains != expected_domains:
        raise ValueError(
            "domain context must contain exactly eligible Domains: "
            f"expected={sorted(expected_domains)} actual={sorted(actual_domains)}"
        )

    unresolved: set[str] = set()
    for domain in sorted(expected_domains):
        expected_keys = set(requirements[domain])
        actual_keys = set(value["domains"][domain])
        if actual_keys != expected_keys:
            raise ValueError(
                f"domain context requirements mismatch for {domain}: "
                f"expected={sorted(expected_keys)} actual={sorted(actual_keys)}"
            )
        for key, item in value["domains"][domain].items():
            status = item["status"]
            if status == "KNOWN":
                if not _non_empty_value(item.get("value")) or not item.get("evidence"):
                    raise ValueError(f"{domain}.{key} KNOWN requires value and evidence")
            elif status == "NOT_APPLICABLE":
                route = _domain_route(manifest, domain)
                errors = validate_non_applicability(
                    evidence=item.get("evidence"),
                    scope_complete=item.get("scope_complete"),
                    trusted_absence_policy=route.get("trusted_absence_policy") if route else None,
                    recon_quality=manifest.get("feature_map", {}).get("recon_context", {}).get("recon_quality"),
                    label=f"{domain}.{key}",
                )
                if errors:
                    raise ValueError("; ".join(errors))
            if requirements[domain][key]["required"] and status == "UNKNOWN":
                unresolved.add(f"{domain}.{key}")
                if require_complete:
                    raise ValueError(f"required Domain context remains UNKNOWN: {domain}.{key}")
    return unresolved


def derive_review_snapshot_id(
    root: Path,
    manifest: dict[str, Any],
    domain_resolution: dict[str, Any] | None,
    domain_context: dict[str, Any],
    screen_results: dict[str, Any],
) -> str:
    """Validate all current Deep inputs, then derive their deterministic identity."""
    validate_routing_snapshot(manifest)
    if manifest.get("deferred_domains"):
        if domain_resolution is None:
            raise ValueError("review snapshot requires domain-resolution.json")
        validate_domain_resolution(root, manifest, domain_resolution, require_terminal=True)
    elif domain_resolution is not None:
        validate_domain_resolution(root, manifest, domain_resolution, require_terminal=True)
    validate_domain_context(root, manifest, domain_context, domain_resolution, require_complete=True)
    try:
        from render_runtime import validate_screen_results
    except ImportError:  # pragma: no cover - package-style import
        from scripts.render_runtime import validate_screen_results

    validate_screen_results(root, manifest, screen_results, domain_resolution)
    return review_snapshot_id(manifest, domain_resolution, domain_context, screen_results)


def validate_target_snapshot(
    manifest: dict[str, Any],
    *,
    managed_output_root: Path | None = None,
) -> None:
    """Reject consumption of a manifest after the audited target changed.

    ``managed_output_root`` excludes the controller-owned output subtree from
    the recomputed inventory and digests, so artifacts published after Recon
    do not look like target mutations. Only that subtree is ignored; every
    other project change still invalidates the snapshot.
    """
    try:
        from scope_context import compilation_digests, resolve_build_root, resolve_scope_root, scope_inventory
    except ImportError:  # pragma: no cover - supports package-style imports
        from scripts.scope_context import compilation_digests, resolve_build_root, resolve_scope_root, scope_inventory

    recon = manifest["feature_map"]["recon_context"]
    target_root = resolve_scope_root(Path(recon["target_root"]))
    build_root = resolve_build_root(target_root, Path(recon["build_root"]))
    exclusions = tuple(recon["exclusion_patterns"])
    includes = tuple(recon.get("include_patterns", ()))
    dependency_roots = tuple(recon.get("dependency_roots", ()))
    excluded_roots = (managed_output_root,) if managed_output_root is not None else ()
    files, excluded = scope_inventory(
        target_root, exclusions, includes, dependency_roots, excluded_roots
    )
    current = compilation_digests(
        target_root,
        files,
        recon["solc_version"],
        build_root=build_root,
        dependency_roots=dependency_roots,
        compilation_files=recon.get("compilation_files"),
        compiler_versions=recon.get("compiler_versions"),
        excluded_roots=excluded_roots,
    )
    expected = {
        "source_digest": recon["source_digest"],
        "audit_source_digest": recon["audit_source_digest"],
        "dependency_digest": recon["dependency_digest"],
        "build_config_digest": recon["build_config_digest"],
        "compilation_input_digest": recon["compilation_input_digest"],
    }
    actual = {
        "source_digest": current["audit_source_digest"],
        "audit_source_digest": current["audit_source_digest"],
        **current,
    }
    if (
        str(build_root) != recon["build_root"]
        or excluded != recon["excluded_paths"]
        or any(actual[key] != expected[key] for key in expected)
    ):
        raise ValueError("Target source/build inputs changed after routing. Rerun Recon and Selector.")


def code_index_binding(manifest: dict[str, Any]) -> dict[str, Any] | None:
    navigation = manifest.get("feature_map", {}).get("recon_context", {}).get("navigation_artifacts")
    if navigation is None:
        return None
    if not isinstance(navigation, dict) or set(navigation) != {"code_index"}:
        raise ValueError("recon_context.navigation_artifacts has an invalid shape")
    binding = navigation["code_index"]
    if binding is not None and not isinstance(binding, dict):
        raise ValueError("recon_context.navigation_artifacts.code_index has an invalid shape")
    return binding


def validate_bound_code_index(
    root: Path,
    manifest: dict[str, Any],
    index_path: Path,
    *,
    registry: dict[str, Any] | None = None,
    managed_output_root: Path | None = None,
) -> dict[str, Any]:
    """Validate the exact code index bound to the current routing snapshot."""
    try:
        from render_runtime import validate_manifest
    except ImportError:  # pragma: no cover - supports package-style imports
        from scripts.render_runtime import validate_manifest

    registry = registry or load_json(root / "data/canonical-checks.json")
    validate_manifest(root, manifest, registry)
    validate_target_snapshot(manifest, managed_output_root=managed_output_root)
    binding = code_index_binding(manifest)
    if binding is None:
        raise ValueError("code-index is not bound to Recon")
    raw = index_path.read_bytes()
    if sha256_bytes(raw) != binding["sha256"]:
        raise ValueError("code-index body digest does not match authoritative Recon")
    index, _ = load_json_bytes(index_path)
    if index.get("schema_version") != binding["schema_version"]:
        raise ValueError("code-index schema_version does not match authoritative Recon")
    audit = manifest["audit_context"]
    validate_code_index(
        root,
        index,
        source_digest=audit["source_digest"],
        compilation_input_digest=audit["compilation_input_digest"],
    )
    return index


def bound_code_index_status(
    root: Path,
    manifest: dict[str, Any],
    index_path: Path,
    *,
    registry: dict[str, Any] | None = None,
    managed_output_root: Path | None = None,
) -> dict[str, Any]:
    """Return a diagnostic status without making the optional index authoritative."""
    try:
        binding = code_index_binding(manifest)
    except ValueError as error:
        return {"available": False, "status": "UNAVAILABLE", "message": f"code-index navigation unavailable: {error}"}
    try:
        exists = index_path.exists()
    except OSError as error:
        return {
            "available": False,
            "status": "UNAVAILABLE",
            "message": f"code-index navigation unavailable: {error}",
        }
    if not exists:
        if binding is None:
            return {"available": False, "status": "ABSENT", "message": "code-index navigation was not generated"}
        return {"available": False, "status": "MISSING", "message": "code-index navigation is missing its bound artifact"}
    if binding is None:
        return {"available": False, "status": "UNAVAILABLE", "message": "code-index navigation exists without an authoritative Recon binding"}
    try:
        raw = index_path.read_bytes()
        if sha256_bytes(raw) != binding.get("sha256"):
            return {
                "available": False,
                "status": "TAMPERED",
                "message": "code-index navigation unavailable: body digest does not match authoritative Recon",
            }
        validate_bound_code_index(root, manifest, index_path, registry=registry, managed_output_root=managed_output_root)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        return {
            "available": False,
            "status": "UNAVAILABLE",
            "message": f"code-index navigation unavailable: {error}",
        }
    return {"available": True, "status": "CURRENT", "message": "code-index navigation is current"}
