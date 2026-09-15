#!/usr/bin/env python3
"""Maintain routing-scoped append-only review JSONL and Markdown views."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from evm_audit_runtime.versions import REVIEW_LEDGER_COMMIT_VERSION, REVIEW_RECORD_VERSION
from evm_audit_runtime.state import review_lifecycle_errors

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows does not provide fcntl
    fcntl = None  # type: ignore[assignment]

try:
    import msvcrt
except ImportError:  # pragma: no cover - POSIX does not provide msvcrt
    msvcrt = None  # type: ignore[assignment]

try:
    from audit_artifacts import (
        atomic_write_text,
        check_body_hash,
        derive_review_snapshot_id,
        fsync_parent_directory,
        has_unresolved_marker,
        load_json,
        require_distinct_paths,
        resolved_routes,
        trusted_absence_policy,
        validate_domain_resolution,
        validate_artifact_identity,
        validate_generated_artifact_path,
        validate_non_applicability,
        validate_schema,
        validate_target_snapshot,
    )
    from render_runtime import selected_entries, validate_manifest, validate_screen_results
except ImportError:  # pragma: no cover
    from scripts.audit_artifacts import (
        atomic_write_text,
        check_body_hash,
        derive_review_snapshot_id,
        fsync_parent_directory,
        has_unresolved_marker,
        load_json,
        require_distinct_paths,
        resolved_routes,
        trusted_absence_policy,
        validate_domain_resolution,
        validate_artifact_identity,
        validate_generated_artifact_path,
        validate_non_applicability,
        validate_schema,
        validate_target_snapshot,
    )
    from scripts.render_runtime import selected_entries, validate_manifest, validate_screen_results

try:
    from runtime_log import configure, error, info, stage, success, verbose as verbose_log, warning
except ImportError:  # pragma: no cover
    from scripts.runtime_log import configure, error, info, stage, success, verbose as verbose_log, warning


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = REVIEW_RECORD_VERSION
TERMINAL = {"NOT_APPLICABLE", "REVIEWED_SAFE", "SUSPICIOUS", "CONFIRMED"}
REVIEW_STAGES = {"DEEP_REVIEW", "PROOF"}
IDENTITY_KEYS = ("routing_snapshot_id", "review_snapshot_id", "registry_sha256", "source_digest", "compilation_input_digest")
BASE_IDENTITY_KEYS = tuple(key for key in IDENTITY_KEYS if key != "review_snapshot_id")


@contextmanager
def _ledger_lock(path: Path, *, shared: bool):
    """Use a portable cross-process lock for readers and writers."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(f".{path.name}.lock")
    with lock_path.open("a+b") as lock:
        if fcntl is not None:
            mode = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
            fcntl.flock(lock.fileno(), mode)
            try:
                yield
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            return
        if msvcrt is None:
            raise RuntimeError("review ledger locking is unavailable on this platform")
        # ponytail: Windows readers share the exclusive byte lock; a second lock protocol is not worth the maintenance cost.
        lock.seek(0, os.SEEK_END)
        if lock.tell() == 0:
            lock.write(b"\0")
            lock.flush()
        lock.seek(0)
        msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)
        try:
            yield
        finally:
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)


def _load_unlocked(path: Path) -> list[dict[str, Any]]:
    raw, committed = _authoritative_bytes(path)
    records = _parse_records(raw, path)
    if committed is not None:
        commit = _load_commit_unlocked(path)
        if commit["record_count"] != len(records):
            raise ValueError(f"{_commit_path(path)} record_count does not match the committed prefix")
        revisions = [record.get("revision", 0) for record in records if record.get("record_type") == "review"]
        if commit["last_revision"] != max(revisions, default=0):
            raise ValueError(f"{_commit_path(path)} last_revision does not match the committed prefix")
    return records


def _parse_records(raw: bytes, path: Path) -> list[dict[str, Any]]:
    if not raw:
        return []
    records: list[dict[str, Any]] = []
    for number, line in enumerate(raw.decode("utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{number} must contain an object")
        records.append(value)
    return records


def _commit_path(path: Path) -> Path:
    return path.with_name(f"{path.name}.commit.json")


def _load_commit_unlocked(path: Path) -> dict[str, Any]:
    commit_path = _commit_path(path)
    try:
        value = json.loads(commit_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid review ledger commit sidecar: {commit_path}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"review ledger commit sidecar must be an object: {commit_path}")
    validate_schema(ROOT, "review-ledger-commit.schema.json", value)
    return value


def _authoritative_bytes(path: Path) -> tuple[bytes, dict[str, Any] | None]:
    if not path.exists():
        if _commit_path(path).exists():
            raise ValueError(f"review ledger is missing but its commit sidecar exists: {path}")
        return b"", None
    raw = path.read_bytes()
    commit_path = _commit_path(path)
    if not commit_path.exists():
        return raw, None
    commit = _load_commit_unlocked(path)
    committed_bytes = commit["committed_bytes"]
    if committed_bytes > len(raw):
        raise ValueError(f"review ledger is shorter than its committed prefix: {path}")
    prefix = raw[:committed_bytes]
    if committed_bytes and not prefix.endswith(b"\n"):
        raise ValueError(f"review ledger committed prefix does not end at a complete JSONL record: {path}")
    if hashlib.sha256(prefix).hexdigest() != commit["prefix_sha256"]:
        raise ValueError(f"review ledger committed prefix hash mismatch: {path}")
    if len(raw) > committed_bytes:
        warning(f"{path}: ignoring {len(raw) - committed_bytes} uncommitted tail bytes")
    return prefix, commit


def _commit_metadata(prefix: bytes, records: list[dict[str, Any]]) -> dict[str, Any]:
    revisions = [record.get("revision", 0) for record in records if record.get("record_type") == "review"]
    return {
        "artifact_type": "review-ledger-commit",
        "schema_version": REVIEW_LEDGER_COMMIT_VERSION,
        "committed_bytes": len(prefix),
        "prefix_sha256": hashlib.sha256(prefix).hexdigest(),
        "record_count": len(records),
        "last_revision": max(revisions, default=0),
    }


def _publish_commit(path: Path, prefix: bytes, records: list[dict[str, Any]]) -> None:
    metadata = _commit_metadata(prefix, records)
    validate_schema(ROOT, "review-ledger-commit.schema.json", metadata)
    atomic_write_text(_commit_path(path), json.dumps(metadata, ensure_ascii=False, sort_keys=True) + "\n")


def read_json(path: Path) -> dict[str, Any]:
    return load_json(path)


def checkpoint(manifest: dict[str, Any], review_snapshot_id: str | None = None) -> dict[str, Any]:
    if not review_snapshot_id:
        raise ValueError("checkpoint requires the current review_snapshot_id")
    audit = manifest["audit_context"]
    return {
        "record_type": "checkpoint",
        "schema_version": SCHEMA_VERSION,
        "routing_snapshot_id": manifest["routing_snapshot_id"],
        "review_snapshot_id": review_snapshot_id,
        "registry_sha256": audit["registry_sha256"],
        "source_digest": audit["source_digest"],
        "compilation_input_digest": audit["compilation_input_digest"],
    }


def load(path: Path) -> list[dict[str, Any]]:
    with _ledger_lock(path, shared=True):
        return _load_unlocked(path)


def ledger_content_digest(paths: list[Path]) -> str:
    """Deterministic digest over the committed content of one or more ledgers.

    Generated proof views bind this digest into their identity so a follow-up
    revision cannot be served from a view rendered against older ledger state.
    """
    digest = hashlib.sha256()
    for path in sorted(paths, key=lambda item: item.name):
        with _ledger_lock(path, shared=True):
            data = _authoritative_bytes(path)[0]
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def _manifest_routes(
    manifest: dict[str, Any],
    domain_resolution: dict[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    return {
        entry["canonical_id"]: entry
        for entry in [
            *resolved_routes(manifest, domain_resolution),
            *manifest.get("filtered", []),
        ]
    }


def _nonempty(record: dict[str, Any], fields: Iterable[str]) -> list[str]:
    return [field for field in fields if not isinstance(record.get(field), str) or not record[field].strip()]


def _record_key(canonical_id: Any) -> str:
    return canonical_id if isinstance(canonical_id, str) else repr(canonical_id)


def validate_record_contents(
    record: dict[str, Any],
    manifest: dict[str, Any],
    registry: dict[str, Any],
    expected_ids: set[str] | None = None,
    domain_resolution: dict[str, Any] | None = None,
    review_snapshot_id: str | None = None,
) -> list[str]:
    """Validate one record without applying history-dependent lifecycle rules."""
    errors: list[str] = []
    try:
        validate_schema(ROOT, "review-record.schema.json", record)
    except ValueError as error:
        errors.append(str(error))
    if record.get("record_type") != "review":
        return errors or ["review record must have record_type=review"]
    canonical_id = record.get("canonical_id")
    routes = _manifest_routes(manifest, domain_resolution)
    route = routes.get(canonical_id)
    if route is None:
        errors.append(f"unknown routed canonical ID: {canonical_id}")
    elif route.get("route_status") != "SELECTED" and (expected_ids is None or canonical_id not in expected_ids):
        errors.append(f"review record is not selected: {canonical_id}")
    elif expected_ids is not None and canonical_id not in expected_ids:
        errors.append(f"review record is not a Screen candidate: {canonical_id}")
    if route and record.get("owner_domain") != route.get("owner_domain"):
        errors.append(f"{canonical_id}: owner_domain does not match routing manifest")
    if record.get("routing_snapshot_id") != manifest.get("routing_snapshot_id"):
        errors.append(f"{canonical_id}: routing_snapshot_id does not match manifest")
    if review_snapshot_id is not None and record.get("review_snapshot_id") != review_snapshot_id:
        errors.append(f"{canonical_id}: review_snapshot_id does not match current Deep inputs")
    audit = manifest["audit_context"]
    identity = {
        "routing_snapshot_id": manifest["routing_snapshot_id"],
        "registry_sha256": audit["registry_sha256"],
        "source_digest": audit["source_digest"],
        "compilation_input_digest": audit["compilation_input_digest"],
    }
    for key in BASE_IDENTITY_KEYS[1:]:
        if record.get(key) != identity.get(key):
            errors.append(f"{canonical_id}: {key} does not match manifest")
    checks = {check["canonical_id"]: check for check in registry.get("checks", [])}
    check = checks.get(canonical_id)
    if check is None:
        errors.append(f"unknown canonical ID in registry: {canonical_id}")
    elif record.get("check_body_hash") != check_body_hash(check):
        errors.append(f"{canonical_id}: check_body_hash does not match registry")

    if record.get("review_stage") not in REVIEW_STAGES:
        errors.append(f"{canonical_id}: review_stage must be DEEP_REVIEW or PROOF")
    status = record.get("status")
    if status not in TERMINAL:
        errors.append(f"{canonical_id}: status is not terminal")
    required_fields = {
        "NOT_APPLICABLE": ("applicability",),
        "REVIEWED_SAFE": ("applicability", "code_path", "preserved_invariant"),
        "SUSPICIOUS": ("code_path", "unresolved_reason"),
        "CONFIRMED": ("applicability", "code_path", "preconditions", "exploitability", "impact", "proof"),
    }.get(status, ())
    missing = _nonempty(record, required_fields)
    if missing:
        errors.append(f"{canonical_id}: missing review fields {missing}")
    evidence = record.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        errors.append(f"{canonical_id}: evidence must be a non-empty typed list")
    if status == "REVIEWED_SAFE" and has_unresolved_marker(*(record.get(field) for field in ("applicability", "code_path", "preserved_invariant", "blocking_guard"))):
        errors.append(f"{canonical_id}: REVIEWED_SAFE cannot contain UNKNOWN/UNRESOLVED/TODO fields")
    if status == "SUSPICIOUS":
        if _nonempty(record, ("unresolved_reason",)):
            errors.append(f"{canonical_id}: SUSPICIOUS requires unresolved_reason")
    if status == "NOT_APPLICABLE" and not str(record.get("applicability", "")).startswith("NOT_APPLICABLE"):
        errors.append(f"{canonical_id}: NOT_APPLICABLE must explain non-applicability")
    if status == "NOT_APPLICABLE":
        errors.extend(validate_non_applicability(
            evidence=evidence,
            scope_complete=record.get("scope_complete"),
            trusted_absence_policy=trusted_absence_policy(manifest, record.get("owner_domain", "")),
            recon_quality=manifest.get("feature_map", {}).get("recon_context", {}).get("recon_quality"),
            label=str(canonical_id),
            values=tuple(record.get(field) for field in (
                "applicability", "code_path", "preconditions", "exploitability", "impact", "proof",
                "preserved_invariant", "unresolved_reason", "blocking_guard", "suspected_impact", "suspected_preconditions",
            )),
        ))
    if status == "CONFIRMED" and has_unresolved_marker(*(record.get(field) for field in ("applicability", "code_path", "preconditions", "exploitability", "impact", "proof"))):
        errors.append(f"{canonical_id}: CONFIRMED cannot contain UNKNOWN/UNRESOLVED/TODO fields")
    if status == "CONFIRMED":
        if record.get("review_stage") != "PROOF":
            errors.append(f"{canonical_id}: CONFIRMED requires review_stage=PROOF")
        if not isinstance(evidence, list) or not any(item.get("kind") in {"test", "trace", "invariant", "calculation"} for item in evidence if isinstance(item, dict)):
            errors.append(f"{canonical_id}: CONFIRMED requires strong proof evidence")
    return errors


def validate_record(
    record: dict[str, Any],
    manifest: dict[str, Any],
    registry: dict[str, Any],
    expected_ids: set[str] | None = None,
    domain_resolution: dict[str, Any] | None = None,
    review_snapshot_id: str | None = None,
) -> list[str]:
    """Compatibility alias; use validate_records for authoritative history validation."""
    return validate_record_contents(
        record, manifest, registry, expected_ids, domain_resolution, review_snapshot_id
    )


def validate_record_transition(
    previous: dict[str, Any] | None,
    current: dict[str, Any],
) -> list[str]:
    """Validate lifecycle rules between adjacent records."""
    return review_lifecycle_errors(previous, current)


def validate_records(
    records: list[dict[str, Any]],
    manifest: dict[str, Any],
    registry: dict[str, Any],
    expected_ids: set[str] | None = None,
    domain_resolution: dict[str, Any] | None = None,
    review_snapshot_id: str | None = None,
) -> list[str]:
    errors: list[str] = []
    if not records:
        return ["ledger is empty"]
    if records[0].get("record_type") != "checkpoint":
        errors.append("first JSONL record must be a checkpoint")
    else:
        try:
            validate_schema(ROOT, "review-record.schema.json", records[0])
        except ValueError as error:
            errors.append(str(error))
        audit = manifest["audit_context"]
        expected = checkpoint(manifest, review_snapshot_id) if review_snapshot_id else {
            "routing_snapshot_id": manifest["routing_snapshot_id"],
            "registry_sha256": audit["registry_sha256"],
            "source_digest": audit["source_digest"],
            "compilation_input_digest": audit["compilation_input_digest"],
        }
        for key in IDENTITY_KEYS if review_snapshot_id else BASE_IDENTITY_KEYS:
            if records[0].get(key) != expected.get(key):
                errors.append(f"checkpoint {key} does not match manifest")
    latest: dict[str, dict[str, Any]] = {}
    for record in records[1:]:
        canonical_id = record.get("canonical_id")
        record_key = _record_key(canonical_id)
        if record.get("record_type") == "checkpoint":
            errors.append("checkpoint is only allowed as the first JSONL record")
            continue
        record_errors = validate_record_contents(record, manifest, registry, expected_ids, domain_resolution, review_snapshot_id)
        errors.extend(record_errors)
        previous = latest.get(record_key)
        revision = record.get("revision")
        if previous is None:
            if revision != 1:
                errors.append(f"{canonical_id}: first review revision must be 1")
        elif revision != previous.get("revision", 0) + 1:
            errors.append(
                f"{canonical_id}: revision must be {previous.get('revision', 0) + 1}, got {revision}"
            )
        errors.extend(validate_record_transition(previous, record))
        latest[record_key] = record
    return errors


def collect_review_records(
    paths: list[Path],
    manifest: dict[str, Any],
    registry: dict[str, Any],
    expected_ids: set[str],
    domain_resolution: dict[str, Any] | None = None,
    review_snapshot_id: str | None = None,
    *,
    managed_output_root: Path | None = None,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Validate and combine ledgers without allowing cross-ledger overwrites."""
    values_by_path, errors = _validated_ledgers(
        paths, manifest, registry, expected_ids, domain_resolution, review_snapshot_id,
        managed_output_root=managed_output_root,
    )
    records: dict[str, dict[str, Any]] = {}
    for values in values_by_path:
        for record in values[1:]:
            if record.get("record_type") != "review":
                continue
            canonical_id = record.get("canonical_id")
            records[_record_key(canonical_id)] = record
    return records, errors


def _validated_ledgers(
    paths: list[Path],
    manifest: dict[str, Any],
    registry: dict[str, Any],
    expected_ids: set[str],
    domain_resolution: dict[str, Any] | None = None,
    review_snapshot_id: str | None = None,
    *,
    managed_output_root: Path | None = None,
) -> tuple[list[list[dict[str, Any]]], list[str]]:
    validate_target_snapshot(manifest, managed_output_root=managed_output_root)
    values_by_path: list[list[dict[str, Any]]] = []
    errors: list[str] = []
    record_sources: dict[str, Path] = {}
    for path in paths:
        if not path.exists():
            continue
        try:
            values = load(path)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            errors.append(f"{path}: {error}")
            continue
        errors.extend(
            f"{path}: {error}"
            for error in validate_records(values, manifest, registry, expected_ids, domain_resolution, review_snapshot_id)
        )
        for record in values[1:]:
            if record.get("record_type") != "review":
                continue
            canonical_id = record.get("canonical_id")
            record_key = _record_key(canonical_id)
            if record_key in record_sources and record_sources[record_key] != path:
                errors.append(f"duplicate Deep record across ledgers: {canonical_id}")
            else:
                record_sources[record_key] = path
        values_by_path.append(values)
    return values_by_path, errors


def collect_review_history(
    paths: list[Path],
    manifest: dict[str, Any],
    registry: dict[str, Any],
    expected_ids: set[str],
    domain_resolution: dict[str, Any] | None = None,
    review_snapshot_id: str | None = None,
    *,
    managed_output_root: Path | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Return the validated event history for a Markdown audit view."""
    values_by_path, errors = _validated_ledgers(
        paths, manifest, registry, expected_ids, domain_resolution, review_snapshot_id,
        managed_output_root=managed_output_root,
    )
    history = [
        record
        for values in values_by_path
        for record in values[1:]
        if record.get("record_type") == "review"
    ]
    return [checkpoint(manifest, review_snapshot_id or (history[0].get("review_snapshot_id") if history else None)), *history], errors


@contextmanager
def _writer_lock(path: Path):
    """Serialize revision calculation and append for one ledger."""
    with _ledger_lock(path, shared=False):
        yield


def append(
    path: Path,
    manifest: dict[str, Any],
    record: dict[str, Any],
    registry: dict[str, Any] | None = None,
    expected_ids: set[str] | None = None,
    domain_resolution: dict[str, Any] | None = None,
    *,
    domain_context: dict[str, Any] | None = None,
    screen_results: dict[str, Any] | None = None,
    managed_output_root: Path | None = None,
) -> None:
    if domain_context is None or screen_results is None:
        raise ValueError("append requires current domain_context and screen_results")
    current_snapshot = derive_review_snapshot_id(
        ROOT, manifest, domain_resolution, domain_context, screen_results
    )
    with _writer_lock(path):
        validate_target_snapshot(manifest, managed_output_root=managed_output_root)
        if record.get("record_type") != "review":
            raise ValueError("append requires record_type=review")
        if record.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(f"append requires schema_version={SCHEMA_VERSION}")
        identity = checkpoint(manifest, current_snapshot)
        for key in IDENTITY_KEYS:
            if key in record and record[key] != identity[key]:
                raise ValueError(f"append record {key} does not match manifest")
        record = {**record, **{key: identity[key] for key in IDENTITY_KEYS}}
        registry_value = registry or read_json(ROOT / "data/canonical-checks.json")
        records = _load_unlocked(path)
        if records:
            existing_errors = validate_records(
                records, manifest, registry_value, expected_ids, domain_resolution, current_snapshot
            )
            if existing_errors:
                raise ValueError(f"invalid existing ledger: {'; '.join(existing_errors)}")
        record = dict(record)
        history = [item for item in records[1:] if item.get("canonical_id") == record.get("canonical_id")]
        expected_revision = history[-1].get("revision", 0) + 1 if history else 1
        if "revision" not in record:
            record["revision"] = expected_revision
        elif record["revision"] != expected_revision:
            raise ValueError(
                f"append revision for {record.get('canonical_id')} must be {expected_revision}"
            )
        errors = validate_record_contents(
            record, manifest, registry_value, expected_ids, domain_resolution, current_snapshot
        )
        if errors:
            raise ValueError("; ".join(errors))
        lifecycle_errors = validate_record_transition(history[-1] if history else None, record)
        if lifecycle_errors:
            raise ValueError("; ".join(lifecycle_errors))
        lines = []
        if not records:
            lines.append(json.dumps(identity, ensure_ascii=False, sort_keys=True) + "\n")
        lines.append(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        prefix, commit = _authoritative_bytes(path)
        records = _parse_records(prefix, path)
        if commit is None:
            # Establish the prior prefix before this append can become visible.
            _publish_commit(path, prefix, records)
            commit = _load_commit_unlocked(path)
        if commit is not None and path.exists() and len(path.read_bytes()) > len(prefix):
            # An explicit append is also the recovery point for a non-authoritative tail.
            atomic_write_text(path, prefix.decode("utf-8"))
        created = not path.exists()
        payload = "".join(lines).encode("utf-8")
        descriptor = os.open(path, os.O_APPEND | os.O_WRONLY | os.O_CREAT, 0o644)
        try:
            remaining = payload
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError("review ledger append made no progress")
                remaining = remaining[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        committed_prefix = path.read_bytes()
        committed_records = _parse_records(committed_prefix, path)
        _publish_commit(path, committed_prefix, committed_records)
        if created:
            fsync_parent_directory(path)


def pending(
    manifest: dict[str, Any],
    screen: dict[str, Any],
    ledgers: list[Path],
    registry: dict[str, Any],
    domain_resolution: dict[str, Any] | None = None,
    review_snapshot_id: str | None = None,
    *,
    managed_output_root: Path | None = None,
) -> dict[str, list[str]]:
    validate_target_snapshot(manifest, managed_output_root=managed_output_root)
    validate_schema(ROOT, "screen-results.schema.json", screen)
    validate_artifact_identity(screen, manifest)
    selected = {entry["canonical_id"] for entry in selected_entries(manifest, domain_resolution=domain_resolution)}
    screen_records = screen.get("results", [])
    screened = {entry["canonical_id"] for entry in screen_records}
    if len(screened) != len(screen_records) or not screened <= selected:
        raise ValueError("partial screen results contain duplicate or non-selected IDs")
    for entry in screen_records:
        if entry["result"] == "NOT_APPLICABLE_CONFIRMED":
            route = next(
                (item for item in selected_entries(manifest, domain_resolution=domain_resolution)
                 if item["canonical_id"] == entry["canonical_id"]),
                None,
            )
            errors = validate_non_applicability(
                evidence=entry["evidence"],
                scope_complete=entry.get("scope_complete"),
                trusted_absence_policy=trusted_absence_policy(manifest, route["owner_domain"]) if route else None,
                recon_quality=manifest.get("feature_map", {}).get("recon_context", {}).get("recon_quality"),
                label=entry["canonical_id"],
            )
            if errors:
                raise ValueError("; ".join(errors))
    candidates = {entry["canonical_id"] for entry in screen_records if entry["result"] == "CANDIDATE"}
    records, errors = collect_review_records(
        ledgers, manifest, registry, candidates, domain_resolution, review_snapshot_id,
        managed_output_root=managed_output_root,
    )
    if errors:
        raise ValueError("; ".join(errors))
    safe_done = {canonical_id for canonical_id, record in records.items() if record["status"] in {"NOT_APPLICABLE", "REVIEWED_SAFE", "CONFIRMED"}}
    return {
        "screen_pending": sorted(selected - screened),
        "deep_pending": sorted(candidates - set(records)),
        "suspicious": sorted(canonical_id for canonical_id, record in records.items() if record["status"] == "SUSPICIOUS"),
        "complete": sorted((selected - candidates) | safe_done),
    }


def render_markdown(records: list[dict[str, Any]], manifest: dict[str, Any], registry: dict[str, Any] | None = None) -> str:
    if not records:
        return ""
    checkpoint_record = records[0]
    lines = [
        "<!-- GENERATED REVIEW VIEW: JSONL is authoritative; do not edit by hand. -->",
        f"- **Routing snapshot:** `{checkpoint_record.get('routing_snapshot_id')}`",
        f"- **Review snapshot:** `{checkpoint_record.get('review_snapshot_id')}`",
        f"- **Registry:** `{checkpoint_record.get('registry_sha256')}`",
        f"- **Source digest:** `{checkpoint_record.get('source_digest')}`",
        f"- **Compilation input digest:** `{checkpoint_record.get('compilation_input_digest')}`",
        "",
    ]
    checks = {check["canonical_id"]: check for check in (registry or read_json(ROOT / "data/canonical-checks.json")).get("checks", [])}
    for record in records[1:]:
        canonical_id = record.get("canonical_id", "unknown")
        title = checks.get(canonical_id, {}).get("title", "")
        lines.extend([f"### {canonical_id} — {title}"])
        for key, label in (
            ("revision", "Revision"), ("review_stage", "Review stage"), ("owner_domain", "Owner Domain"), ("check_body_hash", "Check body hash"),
            ("status", "Status"), ("applicability", "Applicability"), ("code_path", "Code path"),
            ("preconditions", "Preconditions"), ("exploitability", "Exploitability"), ("impact", "Impact"),
            ("proof", "PoC / Invariant violation"), ("preserved_invariant", "Preserved invariant"),
            ("unresolved_reason", "Unresolved reason"),
        ):
            if key in record:
                lines.append(f"- **{label}:** {record[key]}")
        if "evidence" in record:
            lines.append("- **Evidence:** " + "; ".join(f"{item['kind']}:{item['location']} — {item['reason']}" for item in record["evidence"]))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write_ledger(
    path: Path,
    manifest: dict[str, Any],
    records: Iterable[dict[str, Any]],
    registry: dict[str, Any] | None = None,
    expected_ids: set[str] | None = None,
    domain_resolution: dict[str, Any] | None = None,
    *,
    domain_context: dict[str, Any] | None = None,
    screen_results: dict[str, Any] | None = None,
    managed_output_root: Path | None = None,
) -> None:
    if domain_context is None or screen_results is None:
        raise ValueError("write_ledger requires current domain_context and screen_results")
    current_snapshot = derive_review_snapshot_id(
        ROOT, manifest, domain_resolution, domain_context, screen_results
    )
    with _writer_lock(path):
        validate_target_snapshot(manifest, managed_output_root=managed_output_root)
        if path.exists() or _commit_path(path).exists():
            raise ValueError(f"refusing to overwrite existing ledger: {path}")
        prepared: list[dict[str, Any]] = []
        next_revision: dict[str, int] = {}
        identity = checkpoint(manifest, current_snapshot)
        for raw_record in records:
            record = {**raw_record, **{key: identity[key] for key in IDENTITY_KEYS}}
            canonical_id = record.get("canonical_id")
            record_key = _record_key(canonical_id)
            if "revision" not in record:
                record["revision"] = next_revision.get(record_key, 0) + 1
            if isinstance(record.get("revision"), int):
                next_revision[record_key] = record["revision"]
            prepared.append(record)
        values = [identity, *prepared]
        errors = validate_records(
            values,
            manifest,
            registry or read_json(ROOT / "data/canonical-checks.json"),
            expected_ids,
            domain_resolution,
            current_snapshot,
        )
        if errors:
            raise ValueError("; ".join(errors))
        _publish_commit(path, b"", [])
        atomic_write_text(
            path,
            "".join(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n" for value in values),
        )
        prefix = path.read_bytes()
        _publish_commit(path, prefix, values)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--screen-results", type=Path, required=True)
    parser.add_argument("--domain-context", type=Path, required=True)
    parser.add_argument("--domain-resolution", type=Path)
    parser.add_argument("--registry", type=Path, default=ROOT / "data/canonical-checks.json")
    parser.add_argument("--ledger", type=Path, action="append", default=[])
    parser.add_argument("--pending", action="store_true")
    parser.add_argument("--append-record", type=Path)
    parser.add_argument("--render-markdown", type=Path)
    parser.add_argument(
        "--managed-output-root",
        type=Path,
        help="controller-owned audit output root; required when the run lives inside the audited project",
    )
    parser.add_argument("--quiet", action="store_true", help="suppress progress output")
    parser.add_argument("--verbose", action="store_true", help="include per-check review details")
    args = parser.parse_args(argv)
    configure(quiet=args.quiet, verbose=args.verbose)
    try:
        stage("DEEP_REVIEW", detail="Tracking candidate progress")
        manifest, registry = read_json(args.manifest), read_json(args.registry)
        validate_manifest(ROOT, manifest, registry)
        validate_target_snapshot(manifest, managed_output_root=args.managed_output_root)
        recon_context = manifest["feature_map"]["recon_context"]
        audit_root = Path(recon_context["target_root"])
        build_root = Path(recon_context["build_root"])
        for ledger in args.ledger:
            validate_generated_artifact_path(
                ledger,
                audit_root=audit_root,
                build_root=build_root,
                label="review ledger",
                managed_output_root=args.managed_output_root,
            )
        require_distinct_paths(
            ("manifest", args.manifest),
            ("registry", args.registry),
            ("screen results", args.screen_results),
            ("domain resolution", args.domain_resolution),
            ("domain context", args.domain_context),
            ("append record", args.append_record),
            ("review Markdown", args.render_markdown),
            *[("review ledger", ledger) for ledger in args.ledger],
        )
        if args.render_markdown:
            validate_generated_artifact_path(
                args.render_markdown,
                audit_root=audit_root,
                build_root=build_root,
                label="review Markdown",
                managed_output_root=args.managed_output_root,
            )
        screen = read_json(args.screen_results)
        domain_resolution = read_json(args.domain_resolution) if args.domain_resolution else None
        domain_context = read_json(args.domain_context)
        current_snapshot = derive_review_snapshot_id(
            ROOT, manifest, domain_resolution, domain_context, screen
        )
        if args.pending:
            progress = pending(
                manifest, screen, args.ledger, registry, domain_resolution, current_snapshot,
                managed_output_root=args.managed_output_root,
            )
            print(json.dumps(progress, ensure_ascii=False, sort_keys=True))
            candidate_count = sum(item.get("result") == "CANDIDATE" for item in screen.get("results", []))
            info(f"Reviewed: {candidate_count - len(progress['deep_pending'])} / {candidate_count}")
            info(f"Remaining: {len(progress['deep_pending'])}")
            if progress["suspicious"]:
                warning(f"{len(progress['suspicious'])} review item(s) remain SUSPICIOUS")
            return 0
        candidates = validate_screen_results(ROOT, manifest, screen, domain_resolution)
        appended_record: dict[str, Any] | None = None
        if args.append_record:
            if len(args.ledger) != 1:
                raise ValueError("--append-record requires exactly one --ledger output")
            appended_record = read_json(args.append_record)
            append(
                args.ledger[0],
                manifest,
                appended_record,
                registry,
                candidates,
                domain_resolution,
                domain_context=domain_context,
                screen_results=screen,
                managed_output_root=args.managed_output_root,
            )
            success("Review ledger updated")
        records: dict[str, dict[str, Any]] = {}
        if args.render_markdown:
            values, errors = collect_review_history(
                args.ledger, manifest, registry, candidates, domain_resolution, current_snapshot,
                managed_output_root=args.managed_output_root,
            )
            if errors:
                raise ValueError("; ".join(errors))
            args.render_markdown.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_text(args.render_markdown, render_markdown(values, manifest, registry))
            success(f"Review view written to {args.render_markdown}")
            records, errors = collect_review_records(
                args.ledger, manifest, registry, candidates, domain_resolution, current_snapshot,
                managed_output_root=args.managed_output_root,
            )
        elif args.append_record:
            records, errors = collect_review_records(
                args.ledger, manifest, registry, candidates, domain_resolution, current_snapshot,
                managed_output_root=args.managed_output_root,
            )
            if errors:
                raise ValueError("; ".join(errors))
        if args.append_record or args.render_markdown:
            reviewed = len(records)
            info(f"Reviewed: {reviewed} / {len(candidates)}")
            info(f"Remaining: {len(candidates) - reviewed}")
            suspicious = sum(record.get("status") == "SUSPICIOUS" for record in records.values())
            if suspicious:
                warning(f"{suspicious} review item(s) remain SUSPICIOUS")
            if args.verbose:
                for record in sorted(records.values(), key=lambda item: item["canonical_id"]):
                    verbose_log(f"[REVIEW] {record['canonical_id']} -> {record['status']}")
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        error(exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
