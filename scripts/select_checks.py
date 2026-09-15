#!/usr/bin/env python3
"""Route canonical checks once from a scope-bound Feature Map v4."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from evm_audit_runtime.controller_state import progress_metadata
from evm_audit_runtime.versions import ENVIRONMENT_CONTEXT_VERSION, FEATURE_MAP_VERSION, FEATURE_REGISTRY_VERSION, ROUTING_MANIFEST_VERSION

try:
    from audit_artifacts import atomic_write_text, bind_routing_snapshot, check_body_hash, registry_sha256, require_distinct_paths, restore_file, snapshot_file, validate_generated_artifact_path, validate_schema
    from scope_context import DEFAULT_DEPENDENCY_ROOTS, compilation_digests, resolve_build_root, resolve_scope_root, scope_inventory, source_digest
except ImportError:  # pragma: no cover
    from scripts.audit_artifacts import atomic_write_text, bind_routing_snapshot, check_body_hash, registry_sha256, require_distinct_paths, restore_file, snapshot_file, validate_generated_artifact_path, validate_schema
    from scripts.scope_context import DEFAULT_DEPENDENCY_ROOTS, compilation_digests, resolve_build_root, resolve_scope_root, scope_inventory, source_digest

try:
    from runtime_log import configure, error, info, stage, success, verbose as verbose_log
except ImportError:  # pragma: no cover
    from scripts.runtime_log import configure, error, info, stage, success, verbose as verbose_log


ROOT = Path(__file__).resolve().parents[1]
FEATURE_STATES = {"PRESENT", "ABSENT_CONFIRMED", "UNKNOWN"}
PREDICATE_KEYS = ("all_of", "any_of", "none_of")
SELECTOR_VERSION = str(ROUTING_MANIFEST_VERSION)
EVIDENCE_KINDS = {"slither-ast", "slither-ir", "compiler-ast", "source", "deployment", "manual"}
HARD_FORKS = ("frontier", "homestead", "byzantium", "constantinople", "istanbul", "berlin", "london", "paris", "shanghai", "cancun", "prague")
CHAIN_FAMILY_BY_ID = {
    1: "ethereum", 10: "op-stack", 56: "bnb-smart-chain", 137: "polygon-pos",
    324: "zksync-era", 8453: "op-stack", 42161: "arbitrum", 81457: "blast",
}
EXECUTION_ENVIRONMENTS_BY_CHAIN_ID = {
    **{chain_id: {"ethereum-evm"} for chain_id in CHAIN_FAMILY_BY_ID if chain_id != 324},
    324: {"eravm-native", "zksync-evm-interpreter"},
}


class SelectionInputError(ValueError):
    """Raised when routing input cannot safely support selection."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SelectionInputError(f"cannot read JSON {path}: {error}") from error
    if not isinstance(value, dict):
        raise SelectionInputError(f"JSON root must be an object: {path}")
    return value


def find_git_root(path: Path) -> Path | None:
    start = path.resolve()
    if start.is_file():
        start = start.parent
    result = subprocess.run(
        ["git", "-C", str(start), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        return None
    value = result.stdout.strip()
    return Path(value).resolve() if value else None


def git_value(root: Path, *args: str) -> str | None:
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else None


def build_info(root: Path) -> dict[str, Any]:
    path = root / "build-info.json"
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def knowledge_state(root: Path) -> tuple[str | None, bool | None]:
    commit = git_value(root, "rev-parse", "HEAD")
    status = git_value(root, "status", "--short")
    if commit is not None and status is not None:
        return commit, bool(status)
    info = build_info(root)
    fallback = info.get("source_commit")
    return (fallback if isinstance(fallback, str) and fallback else None), None


def audit_context(
    root: Path,
    registry: dict[str, Any],
    recon_context: dict[str, Any],
    *,
    target_root: Path,
    target_commit: str | None = None,
    chain_id: int | None = None,
    chain_family: str | None = None,
    execution_environment: str | None = None,
    fork_block: int | None = None,
    compiler_version: str | None = None,
    evm_fork: str | None = None,
    protocol_version: str | None = None,
    audit_timestamp: str | None = None,
    trusted_facts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    knowledge_commit, knowledge_dirty = knowledge_state(root)
    environment = validate_environment_context(
        recon_context, chain_id=chain_id, chain_family=chain_family,
        execution_environment=execution_environment, compiler_version=compiler_version,
        evm_fork=evm_fork, protocol_version=protocol_version, trusted_facts=trusted_facts,
    )
    return {
        "selector_version": SELECTOR_VERSION,
        "registry_sha256": registry_sha256(registry),
        "knowledge_commit": knowledge_commit,
        "knowledge_dirty": knowledge_dirty,
        "target_repo_commit": target_commit or git_value(find_git_root(target_root) or target_root.resolve(), "rev-parse", "HEAD"),
        "source_digest": recon_context["source_digest"],
        "audit_source_digest": recon_context["audit_source_digest"],
        "dependency_digest": recon_context["dependency_digest"],
        "build_config_digest": recon_context["build_config_digest"],
        "compilation_input_digest": recon_context["compilation_input_digest"],
        **environment,
        "fork_block": fork_block,
        "fork_block_semantics": "reproducibility metadata only; does not derive evm_fork",
        "audit_timestamp": audit_timestamp or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def validate_environment_context(
    recon_context: dict[str, Any], *, chain_id: int | None = None,
    chain_family: str | None = None, execution_environment: str | None = None,
    compiler_version: str | None = None, evm_fork: str | None = None,
    protocol_version: str | None = None,
    trusted_facts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    recon_compiler = recon_context.get("solc_version")
    recon_compilers = recon_context.get("compiler_versions") or ([recon_compiler] if recon_compiler else [])
    if compiler_version and recon_compilers:
        cli_version = _version(compiler_version)
        detected_versions = {_version(value) for value in recon_compilers if isinstance(value, str)}
        if cli_version is None or None in detected_versions or cli_version not in detected_versions:
            raise SelectionInputError(
                f"compiler_version {compiler_version} conflicts with Recon compiler_versions {recon_compilers}"
            )
    supplied = trusted_facts or {}
    allowed_keys = {"chain_id", "chain_family", "execution_environment", "compiler_version", "evm_fork", "protocol_version"}
    if set(supplied) - allowed_keys:
        raise SelectionInputError(f"unknown environment facts: {sorted(set(supplied) - allowed_keys)}")

    declared = {
        "chain_id": chain_id, "chain_family": chain_family,
        "execution_environment": execution_environment,
        "compiler_version": compiler_version, "evm_fork": evm_fork,
        "protocol_version": protocol_version,
    }

    def fact(key: str, detected: Any = None) -> dict[str, Any]:
        provided = supplied.get(key)
        if provided is not None:
            if not isinstance(provided, dict) or provided.get("trust") not in {"UNKNOWN", "DECLARED", "OBSERVED", "CONFIRMED"}:
                raise SelectionInputError(f"environment fact {key} has invalid trust")
            if declared[key] is not None and provided.get("value") != declared[key]:
                raise SelectionInputError(f"environment fact {key} conflicts with CLI value")
            if detected is not None and provided.get("value") != detected:
                raise SelectionInputError(f"environment fact {key} conflicts with Recon evidence")
            value = provided.get("value")
            if key == "chain_id" and value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 0):
                raise SelectionInputError("environment fact chain_id must be a non-negative integer or null")
            if key != "chain_id" and value is not None and not isinstance(value, str):
                raise SelectionInputError(f"environment fact {key} must be a string or null")
            if provided["trust"] != "UNKNOWN" and (not provided.get("source") or not provided.get("evidence")):
                raise SelectionInputError(f"environment fact {key} requires source and evidence")
            return dict(provided)
        if detected is not None:
            return {"value": detected, "trust": "CONFIRMED", "source": "recon-compilation", "evidence": ["successful complete compilation"]}
        value = declared[key]
        return {
            "value": value,
            "trust": "DECLARED" if value is not None else "UNKNOWN",
            "source": "cli" if value is not None else "none",
            "evidence": ["explicit CLI declaration"] if value is not None else [],
        }

    compiler_fact = recon_compiler if len(recon_compilers) == 1 else None
    facts = {key: fact(key, compiler_fact if key == "compiler_version" else None) for key in sorted(allowed_keys)}
    resolved_chain_id = facts["chain_id"]["value"]
    mapped_family = CHAIN_FAMILY_BY_ID.get(resolved_chain_id)
    family_fact = facts["chain_family"]
    if mapped_family:
        if family_fact["value"] not in {None, mapped_family}:
            raise SelectionInputError(f"chain_id {resolved_chain_id} maps to {mapped_family}, not {family_fact['value']}")
        if family_fact["value"] is None:
            family_fact = {
                "value": mapped_family,
                "trust": facts["chain_id"]["trust"],
                "source": "chain-id mapping",
                "evidence": list(facts["chain_id"]["evidence"]),
            }
        facts["chain_family"] = family_fact
    resolved_environment = facts["execution_environment"]["value"]
    if resolved_chain_id in EXECUTION_ENVIRONMENTS_BY_CHAIN_ID and resolved_environment:
        allowed = EXECUTION_ENVIRONMENTS_BY_CHAIN_ID[resolved_chain_id]
        if resolved_environment not in allowed:
            raise SelectionInputError(f"chain_id {resolved_chain_id} is incompatible with execution_environment {resolved_environment}")

    return {
        **{key: facts[key]["value"] for key in sorted(allowed_keys)},
        "environment_facts": facts,
    }


def vocabulary(feature_data: dict[str, Any]) -> tuple[set[str], dict[str, dict[str, Any]]]:
    if feature_data.get("schema_version") != FEATURE_REGISTRY_VERSION:
        raise SelectionInputError(f"feature registry schema_version must be {FEATURE_REGISTRY_VERSION}")
    values = feature_data.get("features")
    if not isinstance(values, dict) or not values:
        raise SelectionInputError("feature registry must contain a non-empty object named 'features'")
    policies: dict[str, dict[str, Any]] = {}
    for feature, entry in values.items():
        if not isinstance(entry, dict):
            raise SelectionInputError(f"feature {feature!r} configuration must be an object")
        if entry.get("absence_policy") not in {"machine-only", "machine-or-deployment", "manual-allowed", "never-confirm-absence"}:
            raise SelectionInputError(f"feature {feature!r} has invalid absence_policy")
        allowed = entry.get("allowed_absence_evidence")
        if not isinstance(allowed, list) or any(kind not in EVIDENCE_KINDS for kind in allowed):
            raise SelectionInputError(f"feature {feature!r} has invalid allowed_absence_evidence")
        policies[feature] = entry
    return set(values), policies


def _string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise SelectionInputError(f"{label} must be a string list")
    if len(value) != len(set(value)):
        raise SelectionInputError(f"{label} must not contain duplicates")
    return value


def validate_recon_context(
    raw: Any,
    target_root: Path | None,
    exclusions: tuple[str, ...],
    *,
    build_root: Path | None = None,
    acquisition_root: Path | None = None,
    include_patterns: tuple[str, ...] = (),
    dependency_roots: tuple[str, ...] = tuple(sorted(DEFAULT_DEPENDENCY_ROOTS)),
    require_complete: bool = False,
    managed_output_root: Path | None = None,
) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise SelectionInputError("Feature Map v4 requires recon_context")
    required = {
        "target_root", "build_root", "files_analyzed", "excluded_paths", "exclusion_patterns", "include_patterns", "dependency_roots", "uncompiled_paths", "source_digest",
        "audit_source_digest", "dependency_digest", "build_config_digest", "compilation_input_digest",
        "compilation_complete", "recon_quality", "slither_version", "solc_version",
    }
    optional = {"compilation_files", "compiler_versions", "navigation_artifacts"}
    if set(raw) - required - optional or not required <= set(raw):
        raise SelectionInputError(f"recon_context fields must include {sorted(required)}")
    analyzed = set(_string_list(raw["files_analyzed"], "recon_context.files_analyzed"))
    _string_list(raw["excluded_paths"], "recon_context.excluded_paths")
    exclusion_patterns = _string_list(raw["exclusion_patterns"], "recon_context.exclusion_patterns")
    if exclusion_patterns != sorted(set(exclusions)):
        raise SelectionInputError("Recon exclusion_patterns do not match the current audit scope")
    include_values = _string_list(raw["include_patterns"], "recon_context.include_patterns")
    if include_values != sorted(set(include_patterns)):
        raise SelectionInputError("Recon include_patterns do not match the current audit scope")
    dependency_values = _string_list(raw["dependency_roots"], "recon_context.dependency_roots")
    if dependency_values != sorted(set(dependency_roots)):
        raise SelectionInputError("Recon dependency_roots do not match the current audit scope")
    uncompiled = _string_list(raw["uncompiled_paths"], "recon_context.uncompiled_paths")
    if not isinstance(raw["target_root"], str) or not raw["target_root"]:
        raise SelectionInputError("recon_context.target_root must be a path")
    if not isinstance(raw["build_root"], str) or not raw["build_root"]:
        raise SelectionInputError("recon_context.build_root must be a path")
    for key in ("source_digest", "audit_source_digest", "dependency_digest", "build_config_digest", "compilation_input_digest"):
        if not isinstance(raw[key], str) or not re.fullmatch(r"[0-9a-f]{64}", raw[key]):
            raise SelectionInputError(f"recon_context.{key} must be a SHA-256 digest")
    if raw["source_digest"] != raw["audit_source_digest"]:
        raise SelectionInputError("recon_context.source_digest must equal audit_source_digest")
    if not isinstance(raw["compilation_complete"], bool):
        raise SelectionInputError("recon_context.compilation_complete must be boolean")
    quality = raw["recon_quality"]
    if not isinstance(quality, dict) or set(quality) - {
        "compilation_complete", "absence_filtering_complete", "mode", "uncompiled_paths", "compilation_provenance"
    } or not {"compilation_complete", "absence_filtering_complete", "mode", "uncompiled_paths"} <= set(quality):
        raise SelectionInputError("recon_context.recon_quality has an invalid shape")
    provenance = quality.get("compilation_provenance", "CONSERVATIVE_BUILD_ROOT_FALLBACK")
    expected_mode = "COMPLETE" if raw["compilation_complete"] else "CONSERVATIVE_DEGRADED"
    if (
        quality["compilation_complete"] is not raw["compilation_complete"]
        or quality["absence_filtering_complete"] is not raw["compilation_complete"]
        or quality["mode"] != expected_mode
        or quality["uncompiled_paths"] != uncompiled
        or provenance not in {"EXACT_COMPILATION_CLOSURE", "CONSERVATIVE_BUILD_ROOT_FALLBACK"}
    ):
        raise SelectionInputError("recon_context.recon_quality does not match compilation coverage")
    if raw["compilation_complete"] and uncompiled:
        raise SelectionInputError("recon_context compilation coverage is inconsistent")
    if require_complete and (not raw["compilation_complete"] or uncompiled):
        raise SelectionInputError("complete compilation is required for strict FAST_FILTER")
    if not isinstance(raw["slither_version"], str) or not raw["slither_version"]:
        raise SelectionInputError("recon_context.slither_version is required")
    if raw["solc_version"] is not None and not isinstance(raw["solc_version"], str):
        raise SelectionInputError("recon_context.solc_version must be a string or null")
    compilation_values = None
    if "compilation_files" in raw:
        compilation_values = _string_list(raw["compilation_files"], "recon_context.compilation_files")
        if not compilation_values:
            raise SelectionInputError("recon_context.compilation_files must not be empty")
        if any(not value.endswith(".sol") for value in compilation_values):
            raise SelectionInputError("recon_context.compilation_files must contain Solidity paths")
    compiler_values = None
    if "compiler_versions" in raw:
        compiler_values = _string_list(raw["compiler_versions"], "recon_context.compiler_versions")
        if not compiler_values:
            raise SelectionInputError("recon_context.compiler_versions must not be empty")
        if len(compiler_values) == 1 and raw["solc_version"] != compiler_values[0]:
            raise SelectionInputError("recon_context.solc_version must identify the only compiler version")
        if len(compiler_values) > 1 and raw["solc_version"] is not None:
            raise SelectionInputError("recon_context.solc_version cannot collapse multiple compiler versions")
        if raw["solc_version"] is not None and raw["solc_version"] not in compiler_values:
            raise SelectionInputError("recon_context.solc_version is not in compiler_versions")
    navigation = raw.get("navigation_artifacts")
    if navigation is not None:
        binding = navigation.get("code_index") if isinstance(navigation, dict) else None
        if not isinstance(navigation, dict) or set(navigation) != {"code_index"}:
            raise SelectionInputError("recon_context.navigation_artifacts has an invalid shape")
        if binding is not None and (
            not isinstance(binding, dict)
            or set(binding) != {"schema_version", "sha256"}
            or binding.get("schema_version") != 2
            or not isinstance(binding.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", binding["sha256"])
        ):
            raise SelectionInputError("recon_context.navigation_artifacts.code_index has an invalid shape")
    if target_root is None:
        raise SelectionInputError("Feature Map v4 selection requires --target-root")
    resolved = resolve_scope_root(target_root)
    resolved_build_root = resolve_build_root(resolved, build_root, boundary=acquisition_root or resolved)
    excluded_roots = (managed_output_root,) if managed_output_root is not None else ()
    files, excluded = scope_inventory(resolved, exclusions, include_values, dependency_values, excluded_roots)
    scope_files = set(files)
    actual_digest = source_digest(resolved, files)
    if actual_digest != raw["source_digest"]:
        raise SelectionInputError("Recon source_digest does not match the current audit scope")
    actual_digests = compilation_digests(
        resolved,
        files,
        raw["solc_version"],
        build_root=resolved_build_root,
        dependency_roots=dependency_values,
        compilation_files=compilation_values,
        compiler_versions=compiler_values,
        boundary=acquisition_root or resolved,
        excluded_roots=excluded_roots,
    )
    for key, value in actual_digests.items():
        if raw[key] != value:
            raise SelectionInputError(f"Recon {key} does not match the current audit scope")
    if Path(raw["target_root"]).resolve() != resolved:
        raise SelectionInputError("Recon target_root does not match --target-root")
    if resolved_build_root != Path(raw["build_root"]).resolve():
        raise SelectionInputError("Recon build_root does not match the current compilation context")
    if raw["excluded_paths"] != excluded:
        raise SelectionInputError("Recon excluded_paths do not match the current audit scope")
    if not analyzed <= scope_files:
        raise SelectionInputError("Recon files_analyzed contains paths outside the current audit scope")
    expected_uncompiled = sorted(scope_files - analyzed)
    if expected_uncompiled != uncompiled:
        raise SelectionInputError("Recon uncompiled_paths does not equal scope_files minus files_analyzed")
    if raw["compilation_complete"] is not (not expected_uncompiled):
        raise SelectionInputError("Recon compilation_complete does not match compilation coverage")
    normalized = dict(raw)
    normalized["recon_quality"] = {**quality, "compilation_provenance": provenance}
    normalized["target_root"] = str(resolved)
    normalized["build_root"] = str(resolved_build_root)
    return normalized


def _evidence(value: Any, feature: str) -> list[dict[str, str]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise SelectionInputError(f"feature {feature!r} evidence must be a list")
    normalized: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, dict) or not set(item) <= {"kind", "location", "reason", "scope_origin"} or not {"kind", "location", "reason"} <= set(item):
            raise SelectionInputError(f"feature {feature!r} evidence entries need kind/location/reason")
        if item.get("kind") not in EVIDENCE_KINDS or any(not isinstance(item.get(key), str) or not item[key].strip() for key in ("location", "reason")):
            raise SelectionInputError(f"feature {feature!r} has invalid typed evidence")
        origin = item.get("scope_origin")
        if origin is not None and origin not in {"AUDIT_SCOPE", "DEPENDENCY", "FIRST_PARTY_DEPENDENCY", "EXTERNAL_DEPENDENCY", "UNKNOWN"}:
            raise SelectionInputError(f"feature {feature!r} has invalid scope_origin")
        normalized_item = {key: item[key].strip() for key in ("kind", "location", "reason")}
        if origin is not None:
            normalized_item["scope_origin"] = origin
        normalized.append(normalized_item)
    return normalized


def normalize_feature_map(
    raw: dict[str, Any],
    names: set[str],
    policies: dict[str, dict[str, Any]],
    target_root: Path | None,
    exclusions: tuple[str, ...] = (),
    *,
    build_root: Path | None = None,
    acquisition_root: Path | None = None,
    include_patterns: tuple[str, ...] = (),
    dependency_roots: tuple[str, ...] = tuple(sorted(DEFAULT_DEPENDENCY_ROOTS)),
    require_complete: bool = False,
    managed_output_root: Path | None = None,
) -> dict[str, dict[str, Any]]:
    if raw.get("schema_version") != FEATURE_MAP_VERSION:
        raise SelectionInputError(f"feature map schema_version must be {FEATURE_MAP_VERSION}")
    recon_context = validate_recon_context(
        raw.get("recon_context"),
        target_root,
        exclusions,
        build_root=build_root,
        acquisition_root=acquisition_root,
        include_patterns=include_patterns,
        dependency_roots=dependency_roots,
        require_complete=require_complete,
        managed_output_root=managed_output_root,
    )
    entries = raw.get("features")
    if not isinstance(entries, dict):
        raise SelectionInputError("feature map must contain an object named 'features'")
    unknown = sorted(set(entries) - names)
    if unknown:
        raise SelectionInputError(f"unknown features in feature map: {', '.join(unknown)}")

    normalized: dict[str, dict[str, Any]] = {}
    for feature, entry in entries.items():
        if not isinstance(entry, dict) or not set(entry) <= {"status", "evidence", "reason"}:
            raise SelectionInputError(f"feature {feature!r} must contain status/evidence and optional reason")
        status = entry.get("status")
        evidence = _evidence(entry.get("evidence"), feature)
        reason = entry.get("reason", "")
        if status not in FEATURE_STATES:
            raise SelectionInputError(f"feature {feature!r} status must be one of {sorted(FEATURE_STATES)}")
        if not isinstance(reason, str):
            raise SelectionInputError(f"feature {feature!r} reason must be a string")
        if status != "UNKNOWN" and not evidence:
            raise SelectionInputError(f"feature {feature!r} status {status} requires concrete evidence")
        if status == "ABSENT_CONFIRMED":
            allowed = set(policies[feature]["allowed_absence_evidence"])
            kinds = {item["kind"] for item in evidence}
            if policies[feature]["absence_policy"] == "never-confirm-absence" or not kinds or not kinds <= allowed:
                status = "UNKNOWN"
                reason = f"absence rejected by policy {policies[feature]['absence_policy']}"
        if status == "ABSENT_CONFIRMED" and not recon_context["recon_quality"]["absence_filtering_complete"]:
            status = "UNKNOWN"
            reason = "absence downgraded because Recon compilation coverage is incomplete"
        normalized[feature] = {"status": status, "evidence": evidence}
        if reason.strip():
            normalized[feature]["reason"] = reason.strip()
    return {
        feature: normalized.get(feature, {"status": "UNKNOWN", "evidence": []})
        for feature in sorted(names)
    }


def status_for(
    feature: str,
    feature_map: dict[str, dict[str, Any]],
    *,
    dependency_presence_sufficient: bool = False,
    require_scope_origin: bool = False,
) -> str:
    entry = feature_map.get(feature, {"status": "UNKNOWN"})
    status = entry.get("status", "UNKNOWN")
    if status != "PRESENT":
        return status
    if not require_scope_origin:
        return status
    origins = {item.get("scope_origin") for item in entry.get("evidence", []) if isinstance(item, dict)}
    if not origins or "UNKNOWN" in origins or None in origins:
        return "UNKNOWN"
    if "AUDIT_SCOPE" in origins or dependency_presence_sufficient:
        return "PRESENT"
    return "UNKNOWN"


def evaluate_group(
    features: list[str],
    mode: str,
    feature_map: dict[str, dict[str, Any]],
    *,
    dependency_presence_sufficient: bool = False,
    require_scope_origin: bool = False,
) -> str:
    if not features:
        return "TRUE"
    states = [status_for(
        feature,
        feature_map,
        dependency_presence_sufficient=dependency_presence_sufficient,
        require_scope_origin=require_scope_origin,
    ) for feature in features]
    if mode == "all_of":
        return "FALSE" if "ABSENT_CONFIRMED" in states else "TRUE" if all(state == "PRESENT" for state in states) else "UNKNOWN"
    if mode == "any_of":
        return "TRUE" if "PRESENT" in states else "FALSE" if all(state == "ABSENT_CONFIRMED" for state in states) else "UNKNOWN"
    if mode == "none_of":
        return "FALSE" if "PRESENT" in states else "TRUE" if all(state == "ABSENT_CONFIRMED" for state in states) else "UNKNOWN"
    raise AssertionError(f"unsupported predicate group: {mode}")


def check_predicate(check: dict[str, Any], names: set[str]) -> dict[str, list[str]]:
    predicate = check.get("predicate")
    if not isinstance(predicate, dict) or set(predicate) != set(PREDICATE_KEYS):
        raise SelectionInputError(f"{check.get('canonical_id')}: predicate must contain all_of/any_of/none_of")
    normalized: dict[str, list[str]] = {}
    for key in PREDICATE_KEYS:
        values = predicate[key]
        if not isinstance(values, list) or any(not isinstance(value, str) or not value.strip() for value in values):
            raise SelectionInputError(f"{check.get('canonical_id')}: predicate.{key} must be a string list")
        normalized[key] = sorted(set(values))
        unknown = sorted(set(normalized[key]) - names)
        if unknown:
            raise SelectionInputError(f"{check.get('canonical_id')}: unknown predicate features: {', '.join(unknown)}")
    return normalized


def evaluate_check(
    check: dict[str, Any],
    feature_map: dict[str, dict[str, Any]],
    names: set[str],
    *,
    dependency_presence_sufficient: bool = False,
    require_scope_origin: bool = True,
) -> dict[str, Any]:
    if check.get("always_screen") is True:
        return {
            "result": "TRUE", "predicate_result": "TRUE", "predicate_source": check.get("predicate_source", "curated"),
            "predicate": {key: [] for key in PREDICATE_KEYS}, "matched_features": [], "unknown_features": [], "basis": ["always_screen=true"],
        }
    predicate = check_predicate(check, names)
    groups = {
        key: evaluate_group(
            predicate[key],
            key,
            feature_map,
            dependency_presence_sufficient=dependency_presence_sufficient,
            require_scope_origin=require_scope_origin,
        )
        for key in PREDICATE_KEYS
    }
    predicate_result = "FALSE" if "FALSE" in groups.values() else "TRUE" if all(value == "TRUE" for value in groups.values()) else "UNKNOWN"
    predicate_source = check.get("predicate_source", "inferred")
    result = "UNKNOWN" if predicate_result == "FALSE" and predicate_source != "curated" else predicate_result
    referenced = {feature for values in predicate.values() for feature in values}

    def state(feature: str) -> str:
        return status_for(
            feature,
            feature_map,
            dependency_presence_sufficient=dependency_presence_sufficient,
            require_scope_origin=require_scope_origin,
        )

    matched = sorted(feature for feature in referenced if state(feature) == "PRESENT")
    unknown = sorted(feature for feature in referenced if state(feature) == "UNKNOWN")
    basis = [f"{key}={value}" for key, value in groups.items() if predicate[key]]
    if matched:
        basis.append("present=" + ",".join(matched))
    if unknown:
        basis.append("unknown=" + ",".join(unknown))
    if predicate_result == "FALSE":
        basis.append("failed=" + ",".join(key for key, value in groups.items() if value == "FALSE"))
    if predicate_result == "FALSE" and result == "UNKNOWN":
        basis.append("inferred-false-downgraded=UNKNOWN")
    return {
        "result": result, "predicate_result": predicate_result, "predicate_source": predicate_source,
        "predicate": predicate, "matched_features": matched, "unknown_features": unknown, "basis": basis or ["empty predicate"],
    }


def _version(value: str) -> tuple[int, int, int] | None:
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", value)
    return tuple(map(int, match.groups())) if match else None


def compiler_matches(constraint: str, actual: str) -> bool | None:
    version = _version(actual)
    if version is None:
        return None
    for clause in constraint.split(","):
        match = re.fullmatch(r"\s*(>=|<=|==|>|<)\s*(\d+\.\d+\.\d+)\s*", clause)
        if not match:
            raise SelectionInputError(f"invalid compiler applicability constraint: {constraint}")
        expected = _version(match.group(2))
        operator = match.group(1)
        if expected is None or not {">=": version >= expected, "<=": version <= expected, "==": version == expected, ">": version > expected, "<": version < expected}[operator]:
            return False
    return True


def evaluate_environment(check: dict[str, Any], environment: dict[str, Any]) -> tuple[str, list[str]]:
    applicability = check.get("applicability")
    if not applicability:
        return "TRUE", ["no environment constraints"]
    results: list[str] = []
    basis: list[str] = []
    dimensions = (
        ("chain_ids", "chain_id"),
        ("chain_families", "chain_family"),
        ("execution_environments", "execution_environment"),
        ("protocol_versions", "protocol_version"),
    )
    for allowed_key, actual_key in dimensions:
        allowed = applicability.get(allowed_key, []) or []
        if not allowed:
            continue
        fact = environment.get("environment_facts", {}).get(actual_key, {})
        actual = fact.get("value") if fact.get("trust") == "CONFIRMED" else None
        result = "UNKNOWN" if actual is None else "TRUE" if actual in allowed else "FALSE"
        results.append(result)
        basis.append(f"{actual_key}={result}({fact.get('trust', 'UNKNOWN')})")
    constraint = applicability.get("compiler")
    if constraint:
        fact = environment.get("environment_facts", {}).get("compiler_version", {})
        actual = fact.get("value") if fact.get("trust") == "CONFIRMED" else None
        match = None if actual is None else compiler_matches(constraint, actual)
        result = "UNKNOWN" if match is None else "TRUE" if match else "FALSE"
        results.append(result)
        basis.append(f"compiler={result}")
    fork_fact = environment.get("environment_facts", {}).get("evm_fork", {})
    actual_fork = fork_fact.get("value") if fork_fact.get("trust") == "CONFIRMED" else None
    for bound_key, comparison in (("evm_fork_from", "from"), ("evm_fork_until", "until")):
        bound = applicability.get(bound_key)
        if not bound:
            continue
        if bound not in HARD_FORKS:
            raise SelectionInputError(f"{check.get('canonical_id')}: unknown EVM fork {bound!r}")
        if actual_fork is None:
            result = "UNKNOWN"
        elif actual_fork not in HARD_FORKS:
            raise SelectionInputError(f"unknown target EVM fork {actual_fork!r}")
        else:
            ok = HARD_FORKS.index(actual_fork) >= HARD_FORKS.index(bound) if comparison == "from" else HARD_FORKS.index(actual_fork) <= HARD_FORKS.index(bound)
            result = "TRUE" if ok else "FALSE"
        results.append(result)
        basis.append(f"{bound_key}={result}")
    return ("FALSE" if "FALSE" in results else "TRUE" if all(result == "TRUE" for result in results) else "UNKNOWN"), basis


def evaluate_domains(
    domain_configs: dict[str, dict[str, Any]],
    feature_map: dict[str, dict[str, Any]],
    explicit_domains: list[str] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    selected: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []
    filtered: list[dict[str, Any]] = []
    considered = explicit_domains or sorted(domain_configs)
    for domain in considered:
        config = domain_configs[domain]
        if explicit_domains:
            result, basis = "TRUE", ["explicit domain scope"]
        elif config.get("always_screen"):
            result, basis = "TRUE", ["always_screen=true"]
        else:
            result = evaluate_group(
                config["surface_features"],
                "any_of",
                feature_map,
                dependency_presence_sufficient=config.get("dependency_presence_sufficient", False),
                require_scope_origin=True,
            )
            basis = [f"surface_features.any_of={result}"]
        state = "SELECTED" if result == "TRUE" else "FILTERED" if result == "FALSE" else "DEFERRED"
        entry = {
            "domain": domain, "state": state, "evaluation": result,
            "surface_features": config["surface_features"], "basis": basis,
            "trusted_absence_policy": config.get("trusted_absence_policy"),
        }
        {"SELECTED": selected, "DEFERRED": deferred, "FILTERED": filtered}[state].append(entry)
    return selected, deferred, filtered


def select(
    registry: dict[str, Any],
    feature_map: dict[str, dict[str, Any]],
    names: set[str],
    scope_domains: list[str] | None,
    context: dict[str, Any] | None = None,
    domain_configs: dict[str, dict[str, Any]] | None = None,
    environment: dict[str, Any] | None = None,
    recon_context: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    environment = environment or {}
    if domain_configs is None:
        selected_domains = [{"domain": domain, "evaluation": "TRUE", "surface_features": [], "basis": ["explicit domain scope"]} for domain in (scope_domains or [])]
        if not selected_domains:
            selected_domains = [{"domain": domain, "evaluation": "TRUE", "surface_features": [], "basis": ["implicit scope"]} for domain in sorted({d for c in registry.get("checks", []) for d in c.get("domains", [])})]
        deferred_domains: list[dict[str, Any]] = []
        filtered_domains: list[dict[str, Any]] = []
    else:
        selected_domains, deferred_domains, filtered_domains = evaluate_domains(domain_configs, feature_map, scope_domains)
    selected_domain_ids = {entry["domain"] for entry in selected_domains}
    deferred_domain_ids = {entry["domain"] for entry in deferred_domains}
    filtered_domain_ids = {entry["domain"] for entry in filtered_domains}
    considered_domain_ids = selected_domain_ids | deferred_domain_ids | filtered_domain_ids

    selected: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []
    filtered: list[dict[str, Any]] = []
    selected_checks: list[dict[str, Any]] = []
    for check in registry.get("checks", []):
        domains = check.get("domains", [])
        scoped_domains = sorted(set(domains) & considered_domain_ids)
        if not scoped_domains:
            continue
        active_domains = sorted(set(domains) & selected_domain_ids)
        deferred_for_check = sorted(set(domains) & deferred_domain_ids)
        filtered_for_check = sorted(set(domains) & filtered_domain_ids)
        owner_domain = check.get("primary_domain")
        if not active_domains:
            bucket_domains = deferred_for_check or filtered_for_check
            if owner_domain not in bucket_domains:
                owner_domain = bucket_domains[0]
            route_entry = {
                "canonical_id": check["canonical_id"], "title": check.get("title", ""), "domains": domains,
                "check_body_hash": check_body_hash(check),
                "owner_domain": owner_domain, "freshness": check.get("freshness"), "verified_at": check.get("verified_at"),
                "route_status": "DEFERRED_DOMAIN" if deferred_for_check else "FILTERED_DOMAIN",
                "environment_evaluation": "NOT_EVALUATED", "environment_basis": [],
                "predicate": check.get("predicate"), "predicate_source": check.get("predicate_source"),
                "predicate_evaluation": "NOT_EVALUATED", "feature_evaluation": "NOT_EVALUATED",
                "matched_features": [], "unknown_features": [],
                "basis": [f"domain={bucket_domains[0]}:{'DEFERRED' if deferred_for_check else 'FILTERED'}"],
            }
            (deferred if deferred_for_check else filtered).append(route_entry)
            continue
        environment_result, environment_basis = evaluate_environment(check, environment)
        owner_config = (domain_configs or {}).get(check.get("primary_domain") or "", {})
        feature = evaluate_check(
            check,
            feature_map,
            names,
            dependency_presence_sufficient=owner_config.get("dependency_presence_sufficient", False),
            require_scope_origin=True,
        )
        if owner_domain not in active_domains:
            owner_domain = active_domains[0]
        if environment_result == "FALSE":
            route_status = "FILTERED_ENVIRONMENT"
        elif feature["result"] == "FALSE":
            route_status = "FILTERED_FEATURE"
        else:
            route_status = "SELECTED"
        route_entry = {
            "canonical_id": check["canonical_id"], "title": check.get("title", ""), "domains": domains,
            "check_body_hash": check_body_hash(check),
            "owner_domain": owner_domain, "freshness": check.get("freshness"), "verified_at": check.get("verified_at"),
            "route_status": route_status, "environment_evaluation": environment_result, "environment_basis": environment_basis,
            "predicate": feature["predicate"], "predicate_source": feature["predicate_source"],
            "predicate_evaluation": feature["predicate_result"], "feature_evaluation": feature["result"],
            "matched_features": feature["matched_features"], "unknown_features": feature["unknown_features"],
            "basis": [*environment_basis, *feature["basis"]],
        }
        if route_status == "SELECTED":
            selected.append(route_entry)
            selected_checks.append(check)
        else:
            filtered.append(route_entry)

    eligible_domains = selected_domains + deferred_domains
    required_context_requirements = {
        entry["domain"]: {
            requirement["key"]: {
                "required": requirement["required"],
                "description": requirement["description"],
            }
            for requirement in (domain_configs or {}).get(entry["domain"], {}).get("required_context", [])
        }
        for entry in eligible_domains
    }
    manifest = {
        "artifact_type": "routing-manifest",
        "immutable": True,
        "schema_version": ROUTING_MANIFEST_VERSION,
        "stage": "ENVIRONMENT_DOMAIN_CHECK_ROUTING",
        "audit_context": context or {
            "selector_version": SELECTOR_VERSION, "registry_sha256": registry_sha256(registry),
            "knowledge_commit": None, "knowledge_dirty": None, "target_repo_commit": None,
            "source_digest": (recon_context or {}).get("source_digest"),
            "audit_source_digest": (recon_context or {}).get("audit_source_digest"),
            "dependency_digest": (recon_context or {}).get("dependency_digest"),
            "build_config_digest": (recon_context or {}).get("build_config_digest"),
            "compilation_input_digest": (recon_context or {}).get("compilation_input_digest"),
            "chain_id": None, "chain_family": None,
            "execution_environment": None, "fork_block": None, "fork_block_semantics": "reproducibility metadata only; does not derive evm_fork",
            "compiler_version": None, "evm_fork": None, "protocol_version": None, "environment_facts": {},
            "audit_timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        },
        "scope": {"domains": scope_domains, "candidate_count": len(selected) + len(deferred) + len(filtered)},
        "feature_map": {"schema_version": FEATURE_MAP_VERSION, "recon_context": recon_context, "features": feature_map},
        "selected_domains": selected_domains, "deferred_domains": deferred_domains, "filtered_domains": filtered_domains,
        "required_context_requirements": required_context_requirements,
        "selected_count": len(selected), "deferred_count": len(deferred), "filtered_count": len(filtered),
        "selected": selected, "deferred": deferred, "filtered": filtered,
        "filtered_out": [entry["canonical_id"] for entry in filtered],
    }
    return bind_routing_snapshot(manifest), selected_checks


def load_domains(root: Path) -> dict[str, dict[str, Any]]:
    configs = {}
    for path in sorted((root / "domains").glob("*.json")):
        if path.name == "domain.schema.json":
            continue
        value = load_json(path)
        configs[value["id"]] = value
    return configs


def parse_domains(args: argparse.Namespace, known: set[str]) -> list[str] | None:
    if args.domain and args.domains:
        raise SelectionInputError("use only one of --domain and --domains")
    raw = args.domain or args.domains
    if not raw:
        return None
    values = sorted({value.strip() for value in raw.split(",") if value.strip()})
    unknown = sorted(set(values) - known)
    if not values or unknown:
        raise SelectionInputError(f"unknown or empty domain scope: {', '.join(unknown)}")
    return values


def write_text(path: Path, content: str) -> None:
    atomic_write_text(path, content)


def environment_artifact(context: dict[str, Any], snapshot_id: str) -> dict[str, Any]:
    return {
        "schema_version": ENVIRONMENT_CONTEXT_VERSION,
        "routing_snapshot_id": snapshot_id,
        "facts": context.get("environment_facts", {}),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--feature-map", type=Path, required=True, help="scope-bound Feature Map v4")
    parser.add_argument("--target-root", type=Path, required=True, help="current audit scope used to verify recon source_digest")
    parser.add_argument("--build-root", type=Path, help="compilation/build project root; must match Recon")
    parser.add_argument("--acquisition-root", type=Path, help="stop automatic build-root discovery above this source boundary")
    parser.add_argument(
        "--managed-output-root",
        type=Path,
        help="controller-owned audit output root; excluded from scope and digest recomputation when the run lives inside the audited project",
    )
    parser.add_argument("--exclude", action="append", default=[], help="additional audit-scope glob; must match Recon")
    parser.add_argument("--include", action="append", default=[], help="include a normally dependency-only audit path; must match Recon")
    parser.add_argument("--dependency-root", action="append", default=None, help="top-level dependency root; must match Recon")
    parser.add_argument("--domain", help="explicit single-domain scope")
    parser.add_argument("--domains", help="explicit comma-separated domain scope")
    parser.add_argument("--target-commit")
    parser.add_argument("--chain-id", type=int)
    parser.add_argument("--chain-family")
    parser.add_argument("--execution-environment", choices=("ethereum-evm", "eravm-native", "zksync-evm-interpreter"))
    parser.add_argument("--fork-block", type=int, help="reproducibility metadata only; does not derive --evm-fork")
    parser.add_argument("--compiler-version")
    parser.add_argument("--evm-fork", choices=HARD_FORKS)
    parser.add_argument("--protocol-version")
    parser.add_argument("--audit-timestamp")
    parser.add_argument("--manifest-out", type=Path)
    parser.add_argument("--context-out", type=Path)
    parser.add_argument("--environment-out", type=Path, help="write the typed environment facts artifact")
    parser.add_argument("--environment-context", type=Path, help="typed environment facts; CLI values remain DECLARED")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--quiet", action="store_true", help="suppress progress output")
    parser.add_argument("--verbose", action="store_true", help="include per-domain routing details")
    parser.add_argument("--require-complete-compilation", action="store_true", help="reject degraded Recon coverage")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    configure(quiet=args.quiet, verbose=args.verbose)

    try:
        stage("ROUTING", detail="Selecting checks and creating the immutable routing snapshot")
        registry = load_json(root / "data" / "canonical-checks.json")
        feature_data = load_json(root / "data" / "features.json")
        names, policies = vocabulary(feature_data)
        raw_feature_map = load_json(args.feature_map.resolve())
        exclusions = tuple(args.exclude)
        include_patterns = tuple(args.include)
        dependency_roots = tuple(args.dependency_root) if args.dependency_root is not None else tuple(sorted(DEFAULT_DEPENDENCY_ROOTS))
        resolved_build_root = resolve_build_root(
            args.target_root,
            args.build_root,
            boundary=args.acquisition_root or args.target_root,
        )
        require_distinct_paths(
            ("feature-map", args.feature_map),
            ("environment-context", args.environment_context),
            ("manifest", args.manifest_out),
            ("context", args.context_out),
            ("environment", args.environment_out),
        )
        for label, output in (
            ("manifest", args.manifest_out),
            ("context", args.context_out),
            ("environment", args.environment_out),
        ):
            if output is not None:
                validate_generated_artifact_path(
                    output,
                    audit_root=resolve_scope_root(args.target_root),
                    build_root=resolved_build_root,
                    label=label,
                    managed_output_root=args.managed_output_root,
                )
        feature_map = normalize_feature_map(
            raw_feature_map,
            names,
            policies,
            args.target_root,
            exclusions,
            build_root=resolved_build_root,
            acquisition_root=args.acquisition_root,
            include_patterns=include_patterns,
            dependency_roots=dependency_roots,
            require_complete=args.require_complete_compilation,
            managed_output_root=args.managed_output_root,
        )
        recon_context = validate_recon_context(
            raw_feature_map["recon_context"],
            args.target_root,
            exclusions,
            build_root=resolved_build_root,
            acquisition_root=args.acquisition_root,
            include_patterns=include_patterns,
            dependency_roots=dependency_roots,
            require_complete=args.require_complete_compilation,
            managed_output_root=args.managed_output_root,
        )
        domain_configs = load_domains(root)
        scope_domains = parse_domains(args, set(domain_configs))
        environment_context = load_json(args.environment_context.resolve()) if args.environment_context else {"schema_version": ENVIRONMENT_CONTEXT_VERSION, "facts": {}}
        if environment_context.get("schema_version", ENVIRONMENT_CONTEXT_VERSION) != ENVIRONMENT_CONTEXT_VERSION or not isinstance(environment_context.get("facts"), dict):
            raise SelectionInputError(f"environment context must have schema_version {ENVIRONMENT_CONTEXT_VERSION} and facts")
        validate_schema(root, "environment-context.schema.json", environment_context)
        context = audit_context(
            root, registry, recon_context, target_root=args.target_root, target_commit=args.target_commit,
            chain_id=args.chain_id, chain_family=args.chain_family, execution_environment=args.execution_environment,
            fork_block=args.fork_block, compiler_version=args.compiler_version, evm_fork=args.evm_fork,
            protocol_version=args.protocol_version, audit_timestamp=args.audit_timestamp,
            trusted_facts=environment_context["facts"],
        )
        environment = {key: context[key] for key in ("chain_id", "chain_family", "execution_environment", "compiler_version", "evm_fork", "protocol_version")}
        environment["environment_facts"] = context["environment_facts"]
        manifest, _ = select(registry, feature_map, names, scope_domains, context, domain_configs, environment, recon_context)

        outputs = {
            args.manifest_out: json.dumps(manifest, ensure_ascii=False, indent=2) + "\n" if args.manifest_out else None,
            args.context_out: json.dumps({**context, "routing_snapshot_id": manifest["routing_snapshot_id"]}, ensure_ascii=False, indent=2) + "\n" if args.context_out else None,
            args.environment_out: json.dumps(environment_artifact(context, manifest["routing_snapshot_id"]), ensure_ascii=False, indent=2) + "\n" if args.environment_out else None,
        }
        outputs = {path: content for path, content in outputs.items() if path is not None and content is not None}
        snapshots = {path: snapshot_file(path) for path in outputs}
        try:
            for path, content in outputs.items():
                write_text(path, content)
        except Exception:
            for path, snapshot in snapshots.items():
                restore_file(path, snapshot)
            raise
        if args.format == "json":
            print(json.dumps(manifest, ensure_ascii=False, indent=2))
        else:
            print(f"stage={manifest['stage']} snapshot={manifest['routing_snapshot_id']} selected_domains={len(manifest['selected_domains'])} deferred_domains={len(manifest['deferred_domains'])} selected={manifest['selected_count']} deferred={manifest['deferred_count']} filtered={manifest['filtered_count']}")
            for entry in manifest["selected"]:
                print(f"{entry['canonical_id']}\t{','.join(entry['matched_features']) or 'UNKNOWN/always_screen'}\t{entry['title']}")
        info(f"Selected Domains: {len(manifest['selected_domains'])}")
        info(f"Deferred Domains: {len(manifest['deferred_domains'])}")
        info(f"Filtered Domains: {len(manifest['filtered_domains'])}")
        info(f"Selected checks: {manifest['selected_count']}")
        info(f"Deferred checks: {manifest['deferred_count']}")
        info(f"Filtered checks: {manifest['filtered_count']}")
        for bucket in ("selected_domains", "deferred_domains", "filtered_domains"):
            for domain in manifest[bucket]:
                verbose_log(f"[DOMAIN] {domain['domain']} {domain['state']}")
        success(f"{progress_metadata('ROUTING')['label']} snapshot created: {manifest['routing_snapshot_id'][:12]}")
        return 0
    except (OSError, KeyError, SelectionInputError, ValueError) as exc:
        error(exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
