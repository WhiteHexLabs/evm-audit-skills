"""Validation and identity helpers for multi-target Solidity compilation."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

COMPILATION_PLAN_VERSION = 1
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


class CompilationPlanError(ValueError):
    """A compilation plan cannot be used safely."""


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _relative_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CompilationPlanError(f"{label} must be a non-empty relative path")
    path = Path(value.strip())
    if path.is_absolute() or ".." in path.parts:
        raise CompilationPlanError(f"{label} must stay relative to its declared root: {value!r}")
    return path.as_posix()


def _inside(path: Path, root: Path, label: str) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as error:
        raise CompilationPlanError(f"{label} escapes its declared root: {resolved}") from error
    return resolved


def _scope_files(audit_root: Path, scope_root: str, managed_output_root: Path | None) -> list[str]:
    relative = _relative_path(scope_root, "unit.scope_roots entry")
    path = _inside(audit_root / relative, audit_root, "unit scope root")
    if managed_output_root is not None:
        managed = managed_output_root.resolve()
        try:
            path.relative_to(managed)
        except ValueError:
            pass
        else:
            raise CompilationPlanError("unit scope root is inside the managed audit output")
    if path.is_file():
        if path.suffix != ".sol":
            raise CompilationPlanError(f"unit scope root is not Solidity: {relative}")
        return [path.relative_to(audit_root.resolve()).as_posix()]
    if not path.is_dir():
        raise CompilationPlanError(f"unit scope root does not exist: {relative}")
    files = sorted(
        item.relative_to(audit_root.resolve()).as_posix()
        for item in path.rglob("*.sol")
        if item.is_file()
    )
    if not files:
        raise CompilationPlanError(f"unit scope root contains no Solidity files: {relative}")
    return files


def normalize_compilation_plan(
    value: Any,
    *,
    audit_root: Path,
    build_root: Path,
    managed_output_root: Path | None = None,
) -> dict[str, Any]:
    """Validate and canonicalize a plan without executing a compiler."""
    if not isinstance(value, dict) or value.get("schema_version") != COMPILATION_PLAN_VERSION:
        raise CompilationPlanError(
            f"compilation plan schema_version must be {COMPILATION_PLAN_VERSION}"
        )
    units = value.get("units")
    if not isinstance(units, list) or not units:
        raise CompilationPlanError("compilation plan units must be a non-empty array")
    audit_root = audit_root.resolve()
    build_root = build_root.resolve()
    if not audit_root.is_dir() or not build_root.is_dir():
        raise CompilationPlanError("compilation plan requires directory audit_root and build_root")
    try:
        audit_root.relative_to(build_root)
    except ValueError as error:
        raise CompilationPlanError("audit_root must be inside build_root for a compilation plan") from error

    normalized: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_semantics: set[str] = set()
    for index, raw in enumerate(units):
        label = f"units[{index}]"
        if not isinstance(raw, dict):
            raise CompilationPlanError(f"{label} must be an object")
        allowed = {"id", "target", "scope_roots", "foundry_profile", "expected_compiler_versions"}
        unknown = sorted(set(raw) - allowed)
        if unknown:
            raise CompilationPlanError(f"{label} has unknown fields: {', '.join(unknown)}")
        unit_id = raw.get("id")
        if not isinstance(unit_id, str) or not _ID.fullmatch(unit_id):
            raise CompilationPlanError(f"{label}.id must match {_ID.pattern}")
        if unit_id in seen_ids:
            raise CompilationPlanError(f"duplicate compilation unit id: {unit_id}")
        seen_ids.add(unit_id)
        target_relative = _relative_path(raw.get("target"), f"{label}.target")
        target = _inside(build_root / target_relative, build_root, f"{label}.target")
        if not target.exists():
            raise CompilationPlanError(f"{label}.target does not exist: {target_relative}")
        if managed_output_root is not None:
            try:
                target.relative_to(managed_output_root.resolve())
            except ValueError:
                pass
            else:
                raise CompilationPlanError(f"{label}.target is inside the managed audit output")

        roots = raw.get("scope_roots")
        if not isinstance(roots, list) or not roots:
            raise CompilationPlanError(f"{label}.scope_roots must be a non-empty array")
        scope_roots = sorted({_relative_path(item, f"{label}.scope_roots entry") for item in roots})
        files = sorted({file for root in scope_roots for file in _scope_files(audit_root, root, managed_output_root)})
        profile = raw.get("foundry_profile")
        if profile is not None:
            if not isinstance(profile, str) or not profile.strip() or not _ID.fullmatch(profile.strip()):
                raise CompilationPlanError(f"{label}.foundry_profile must be a simple profile name")
            profile = profile.strip()
            if not (build_root / "foundry.toml").is_file():
                raise CompilationPlanError(f"{label}.foundry_profile requires foundry.toml")
        versions = raw.get("expected_compiler_versions", [])
        if not isinstance(versions, list) or any(not isinstance(item, str) or not item.strip() for item in versions):
            raise CompilationPlanError(f"{label}.expected_compiler_versions must be a string array")
        versions = sorted({item.strip() for item in versions})
        result: dict[str, Any] = {
            "id": unit_id,
            "target": target_relative,
            "scope_roots": scope_roots,
            "scope_files": files,
        }
        if profile is not None:
            result["foundry_profile"] = profile
        if versions:
            result["expected_compiler_versions"] = versions
        semantic = {key: result[key] for key in result if key != "scope_files"}
        semantic["scope_files"] = files
        semantic_digest = _canonical(semantic)
        if semantic_digest in seen_semantics:
            raise CompilationPlanError(f"duplicate compilation unit configuration: {unit_id}")
        seen_semantics.add(semantic_digest)
        normalized.append(result)

    normalized.sort(key=lambda item: item["id"])
    return {"schema_version": COMPILATION_PLAN_VERSION, "units": normalized}


def public_plan(plan: dict[str, Any]) -> dict[str, Any]:
    """Remove execution-only derived scope file lists before persistence."""
    return {
        "schema_version": plan["schema_version"],
        "units": [
            {
                key: unit[key]
                for key in ("id", "target", "scope_roots", "foundry_profile", "expected_compiler_versions")
                if key in unit
            }
            for unit in plan["units"]
        ],
    }


def compilation_plan_digest(plan: dict[str, Any]) -> str:
    return _digest(public_plan(plan))


def target_results_digest(results: Iterable[dict[str, Any]]) -> str:
    semantic = []
    for result in sorted(results, key=lambda item: item["id"]):
        semantic.append(
            {
                key: result.get(key)
                for key in (
                    "id", "target", "foundry_profile", "status", "scope_files", "analyzed_files", "missing_files",
                    "compiler_versions", "expected_compiler_versions", "configuration_verified",
                    "configuration_source", "configuration_digest", "compilation_provenance", "compilation_files",
                )
                if key in result
            }
        )
    return _digest(semantic)


def bind_compilation_digest(base_digest: str, plan_digest: str, results_digest: str) -> str:
    return _digest({
        "base_compilation_input_digest": base_digest,
        "compilation_plan_digest": plan_digest,
        "compilation_targets_digest": results_digest,
    })


def coverage_summary(scope_files: Iterable[str], units: Iterable[dict[str, Any]]) -> dict[str, Any]:
    scope = set(scope_files)
    assigned = {item for unit in units for item in unit.get("scope_files", [])}
    analyzed = {item for unit in units if unit.get("status") == "COMPLETE" for item in unit.get("analyzed_files", [])}
    missing = sorted(scope - analyzed)
    return {
        "unassigned_paths": sorted(scope - assigned),
        "analyzed_paths": sorted(analyzed),
        "uncompiled_paths": missing,
        "complete": not (scope - assigned) and not missing and all(unit.get("status") == "COMPLETE" for unit in units),
    }


def validate_target_results(
    plan: dict[str, Any],
    results: Any,
    scope_files: Iterable[str],
) -> None:
    """Check that recorded per-target coverage is bound to the plan."""
    if not isinstance(results, list):
        raise CompilationPlanError("compilation_targets must be an array")
    expected = {unit["id"]: unit for unit in plan["units"]}
    actual: dict[str, dict[str, Any]] = {}
    for result in results:
        if not isinstance(result, dict) or not isinstance(result.get("id"), str):
            raise CompilationPlanError("compilation target result must contain an id")
        if result["id"] in actual:
            raise CompilationPlanError(f"duplicate compilation target result: {result['id']}")
        actual[result["id"]] = result
    if set(actual) != set(expected):
        raise CompilationPlanError(
            f"compilation target results do not match plan: expected={sorted(expected)} actual={sorted(actual)}"
        )
    scope = set(scope_files)
    for unit_id, result in actual.items():
        unit = expected[unit_id]
        if result.get("target") != unit.get("target") or result.get("foundry_profile") != unit.get("foundry_profile"):
            raise CompilationPlanError(f"compilation target {unit_id} target configuration does not match plan")
        if result.get("scope_files") != unit.get("scope_files"):
            raise CompilationPlanError(f"compilation target {unit_id} scope_files do not match plan")
        if result.get("expected_compiler_versions", []) != unit.get("expected_compiler_versions", []):
            raise CompilationPlanError(f"compilation target {unit_id} expected compiler versions do not match plan")
        if result.get("configuration_source") is not None and not isinstance(result.get("configuration_source"), str):
            raise CompilationPlanError(f"compilation target {unit_id} has invalid configuration_source")
        status = result.get("status")
        if status not in {"COMPLETE", "INCOMPLETE", "FAILED"}:
            raise CompilationPlanError(f"compilation target {unit_id} has invalid status")
        for key in ("analyzed_files", "missing_files"):
            values = result.get(key)
            if not isinstance(values, list) or len(values) != len(set(values)) or any(item not in scope for item in values):
                raise CompilationPlanError(f"compilation target {unit_id} has invalid {key}")
            if values != sorted(values):
                raise CompilationPlanError(f"compilation target {unit_id} {key} must be sorted")
        if result.get("missing_files") != sorted(set(unit["scope_files"]) - set(result["analyzed_files"])):
            raise CompilationPlanError(f"compilation target {unit_id} missing_files are inconsistent")
        if status == "COMPLETE" and (
            result["missing_files"] or result.get("configuration_verified") is not True
        ):
            raise CompilationPlanError(f"compilation target {unit_id} is marked COMPLETE with incomplete evidence")
