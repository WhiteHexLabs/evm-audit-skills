#!/usr/bin/env python3
"""Build an evidence-backed feature map from Slither's Solidity AST/IR.

Only detectors implemented below may emit ``ABSENT_CONFIRMED`` after a complete
Slither compilation. Features outside that detector set remain ``UNKNOWN`` for
an auditor or LLM to supplement; source-text keyword absence is never evidence.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    from scope_context import (
        DEFAULT_DEPENDENCY_ROOTS,
        compilation_digests,
        conservative_input_snapshot,
        excluded_by_root,
        relative_excluded_roots,
        relative_scope_path,
        resolve_build_root,
        resolve_scope_root,
        scope_inventory,
        source_digest,
    )
except ImportError:  # pragma: no cover - supports importing from another cwd
    from scripts.scope_context import (
        DEFAULT_DEPENDENCY_ROOTS,
        compilation_digests,
        conservative_input_snapshot,
        excluded_by_root,
        relative_excluded_roots,
        relative_scope_path,
        resolve_build_root,
        resolve_scope_root,
        scope_inventory,
        source_digest,
    )

try:
    from audit_artifacts import atomic_write_text, require_distinct_paths, restore_file, sha256_bytes, snapshot_file, validate_generated_artifact_path, validate_schema
except ImportError:  # pragma: no cover - supports importing from another cwd
    from scripts.audit_artifacts import atomic_write_text, require_distinct_paths, restore_file, sha256_bytes, snapshot_file, validate_generated_artifact_path, validate_schema

try:
    from code_context import build_code_index
except ImportError:  # pragma: no cover - supports importing from another cwd
    from scripts.code_context import build_code_index

try:
    from runtime_log import configure, error, info, stage, success
except ImportError:  # pragma: no cover - supports importing from another cwd
    from scripts.runtime_log import configure, error, info, stage, success

from evm_audit_runtime.versions import FEATURE_MAP_VERSION
from evm_audit_runtime.repository_trust import inspect_repository


ROOT = Path(__file__).resolve().parents[1]

DETECTOR_IMPLEMENTATIONS = {
    "external_call_ir",
    "low_level_call_ir",
    "delegatecall_ir",
    "msg_value_read",
    "payable_function",
    "arbitrary_external_target_ir",
    "assembly_node",
    "create2_ir",
    "signed_conversion_ir",
    "time_read",
    "binary_ir",
    "loop_node",
}
SAFE_ABSENCE_IMPLEMENTATIONS = {"assembly_node", "msg_value_read", "payable_function"}


def load_detector_config(root: Path, feature_names: set[str] | None = None) -> dict[str, dict[str, Any]]:
    value = json.loads((root / "data" / "feature-detectors.json").read_text(encoding="utf-8"))
    validate_schema(root, "feature-detectors.schema.json", value)
    config = value["features"]
    if feature_names is not None:
        unknown = sorted(set(config) - feature_names)
        if unknown:
            raise ValueError(f"feature detector registry contains unknown features: {', '.join(unknown)}")
    for feature, detector in config.items():
        mode = detector["mode"]
        if mode == "heuristic" and "terms" not in detector:
            raise ValueError(f"heuristic detector has no terms: {feature}")
        if mode == "structural" and detector.get("implementation") not in DETECTOR_IMPLEMENTATIONS:
            raise ValueError(f"unknown structural detector implementation: {detector.get('implementation')}")
        if detector["absence_capable"] and detector.get("implementation") not in SAFE_ABSENCE_IMPLEMENTATIONS:
            raise ValueError(f"absence capability is not approved for detector: {feature}")
    return config


def ensure_slither_import() -> Any:
    try:
        from slither.slither import Slither

        return Slither
    except ImportError as original_error:
        if os.environ.get("EVM_RECON_REEXEC") == "1":
            raise RuntimeError("Slither Python package is unavailable") from original_error
        executable = shutil.which("slither")
        if not executable:
            raise RuntimeError("Slither is required; install slither-analyzer") from original_error
        first_line = Path(executable).read_text(encoding="utf-8").splitlines()[0]
        if not first_line.startswith("#!"):
            raise RuntimeError("cannot resolve the Python interpreter used by Slither") from original_error
        interpreter = shlex.split(first_line[2:].strip())
        if not interpreter:
            raise RuntimeError("cannot resolve the Python interpreter used by Slither") from original_error
        environment = dict(os.environ)
        environment["EVM_RECON_REEXEC"] = "1"
        os.execvpe(interpreter[0], [*interpreter, str(Path(__file__).resolve()), *sys.argv[1:]], environment)
        raise AssertionError("unreachable")


def scope_origin_for(
    value: Any,
    scope_root: Path | None,
    audit_files: set[str] | None,
) -> str:
    if scope_root is None:
        return "UNKNOWN"
    mapping = getattr(value, "source_mapping", None)
    filename = getattr(getattr(mapping, "filename", None), "absolute", None)
    if not filename:
        return "UNKNOWN"
    absolute = Path(str(filename)).resolve()
    if scope_root.is_file():
        return "AUDIT_SCOPE" if absolute == scope_root.resolve() else "DEPENDENCY"
    relative = relative_scope_path(scope_root, absolute)
    return "AUDIT_SCOPE" if relative is not None and (audit_files is None or relative in audit_files) else "DEPENDENCY"


def source_evidence(
    value: Any,
    detector: str,
    kind: str,
    scope_root: Path | None = None,
    audit_files: set[str] | None = None,
) -> tuple[str, str, str, str]:
    mapping = getattr(value, "source_mapping", None)
    filename = getattr(getattr(mapping, "filename", None), "relative", None)
    lines = getattr(mapping, "lines", None) or []
    location = f"{filename}:{lines[0]}" if filename and lines else str(filename or "unknown")
    return kind, location, f"Slither detector matched {detector}", scope_origin_for(value, scope_root, audit_files)


def add(
    evidence: dict[str, set[tuple[str, str, str, str]]],
    feature: str,
    value: Any,
    detector: str,
    kind: str = "slither-ast",
    scope_root: Path | None = None,
    audit_files: set[str] | None = None,
) -> None:
    evidence[feature].add(source_evidence(value, detector, kind, scope_root, audit_files))


def add_presence_heuristics(
    evidence: dict[str, set[tuple[str, str, str, str]]],
    value: Any,
    text: str,
    detectors: dict[str, dict[str, Any]],
    scope_root: Path | None = None,
    audit_files: set[str] | None = None,
) -> None:
    for feature, detector in detectors.items():
        if detector["mode"] == "heuristic" and any(term in text for term in detector["terms"]):
            add(evidence, feature, value, detector["label"], "source", scope_root, audit_files)


def add_structural(
    evidence: dict[str, set[tuple[str, str, str, str]]],
    detectors: dict[str, dict[str, Any]],
    implementation: str,
    value: Any,
    detector: str,
    kind: str = "slither-ast",
    scope_root: Path | None = None,
    audit_files: set[str] | None = None,
) -> None:
    for feature, config in detectors.items():
        if config["mode"] == "structural" and config.get("implementation") == implementation:
            add(evidence, feature, value, detector, kind, scope_root, audit_files)


def lowered_parts(contract: Any, function: Any | None = None, node: Any | None = None) -> str:
    values = [getattr(contract, "name", "")]
    values.extend(getattr(base, "name", "") for base in getattr(contract, "inheritance", []))
    if function is not None:
        values.extend(
            [
                getattr(function, "name", ""),
                getattr(function, "full_name", ""),
                str(getattr(function, "return_type", "")),
            ]
        )
        values.extend(str(variable) for variable in getattr(function, "variables_read", []))
        values.extend(getattr(modifier, "name", "") for modifier in getattr(function, "modifiers", []))
    if node is not None:
        values.append(str(getattr(node, "expression", "")))
        values.extend(f"{type(ir).__name__}:{ir}" for ir in getattr(node, "irs", []))
    return " ".join(values).lower()


def detect(
    slither: Any,
    detectors: dict[str, dict[str, Any]],
    scope_root: Path | None = None,
    audit_files: set[str] | None = None,
) -> dict[str, set[tuple[str, str, str, str]]]:
    from slither.slithir.operations import (
        Binary,
        HighLevelCall,
        LibraryCall,
        LowLevelCall,
        NewContract,
        Send,
        SolidityCall,
        Transfer,
        TypeConversion,
    )

    evidence = {feature: set() for feature in detectors}
    for contract in slither.contracts:
        contract_text = lowered_parts(contract)
        add_presence_heuristics(evidence, contract, contract_text, detectors, scope_root, audit_files)

        for function in contract.functions_and_modifiers_declared:
            function_text = lowered_parts(contract, function)
            add_presence_heuristics(evidence, function, function_text, detectors, scope_root, audit_files)
            if getattr(function, "payable", False):
                add_structural(evidence, detectors, "payable_function", function, "payable-function", scope_root=scope_root, audit_files=audit_files)
            if any(str(variable).lower() == "msg.value" for variable in getattr(function, "solidity_variables_read", [])):
                add_structural(evidence, detectors, "msg_value_read", function, "msg-value-read", scope_root=scope_root, audit_files=audit_files)
            if any(str(variable).lower() in {"block.timestamp", "block.number"} for variable in getattr(function, "solidity_variables_read", [])):
                add_structural(evidence, detectors, "time_read", function, "block-time-read", "slither-ir", scope_root, audit_files)

            for node in function.nodes:
                node_type = str(getattr(node, "type", ""))
                text = lowered_parts(contract, function, node)
                add_presence_heuristics(evidence, node, text, detectors, scope_root, audit_files)
                if "ASSEMBLY" in node_type:
                    add_structural(evidence, detectors, "assembly_node", node, "assembly-node", scope_root=scope_root, audit_files=audit_files)
                if "LOOP" in node_type:
                    add_structural(evidence, detectors, "loop_node", node, "loop-node", scope_root=scope_root, audit_files=audit_files)
                for ir in getattr(node, "irs", []):
                    if isinstance(ir, LowLevelCall):
                        call_name = str(getattr(ir, "function_name", "")).lower()
                        add_structural(evidence, detectors, "low_level_call_ir", node, f"{call_name or 'low-level-call'}-ir", "slither-ir", scope_root, audit_files)
                        add_structural(evidence, detectors, "external_call_ir", node, f"{call_name or 'low-level-call'}-ir", "slither-ir", scope_root, audit_files)
                        if call_name == "delegatecall":
                            add_structural(evidence, detectors, "delegatecall_ir", node, "delegatecall-ir", "slither-ir", scope_root, audit_files)
                        destination = str(getattr(ir, "destination", "")).lower()
                        if any(str(parameter).lower() in destination for parameter in getattr(function, "parameters", [])):
                            add_structural(evidence, detectors, "arbitrary_external_target_ir", node, "parameterized-call-target", "slither-ir", scope_root, audit_files)
                    elif isinstance(ir, (Send, Transfer)):
                        add_structural(evidence, detectors, "low_level_call_ir", node, f"{type(ir).__name__.lower()}-ir", "slither-ir", scope_root, audit_files)
                        add_structural(evidence, detectors, "external_call_ir", node, f"{type(ir).__name__.lower()}-ir", "slither-ir", scope_root, audit_files)
                    elif isinstance(ir, (HighLevelCall, LibraryCall, NewContract)):
                        add_structural(evidence, detectors, "external_call_ir", node, f"{type(ir).__name__.lower()}-ir", "slither-ir", scope_root, audit_files)
                    if isinstance(ir, NewContract) and getattr(ir, "call_salt", None) is not None:
                        add_structural(evidence, detectors, "create2_ir", node, "new-contract-salt-ir", "slither-ir", scope_root, audit_files)
                    if isinstance(ir, SolidityCall) and "create2" in str(getattr(ir, "function", "")).lower():
                        add_structural(evidence, detectors, "create2_ir", node, "create2-solidity-call", "slither-ir", scope_root, audit_files)
                    if isinstance(ir, Binary):
                        add_structural(evidence, detectors, "binary_ir", node, "binary-operation", "slither-ir", scope_root, audit_files)
                    if isinstance(ir, TypeConversion):
                        source_type = str(getattr(getattr(ir, "variable", None), "type", "")).lower()
                        target_type = str(getattr(ir, "type", "")).lower()
                        if source_type.startswith("int") != target_type.startswith("int") and (source_type.startswith(("int", "uint")) and target_type.startswith(("int", "uint"))):
                            add_structural(evidence, detectors, "signed_conversion_ir", node, "signed-unsigned-conversion", "slither-ir", scope_root, audit_files)
                if "msg.value" in text:
                    add_structural(evidence, detectors, "msg_value_read", node, "msg-value-text", "source", scope_root, audit_files)
    return evidence


def analyzed_source_paths(slither: Any, scope_root: Path, audit_files: set[str] | None = None) -> list[str]:
    analyzed: set[str] = set()
    for unit in slither.crytic_compile.compilation_units.values():
        for filename in getattr(unit, "filenames", []):
            absolute = Path(str(getattr(filename, "absolute", filename)))
            relative = relative_scope_path(scope_root, absolute)
            if relative is not None and (audit_files is None or relative in audit_files):
                analyzed.add(relative)
    return sorted(analyzed)


def compilation_unit_paths(
    slither: Any,
    build_root: Path,
    excluded_roots: tuple[Path, ...] = (),
) -> list[str] | None:
    """Return the exact closure, or None when Slither cannot expose it.

    An observed source outside ``build_root`` is an integrity error, not a
    reason to use the broad build-root fallback. Sources inside the
    engine-managed output root are generated audit artifacts, never
    compilation inputs.
    """
    units = getattr(getattr(slither, "crytic_compile", None), "compilation_units", None)
    if not isinstance(units, dict) or not units:
        return None
    managed_prefixes = relative_excluded_roots(build_root, excluded_roots)
    paths: set[str] = set()
    for unit in units.values():
        filenames = getattr(unit, "filenames", None)
        if filenames is None:
            return None
        for filename in filenames:
            absolute = Path(str(getattr(filename, "absolute", filename))).resolve()
            try:
                relative = absolute.relative_to(build_root.resolve())
            except ValueError as error:
                raise ValueError(
                    "compiled source is outside build_root; choose a build_root "
                    f"that contains the complete compilation closure: {absolute}"
                ) from error
            if excluded_by_root(relative, managed_prefixes):
                continue
            paths.add(relative.as_posix())
    return sorted(paths) or None


def actual_compiler_versions(slither: Any) -> list[str]:
    versions: set[str] = set()
    for unit in getattr(slither.crytic_compile, "compilation_units", {}).values():
        value = getattr(unit, "compiler_version", None)
        version = getattr(value, "version", value)
        if isinstance(version, str) and version.strip():
            versions.add(version.strip())
    return sorted(versions)


def command_version(command: str | None) -> str | None:
    executable = command or shutil.which("solc")
    if not executable:
        return None
    result = subprocess.run([executable, "--version"], capture_output=True, text=True, check=False)
    for line in result.stdout.splitlines():
        if line.startswith("Version:"):
            return line.removeprefix("Version:").strip()
    return None


def validate_output_targets(
    scope_root: Path,
    build_root: Path,
    scope_files: list[str],
    outputs: tuple[tuple[str, Path | None], ...],
) -> None:
    """Reject outputs that resolve to any audited or compilable Solidity file."""
    source_paths = {
        (scope_root if scope_root.is_file() else scope_root / relative).resolve()
        for relative in scope_files
    }
    source_paths.update(
        path.resolve()
        for path in build_root.rglob("*.sol")
        if path.is_file()
    )
    for label, output in outputs:
        aliased = False
        if output is not None:
            resolved = output.resolve()
            aliased = resolved in source_paths
            if not aliased and output.exists():
                aliased = any(os.path.samefile(output, source) for source in source_paths)
        if aliased:
            raise ValueError(
                f"{label} output would overwrite an audited or compilation Solidity source: "
                f"{resolved}"
            )


def build_feature_map(
    root: Path,
    target: Path,
    solc: str | None,
    confirm_absence: bool,
    audit_root: Path | None = None,
    exclusions: tuple[str, ...] = (),
    build_root: Path | None = None,
    source_trust: str | None = None,
    include_patterns: tuple[str, ...] = (),
    dependency_roots: tuple[str, ...] = tuple(sorted(DEFAULT_DEPENDENCY_ROOTS)),
    code_index_out: Path | None = None,
    feature_map_out: Path | None = None,
    acquisition_root: Path | None = None,
    managed_output_root: Path | None = None,
) -> dict[str, Any]:
    feature_data = json.loads((root / "data" / "features.json").read_text(encoding="utf-8"))
    feature_names = sorted(feature_data["features"])
    detector_config = load_detector_config(root, set(feature_names))
    scope_root = resolve_scope_root(target, audit_root)
    compilation_root = resolve_build_root(scope_root, build_root, boundary=acquisition_root or scope_root)
    trust = inspect_repository(acquisition_root or compilation_root, source_trust)
    if not trust["direct_agent_open_allowed"]:
        raise ValueError(
            "repository trust gate blocked the original source; create a sanitized snapshot "
            "with scripts/repository_preflight.py before Recon"
        )
    excluded_roots = (managed_output_root,) if managed_output_root is not None else ()
    scope_files, excluded_paths = scope_inventory(
        scope_root, exclusions, include_patterns, dependency_roots, excluded_roots
    )
    validate_output_targets(
        scope_root,
        compilation_root,
        scope_files,
        (("feature-map", feature_map_out), ("code-index", code_index_out)),
    )
    for label, output in (("feature-map", feature_map_out), ("code-index", code_index_out)):
        if output is not None:
            validate_generated_artifact_path(
                output,
                audit_root=scope_root,
                build_root=compilation_root,
                label=label,
                managed_output_root=managed_output_root,
            )
    audit_files = set(scope_files)
    pre_snapshot = conservative_input_snapshot(
        scope_root,
        build_root=compilation_root,
        exclusions=exclusions,
        include_patterns=include_patterns,
        dependency_roots=dependency_roots,
        boundary=acquisition_root or scope_root,
        excluded_roots=excluded_roots,
    )
    Slither = ensure_slither_import()
    kwargs: dict[str, Any] = {}
    if solc:
        kwargs["solc"] = solc
    slither = Slither(str(target.resolve()), **kwargs)
    closure_files = compilation_unit_paths(slither, compilation_root, excluded_roots)
    detected = detect(slither, detector_config, scope_root, audit_files)
    files_analyzed = analyzed_source_paths(slither, scope_root, audit_files)
    uncompiled_paths = sorted(set(scope_files) - set(files_analyzed))
    compilation_complete = not uncompiled_paths

    features: dict[str, Any] = {}
    for feature in feature_names:
        values = sorted(detected.get(feature, set()))
        if values:
            features[feature] = {
                "status": "PRESENT",
                "evidence": [
                    {"kind": kind, "location": location, "reason": reason, "scope_origin": scope_origin}
                    for kind, location, reason, scope_origin in values
                ],
            }
        elif confirm_absence and compilation_complete and detector_config.get(feature, {}).get("absence_capable") is True:
            features[feature] = {
                "status": "ABSENT_CONFIRMED",
                "evidence": [{
                    "kind": "slither-ast",
                    "location": str(scope_root),
                    "reason": f"Complete Slither traversal found no {detector_config[feature]['label']}",
                    "scope_origin": "AUDIT_SCOPE",
                }],
            }
        else:
            features[feature] = {"status": "UNKNOWN", "evidence": []}
    compiler_versions = actual_compiler_versions(slither)
    if not compiler_versions:
        fallback_version = command_version(solc)
        compiler_versions = [fallback_version] if fallback_version else []
    solc_version = compiler_versions[0] if len(compiler_versions) == 1 else None
    digests = compilation_digests(
        scope_root,
        scope_files,
        solc_version,
        build_root=compilation_root,
        dependency_roots=dependency_roots,
        boundary=acquisition_root or scope_root,
        compilation_files=closure_files,
        compiler_versions=compiler_versions,
        excluded_roots=excluded_roots,
    )
    recon_context = {
        "target_root": str(scope_root),
        "build_root": str(compilation_root),
        "files_analyzed": files_analyzed,
        "excluded_paths": excluded_paths,
        "exclusion_patterns": sorted(set(exclusions)),
        "include_patterns": sorted(set(include_patterns)),
        "dependency_roots": sorted(set(dependency_roots)),
        "uncompiled_paths": uncompiled_paths,
        "source_digest": digests["audit_source_digest"],
        **digests,
        "compilation_complete": compilation_complete,
        "recon_quality": {
            "compilation_complete": compilation_complete,
            "absence_filtering_complete": compilation_complete,
            "mode": "COMPLETE" if compilation_complete else "CONSERVATIVE_DEGRADED",
            "uncompiled_paths": uncompiled_paths,
            "compilation_provenance": (
                "EXACT_COMPILATION_CLOSURE"
                if closure_files is not None
                else "CONSERVATIVE_BUILD_ROOT_FALLBACK"
            ),
        },
        "slither_version": importlib.metadata.version("slither-analyzer"),
        "solc_version": solc_version,
        "compiler_versions": compiler_versions,
    }
    navigation_binding: dict[str, Any] | None = None
    if closure_files is not None:
        recon_context["compilation_files"] = closure_files
    code_index_serialized: str | None = None
    if code_index_out is not None:
        code_index = build_code_index(
            slither,
            scope_root,
            compilation_root,
            audit_files,
            recon_context["source_digest"],
            recon_context["compilation_input_digest"],
            managed_output_root=managed_output_root,
        )
        validate_schema(root, "code-index.schema.json", code_index)
        code_index_serialized = json.dumps(code_index, ensure_ascii=False, indent=2) + "\n"
        navigation_binding = {
            "schema_version": code_index["schema_version"],
            "sha256": sha256_bytes(code_index_serialized.encode("utf-8")),
        }
    recon_context["navigation_artifacts"] = {"code_index": navigation_binding}
    post_snapshot = conservative_input_snapshot(
        scope_root,
        build_root=compilation_root,
        exclusions=exclusions,
        include_patterns=include_patterns,
        dependency_roots=dependency_roots,
        boundary=acquisition_root or scope_root,
        excluded_roots=excluded_roots,
    )
    if pre_snapshot != post_snapshot:
        raise ValueError("source/build inputs changed during Recon; retry from a stable checkout")
    payload = {
        "schema_version": FEATURE_MAP_VERSION,
        "recon_context": recon_context,
        "features": features,
    }
    rendered = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    output_snapshots = {
        path: snapshot_file(path)
        for path in (feature_map_out, code_index_out)
        if path is not None
    }
    try:
        if feature_map_out is not None:
            atomic_write_text(feature_map_out, rendered)
        if code_index_out is not None and code_index_serialized is not None:
            atomic_write_text(code_index_out, code_index_serialized)
        if conservative_input_snapshot(
            scope_root,
            build_root=compilation_root,
            exclusions=exclusions,
            include_patterns=include_patterns,
            dependency_roots=dependency_roots,
            boundary=acquisition_root or scope_root,
            excluded_roots=excluded_roots,
        ) != pre_snapshot:
            raise ValueError("source/build inputs changed during Recon; retry from a stable checkout")
    except Exception:
        for path, snapshot in output_snapshots.items():
            restore_file(path, snapshot)
        raise
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", type=Path, help="Solidity file or project accepted by Slither")
    parser.add_argument("--root", type=Path, default=ROOT, help="evm-audit-skills suite root")
    parser.add_argument("--solc", help="solc executable forwarded to Slither")
    parser.add_argument("--audit-root", type=Path, help="complete audit scope; defaults to the Slither target")
    parser.add_argument("--build-root", type=Path, help="compilation/build project root; inferred for file targets")
    parser.add_argument("--source-trust", type=str.upper, choices=("TRUSTED", "UNTRUSTED", "UNKNOWN"), default="UNKNOWN")
    parser.add_argument("--acquisition-root", type=Path, help="stop automatic build-root discovery above this source boundary")
    parser.add_argument("--exclude", action="append", default=[], help="additional audit-scope glob to exclude; repeatable")
    parser.add_argument("--include", action="append", default=[], help="include a normally dependency-only audit path; repeatable")
    parser.add_argument("--dependency-root", action="append", default=None, help="top-level dependency root; repeatable")
    parser.add_argument("--present-only", action="store_true", help="leave detector absences UNKNOWN")
    parser.add_argument(
        "--managed-output-root",
        type=Path,
        help="controller-owned audit output root; engine-excluded from scope, digests, snapshots, and code-index inputs",
    )
    parser.add_argument("--output", type=Path, help="write JSON to this path instead of stdout")
    parser.add_argument("--code-index-out", type=Path, help="write a snapshot-bound source navigation index")
    parser.add_argument("--quiet", action="store_true", help="suppress progress output")
    args = parser.parse_args(argv)
    configure(quiet=args.quiet)

    try:
        require_distinct_paths(
            ("feature-map", args.output),
            ("code-index", args.code_index_out),
        )
        stage("RECON", detail="Analyzing the project and building the scope-bound Feature Map")
        payload = build_feature_map(
            args.root.resolve(),
            args.target,
            args.solc,
            not args.present_only,
            args.audit_root,
            tuple(args.exclude),
            args.build_root,
            args.source_trust,
            tuple(args.include),
            tuple(args.dependency_root) if args.dependency_root is not None else tuple(sorted(DEFAULT_DEPENDENCY_ROOTS)),
            args.code_index_out,
            args.output,
            acquisition_root=args.acquisition_root,
            managed_output_root=args.managed_output_root,
        )
        rendered = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
        if not args.output:
            print(rendered, end="")
        statuses = [entry["status"] for entry in payload["features"].values()]
        info(f"Solidity files analyzed: {len(payload['recon_context']['files_analyzed'])}")
        info(f"Compilation complete: {'yes' if payload['recon_context']['compilation_complete'] else 'no'}")
        info(f"PRESENT features: {statuses.count('PRESENT')}")
        info(f"ABSENT_CONFIRMED features: {statuses.count('ABSENT_CONFIRMED')}")
        info(f"UNKNOWN features: {statuses.count('UNKNOWN')}")
        if args.output:
            info(f"Feature Map written to {args.output}")
        success("Feature Map ready")
        return 0
    except Exception as exc:
        error(exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
