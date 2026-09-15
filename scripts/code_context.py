#!/usr/bin/env python3
"""Build and query a small, snapshot-bound Solidity navigation index."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from evm_audit_runtime.code_index import lookup, validate_code_index
from evm_audit_runtime.limits import MAX_CODE_CONTEXT_EDGES, MAX_CODE_CONTEXT_NODES
from evm_audit_runtime.versions import CODE_INDEX_VERSION

try:
    from audit_artifacts import load_json, validate_bound_code_index, validate_schema
    from scope_context import relative_scope_path
except ImportError:  # pragma: no cover
    from scripts.audit_artifacts import load_json, validate_bound_code_index, validate_schema
    from scripts.scope_context import relative_scope_path


ROOT = Path(__file__).resolve().parents[1]
def _slither_api() -> dict[str, Any]:
    try:
        from slither.core.declarations import Contract, Function
        from slither.core.variables.state_variable import StateVariable
        from slither.core.variables.variable import Variable
        from slither.slithir.operations import (
            HighLevelCall,
            InternalCall,
            LibraryCall,
            LowLevelCall,
            SolidityCall,
        )
    except ImportError as error:  # pragma: no cover - recon reports this operational failure
        raise ValueError("Slither object adapters require slither-analyzer") from error
    try:
        version = importlib.metadata.version("slither-analyzer")
    except importlib.metadata.PackageNotFoundError:  # pragma: no cover - covered by the import failure in practice
        version = "unknown"
    return {
        "Contract": Contract,
        "Function": Function,
        "StateVariable": StateVariable,
        "Variable": Variable,
        "HighLevelCall": HighLevelCall,
        "InternalCall": InternalCall,
        "LibraryCall": LibraryCall,
        "LowLevelCall": LowLevelCall,
        "SolidityCall": SolidityCall,
        "version": version,
    }


def _unsupported(api: dict[str, Any], kind: str, value: Any) -> ValueError:
    return ValueError(
        f"unsupported Slither {kind} shape: {type(value).__name__} "
        f"(slither-analyzer {api['version']})"
    )


def _mapping(value: Any) -> Any:
    for candidate in (value, getattr(value, "node", None)):
        mapping = getattr(candidate, "source_mapping", None)
        filename = getattr(mapping, "filename", None)
        if mapping is not None and filename is not None:
            return mapping
    return None


def _line_values(lines: Any) -> list[int]:
    return sorted({line for line in (lines or ()) if isinstance(line, int) and line > 0})


def _external_location(path: Path) -> str:
    try:
        identity = path.read_bytes()
    except OSError:
        identity = path.name.encode("utf-8")
    return f"external://{hashlib.sha256(identity).hexdigest()}/{path.name}"


def _index_location(path: Path, build_root: Path) -> str:
    try:
        relative = path.relative_to(build_root.resolve()).as_posix()
    except ValueError:
        return _external_location(path)
    return "build://" if relative == "." else f"build://{relative}"


def _under_managed_root(value: Any, managed_root: Path | None) -> bool:
    """True when a Slither object is declared inside the managed output tree."""
    if managed_root is None:
        return False
    filename_value = getattr(getattr(_mapping(value), "filename", None), "absolute", None)
    if not filename_value:
        return False
    absolute = Path(str(filename_value)).resolve()
    resolved = managed_root.resolve()
    return absolute == resolved or resolved in absolute.parents


def _location(
    value: Any,
    scope_root: Path,
    build_root: Path,
    audit_files: set[str],
    fallback: tuple[str, int, int, str, bool] | None = None,
) -> tuple[str, int, int, str, bool]:
    mapping = _mapping(value)
    filename_value = getattr(getattr(mapping, "filename", None), "absolute", None)
    lines = _line_values(getattr(mapping, "lines", None))
    if not filename_value or not lines:
        if fallback is not None:
            return (*fallback[:4], True)
        return "unknown://source", 1, 1, "UNKNOWN", True
    absolute = Path(str(filename_value)).resolve()
    relative = relative_scope_path(scope_root, absolute)
    origin = "AUDIT_SCOPE" if relative is not None and relative in audit_files else "DEPENDENCY"
    return _index_location(absolute, build_root), min(lines), max(lines), origin, False


def _function_name(value: Any) -> str:
    full_name = getattr(value, "full_name", None)
    if isinstance(full_name, str) and full_name:
        return full_name
    return str(getattr(value, "name", ""))


def _name(value: Any) -> str:
    name = getattr(value, "name", None)
    if isinstance(name, str) and name:
        return name
    return str(value)


def _text_values(values: Any) -> list[str]:
    return sorted({str(value) for value in (values or ()) if str(value).strip()})


def _variable_values(values: Any) -> list[str]:
    return sorted({_name(value) for value in (values or ()) if _name(value).strip()})


def _function_key(file: str, contract: Any, function: Any) -> str:
    return f"{file}::{getattr(contract, 'name', '')}.{_function_name(function)}"


def _contract_key(file: str, contract: Any) -> str:
    return f"{file}::{getattr(contract, 'name', '')}"


def _function_id(
    function: Any,
    contract: Any,
    scope_root: Path,
    build_root: Path,
    audit_files: set[str],
) -> str:
    file, _, _, _, _ = _location(function, scope_root, build_root, audit_files)
    if file.startswith("unknown://"):
        file, _, _, _, _ = _location(contract, scope_root, build_root, audit_files)
    return _function_key(file, contract, function)


def _concrete_function(
    value: Any,
    api: dict[str, Any],
) -> Any | None:
    if value is None or isinstance(value, api["Function"]):
        return value
    if isinstance(value, api["Variable"]):
        return None
    raise _unsupported(api, "callee", value)


def _resolve_internal_call(ir: Any, api: dict[str, Any]) -> Any | None:
    if not isinstance(ir, api["InternalCall"]):
        return None
    return _concrete_function(getattr(ir, "function", None), api)


def _resolve_high_level_call(item: Any, api: dict[str, Any]) -> tuple[Any, Any]:
    if not isinstance(item, tuple) or len(item) != 2:
        raise _unsupported(api, "high-level call tuple", item)
    contract, ir = item
    if not isinstance(contract, api["Contract"]):
        raise _unsupported(api, "high-level call target", contract)
    if not isinstance(ir, api["HighLevelCall"]):
        raise _unsupported(api, "high-level call IR", ir)
    return contract, ir


def _resolve_library_call(ir: Any, api: dict[str, Any]) -> Any | None:
    if not isinstance(ir, api["LibraryCall"]):
        raise _unsupported(api, "library call IR", ir)
    return _concrete_function(getattr(ir, "function", None), api)


def _call_descriptor(kind: str, *values: Any) -> str:
    parts = [str(value).strip().replace("\n", " ") for value in values if str(value).strip()]
    return f"{kind}:{':'.join(parts) or 'unknown'}"


def _resolved_function_id(
    function: Any,
    function_ids: dict[int, str],
    scope_root: Path,
    build_root: Path,
    audit_files: set[str],
) -> str | None:
    if function is None:
        return None
    known = function_ids.get(id(function))
    if known:
        return known
    contract = getattr(function, "contract_declarer", None) or getattr(function, "contract", None)
    if contract is None:
        return None
    return _function_id(function, contract, scope_root, build_root, audit_files)


def _event(
    caller: str,
    target: str,
    kind: str,
    source: Any,
    function_location: tuple[str, int, int, str, bool],
    scope_root: Path,
    build_root: Path,
    audit_files: set[str],
) -> dict[str, Any]:
    file, start, _, _, fallback = _location(
        source,
        scope_root,
        build_root,
        audit_files,
        function_location,
    )
    value = {"caller": caller, "target": target, "kind": kind, "file": file, "start_line": start}
    if fallback:
        value["location_fallback"] = True
    return value


def build_code_index(
    slither: Any,
    scope_root: Path,
    build_root: Path,
    audit_files: set[str],
    source_digest: str,
    compilation_input_digest: str,
    *,
    managed_output_root: Path | None = None,
) -> dict[str, Any]:
    api = _slither_api()
    scope_root = scope_root.resolve()
    build_root = build_root.resolve()
    contracts: dict[str, Any] = {}
    functions: dict[str, Any] = {}
    inheritance: dict[str, list[str]] = {}
    external_calls: list[dict[str, Any]] = []
    storage_writes: list[dict[str, Any]] = []
    modifiers: dict[str, list[str]] = {}
    source_ranges: dict[str, dict[str, Any]] = {}
    contract_ids: dict[int, str] = {}
    function_ids: dict[int, str] = {}
    function_entries: list[tuple[Any, Any, str, tuple[str, int, int, str, bool]]] = []

    # Generated audit output (PoC sources) is never a navigation input.
    contract_values = [
        value
        for value in (getattr(slither, "contracts", []) or [])
        if not _under_managed_root(value, managed_output_root)
    ]
    contract_values.sort(
        key=lambda value: (
            _location(value, scope_root, build_root, audit_files)[0],
            str(getattr(value, "name", "")),
        )
    )
    for contract in contract_values:
        location = _location(contract, scope_root, build_root, audit_files)
        file, start, end, origin, _ = location
        name = str(getattr(contract, "name", ""))
        key = _contract_key(file, contract)
        if file.startswith("unknown://") or not name:
            raise ValueError(f"cannot derive collision-safe contract identity (slither-analyzer {api['version']})")
        if key in contracts:
            raise ValueError(f"duplicate contract identity in code index: {key}")
        contract_ids[id(contract)] = key
        contracts[key] = {
            "file": file,
            "start_line": start,
            "end_line": end,
            "bases": [],
            "scope_origin": origin,
        }

    for contract in contract_values:
        contract_id = contract_ids[id(contract)]
        bases: set[str] = set()
        for base in getattr(contract, "inheritance", []) or []:
            base_id = contract_ids.get(id(base))
            if base_id is None:
                base_location = _location(base, scope_root, build_root, audit_files)
                base_id = _contract_key(base_location[0], base)
            bases.add(base_id)
        contracts[contract_id]["bases"] = sorted(bases)
        inheritance[contract_id] = sorted(bases)

        declared = list(getattr(contract, "functions_and_modifiers_declared", []) or [])
        declared.sort(key=lambda value: _function_id(value, contract, scope_root, build_root, audit_files))
        for function in declared:
            location = _location(function, scope_root, build_root, audit_files)
            key = _function_id(function, contract, scope_root, build_root, audit_files)
            if key.startswith("unknown://") or key in functions:
                raise ValueError(f"duplicate or unresolved function identity in code index: {key}")
            if id(function) in function_ids:
                raise ValueError(f"function object maps to multiple identities: {key}")
            function_ids[id(function)] = key
            function_entries.append((contract, function, key, location))

    for contract, function, key, function_location in sorted(function_entries, key=lambda value: value[2]):
        file, start, end, origin, _ = function_location
        modifier_names = _text_values(
            getattr(modifier, "name", modifier) for modifier in getattr(function, "modifiers", []) or []
        )
        state_reads = _variable_values(getattr(function, "state_variables_read", []) or [])
        state_writes = _variable_values(getattr(function, "state_variables_written", []) or [])
        local_writes = _variable_values(
            value
            for value in getattr(function, "variables_written", []) or []
            if not isinstance(value, api["StateVariable"])
        )
        functions[key] = {
            "function_id": key,
            "contract_id": contract_ids[id(contract)],
            "contract": str(getattr(contract, "name", "")),
            "name": str(getattr(function, "name", "")),
            "file": file,
            "start_line": start,
            "end_line": end,
            "visibility": str(getattr(function, "visibility", "")),
            "modifiers": modifier_names,
            "reads": _text_values(getattr(function, "variables_read", []) or []),
            "writes": state_writes,
            "state_reads": state_reads,
            "state_writes": state_writes,
            "local_writes": local_writes,
            "internal_calls": [],
            "external_calls": [],
            "scope_origin": origin,
        }
        modifiers[key] = modifier_names
        source_ranges[key] = {"file": file, "start_line": start, "end_line": end}

        events: list[dict[str, Any]] = []
        internal_targets: set[str] = set()
        external_targets: set[str] = set()
        seen_operations: set[int] = set()

        def add_call(target: str, kind: str, source: Any) -> None:
            events.append(
                _event(
                    key,
                    target,
                    kind,
                    source,
                    function_location,
                    scope_root,
                    build_root,
                    audit_files,
                )
            )

        for ir in getattr(function, "internal_calls", []) or []:
            seen_operations.add(id(ir))
            if isinstance(ir, api["InternalCall"]):
                callee = _resolve_internal_call(ir, api)
                target = _resolved_function_id(callee, function_ids, scope_root, build_root, audit_files)
                if target is None:
                    target = _call_descriptor(
                        "internal-unresolved",
                        getattr(ir, "contract_name", ""),
                        getattr(ir, "function_name", ""),
                    )
                else:
                    internal_targets.add(target)
                add_call(target, "internal", ir)
            elif isinstance(ir, api["SolidityCall"]):
                add_call("solidity:" + _function_name(getattr(ir, "function", ir)), "solidity", ir)
            else:
                raise _unsupported(api, "internal call IR", ir)

        for ir in getattr(function, "solidity_calls", []) or []:
            if id(ir) in seen_operations:
                continue
            seen_operations.add(id(ir))
            if not isinstance(ir, api["SolidityCall"]):
                raise _unsupported(api, "Solidity call IR", ir)
            add_call("solidity:" + _function_name(getattr(ir, "function", ir)), "solidity", ir)

        for item in getattr(function, "high_level_calls", []) or []:
            contract_target, ir = _resolve_high_level_call(item, api)
            if isinstance(ir, api["LibraryCall"]):
                if id(ir) in seen_operations:
                    continue
                seen_operations.add(id(ir))
                callee = _resolve_library_call(ir, api)
                target = _resolved_function_id(callee, function_ids, scope_root, build_root, audit_files)
                if target is None:
                    target = _call_descriptor("library-unresolved", getattr(ir, "function_name", ""))
                else:
                    external_targets.add(target)
                add_call(target, "library", ir)
                continue
            callee = _concrete_function(getattr(ir, "function", None), api)
            target = _resolved_function_id(callee, function_ids, scope_root, build_root, audit_files)
            if target is None:
                target = _call_descriptor(
                    "high-level-getter" if isinstance(getattr(ir, "function", None), api["Variable"]) else "high-level-unresolved",
                    getattr(contract_target, "name", ""),
                    getattr(ir, "function_name", ""),
                )
            else:
                external_targets.add(target)
            add_call(target, "high_level", ir)

        for ir in getattr(function, "library_calls", []) or []:
            if id(ir) in seen_operations:
                continue
            seen_operations.add(id(ir))
            callee = _resolve_library_call(ir, api)
            target = _resolved_function_id(callee, function_ids, scope_root, build_root, audit_files)
            if target is None:
                target = _call_descriptor("library-unresolved", getattr(ir, "function_name", ""))
            else:
                external_targets.add(target)
            add_call(target, "library", ir)

        for ir in getattr(function, "low_level_calls", []) or []:
            seen_operations.add(id(ir))
            if not isinstance(ir, api["LowLevelCall"]):
                raise _unsupported(api, "low-level call IR", ir)
            kind = str(getattr(ir, "function_name", "")).lower()
            if kind not in {"call", "delegatecall", "staticcall", "callcode"}:
                kind = "low_level"
            target = _call_descriptor("low-level", kind, getattr(ir, "destination", ""))
            add_call(target, kind, ir)

        functions[key]["internal_calls"] = sorted(internal_targets)
        functions[key]["external_calls"] = sorted(
            external_targets
            | {
                event["target"]
                for event in events
                if event["kind"] != "internal" and event["target"] not in internal_targets
            }
        )
        external_calls.extend(events)

        state_locations: dict[str, set[tuple[str, int, bool]]] = {}
        for node in getattr(function, "nodes", []) or []:
            for variable in getattr(node, "state_variables_written", []) or []:
                variable_name = _name(variable)
                node_location = _location(
                    node,
                    scope_root,
                    build_root,
                    audit_files,
                    function_location,
                )
                state_locations.setdefault(variable_name, set()).add(
                    (node_location[0], node_location[1], node_location[4])
                )
        for variable_name in state_writes:
            locations = state_locations.get(variable_name) or {
                (function_location[0], function_location[1], True)
            }
            for write_file, write_line, fallback in sorted(locations):
                write = {
                    "function": key,
                    "variable": variable_name,
                    "file": write_file,
                    "start_line": write_line,
                }
                if fallback:
                    write["location_fallback"] = True
                storage_writes.append(write)

    external_calls.sort(key=lambda value: json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    storage_writes.sort(key=lambda value: json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return {
        "schema_version": CODE_INDEX_VERSION,
        "target_root": _index_location(scope_root, build_root),
        "build_root": _index_location(build_root, build_root),
        "source_digest": source_digest,
        "compilation_input_digest": compilation_input_digest,
        "contracts": contracts,
        "functions": functions,
        "inheritance": inheritance,
        "external_calls": external_calls,
        "storage_writes": storage_writes,
        "modifiers": modifiers,
        "source_ranges": source_ranges,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, help="query the run-bound Recon code index")
    parser.add_argument("--index", type=Path, help="code index path for bound or explicit development use")
    parser.add_argument("--manifest", type=Path, help="routing manifest bound to --index")
    parser.add_argument(
        "--allow-unbound-index",
        action="store_true",
        help="explicitly inspect an unbound development index",
    )
    parser.add_argument("--function", required=True)
    parser.add_argument("--include-callers", action="store_true")
    parser.add_argument("--include-callees", action="store_true")
    parser.add_argument("--depth", type=int, default=1)
    parser.add_argument("--max-nodes", type=int, default=MAX_CODE_CONTEXT_NODES)
    parser.add_argument("--max-edges", type=int, default=MAX_CODE_CONTEXT_EDGES)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        root = args.root.resolve()
        if args.run_dir is not None:
            if args.index is not None or args.manifest is not None or args.allow_unbound_index:
                raise ValueError("--run-dir cannot be combined with --index, --manifest, or --allow-unbound-index")
            run_dir = args.run_dir.resolve()
            manifest_path = run_dir / "routing/manifest.json"
            index_path = run_dir / "recon/code-index.json"
            index = validate_bound_code_index(root, load_json(manifest_path), index_path)
        elif args.manifest is not None:
            if args.index is None:
                raise ValueError("--manifest requires --index")
            if args.allow_unbound_index:
                raise ValueError("--manifest cannot be combined with --allow-unbound-index")
            index = validate_bound_code_index(root, load_json(args.manifest), args.index)
        elif args.index is not None:
            if not args.allow_unbound_index:
                raise ValueError("--index requires --run-dir or --manifest; use --allow-unbound-index for development")
            index = load_json(args.index)
            validate_code_index(root, index)
        else:
            raise ValueError("one of --run-dir or --index is required")
        result = lookup(
            index,
            args.function,
            include_callers=args.include_callers,
            include_callees=args.include_callees,
            depth=args.depth,
            max_nodes=args.max_nodes,
            max_edges=args.max_edges,
        )
        validate_schema(root, "code-context-query.schema.json", result)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
