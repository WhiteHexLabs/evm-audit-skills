#!/usr/bin/env python3
"""Real Slither regressions for the source navigation index."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from slither import Slither

from helpers import ROOT
import scripts.audit_run as audit_controller
from scripts.audit_artifacts import bind_routing_snapshot, bound_code_index_status, sha256_bytes, validate_schema
from scripts.code_context import _concrete_function, _slither_api, build_code_index, lookup, validate_code_index
from scripts.scope_context import scope_inventory


FIXTURE = ROOT / "tests/fixtures/code_context"


class CodeContextIntegrationTests(unittest.TestCase):
    def test_bound_query_and_controller_share_navigation_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target_root = root / "fixture"
            shutil.copytree(FIXTURE, target_root)
            run_dir = root / "run"
            initialized = subprocess.run(
                [
                    sys.executable,
                    "scripts/audit_run.py",
                    "init",
                    str(target_root / "Main.sol"),
                    "--run-dir",
                    str(run_dir),
                    "--audit-root",
                    str(target_root),
                    "--domain",
                    "evm-audit-general",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(initialized.returncode, 0, initialized.stderr)
            index_path = run_dir / "recon/code-index.json"
            original = index_path.read_bytes()
            index = json.loads(original)
            entry = next(key for key in index["functions"] if key.endswith("::Main.entry(uint256)"))
            values = audit_controller.paths(run_dir)
            manifest = json.loads(values["manifest"].read_text(encoding="utf-8"))

            def query(*extra: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [
                        sys.executable,
                        "scripts/code_context.py",
                        "--run-dir",
                        str(run_dir),
                        "--function",
                        entry,
                        "--depth",
                        "1",
                        *extra,
                    ],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                )

            self.assertEqual(query("--include-callees").returncode, 0)
            self.assertEqual(
                audit_controller._optional_code_index_status(ROOT, values, manifest)["status"],
                "CURRENT",
            )

            changed = json.loads(original)
            changed["external_calls"][0]["start_line"] += 1
            index_path.write_text(json.dumps(changed) + "\n", encoding="utf-8")
            self.assertNotEqual(query("--include-callees").returncode, 0)
            self.assertEqual(
                audit_controller._optional_code_index_status(ROOT, values, manifest)["status"],
                "TAMPERED",
            )

            index_path.write_bytes(original)
            changed = json.loads(original)
            changed["functions"][entry]["start_line"] += 1
            changed["source_ranges"][entry]["start_line"] += 1
            index_path.write_text(json.dumps(changed) + "\n", encoding="utf-8")
            self.assertNotEqual(query("--include-callees").returncode, 0)
            self.assertEqual(
                audit_controller._optional_code_index_status(ROOT, values, manifest)["status"],
                "TAMPERED",
            )

            index_path.write_bytes(original)
            self.assertEqual(query("--include-callees").returncode, 0)
            index_path.unlink()
            self.assertEqual(
                audit_controller._optional_code_index_status(ROOT, values, manifest)["status"],
                "MISSING",
            )
            self.assertNotEqual(query("--include-callees").returncode, 0)

            index_path.write_bytes(original)
            source_path = target_root / "Main.sol"
            source = source_path.read_bytes()
            try:
                source_path.write_bytes(source + b"\n// changed after Recon\n")
                self.assertNotEqual(query("--include-callees").returncode, 0)
            finally:
                source_path.write_bytes(source)

            invalid = json.loads(original)
            invalid["source_ranges"][entry]["start_line"] += 1
            invalid_raw = (json.dumps(invalid) + "\n").encode("utf-8")
            bound_manifest = json.loads(json.dumps(manifest))
            bound_manifest["feature_map"]["recon_context"]["navigation_artifacts"]["code_index"]["sha256"] = sha256_bytes(invalid_raw)
            bound_manifest = bind_routing_snapshot(bound_manifest)
            index_path.write_bytes(invalid_raw)
            self.assertEqual(
                bound_code_index_status(ROOT, bound_manifest, index_path)["status"],
                "UNAVAILABLE",
            )
            binding = bound_manifest["feature_map"]["recon_context"]["navigation_artifacts"]["code_index"]
            binding["sha256"] = sha256_bytes(original)
            binding["schema_version"] = 999
            bound_manifest = bind_routing_snapshot(bound_manifest)
            index_path.write_bytes(original)
            self.assertEqual(
                bound_code_index_status(ROOT, bound_manifest, index_path)["status"],
                "UNAVAILABLE",
            )
            index_path.write_bytes(original)

            unbound = root / "unbound-code-index.json"
            unbound.write_bytes(original)
            unbound_command = [
                sys.executable,
                "scripts/code_context.py",
                "--index",
                str(unbound),
                "--function",
                entry,
                "--root",
                str(ROOT),
            ]
            rejected = subprocess.run(unbound_command, cwd=ROOT, capture_output=True, text=True)
            self.assertNotEqual(rejected.returncode, 0)
            accepted = subprocess.run(
                [*unbound_command, "--allow-unbound-index"],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)

    def test_code_index_query_shapes_stay_strict_and_aligned(self) -> None:
        index_schema = json.loads((ROOT / "schemas/code-index.schema.json").read_text(encoding="utf-8"))
        query_schema = json.loads((ROOT / "schemas/code-context-query.schema.json").read_text(encoding="utf-8"))
        for index_name, query_name in (("range", "range"), ("function", "function"), ("call", "edge")):
            with self.subTest(shape=query_name):
                index_shape = index_schema["$defs"][index_name]
                query_shape = query_schema["$defs"][query_name]
                self.assertEqual(index_shape.get("additionalProperties"), query_shape.get("additionalProperties"))
                self.assertEqual(set(index_shape.get("required", [])), set(query_shape.get("required", [])))
                self.assertEqual(set(index_shape.get("properties", [])), set(query_shape.get("properties", [])))

    def test_unsupported_slither_shape_names_pinned_version(self) -> None:
        api = _slither_api()
        with self.assertRaisesRegex(ValueError, rf"unsupported Slither callee shape.*{api['version']}"):
            _concrete_function(object(), api)

    def test_build_code_index_uses_real_slither_ir(self) -> None:
        solc = shutil.which("solc")
        if solc is None:
            self.fail("real Slither code-index coverage requires solc")
        slither = Slither(str(FIXTURE / "Main.sol"), solc=solc)
        files, _ = scope_inventory(FIXTURE)
        index = build_code_index(
            slither,
            FIXTURE,
            FIXTURE,
            set(files),
            "a" * 64,
            "b" * 64,
        )
        validate_code_index(ROOT, index)
        serialized = (json.dumps(index, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        repeat = build_code_index(
            slither,
            FIXTURE,
            FIXTURE,
            set(files),
            "a" * 64,
            "b" * 64,
        )
        repeat_serialized = (json.dumps(repeat, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        self.assertEqual(serialized, repeat_serialized)
        self.assertEqual(sha256_bytes(serialized), sha256_bytes(repeat_serialized))

        entry = next(key for key in index["functions"] if key.endswith("::Main.entry(uint256)"))
        helper = next(key for key in index["functions"] if key.endswith("::Main._helper(uint256)"))
        callee = next(key for key in index["functions"] if key.endswith("::Main._callee(uint256)"))
        service = next(key for key in index["functions"] if key.endswith("::Service.ping(uint256)"))
        library = next(key for key in index["functions"] if key.endswith("::MathLib.bump(uint256)"))

        self.assertIn(helper, index["functions"][entry]["internal_calls"])
        self.assertIn(callee, index["functions"][helper]["internal_calls"])
        self.assertIn(service, index["functions"][entry]["external_calls"])
        getter_edges = [
            call for call in index["external_calls"]
            if call["caller"] == entry and call["target"].startswith("high-level-getter:")
        ]
        self.assertTrue(getter_edges)
        self.assertTrue(all(call["target"] not in index["functions"] for call in getter_edges))
        self.assertEqual(
            sum(call["target"] == library for call in index["external_calls"]),
            1,
        )
        low_level = [call for call in index["external_calls"] if call["caller"] == entry and call["kind"] in {"call", "delegatecall"}]
        self.assertEqual({call["kind"] for call in low_level}, {"call", "delegatecall"})
        self.assertTrue(all(call["target"] not in index["functions"] for call in low_level))
        self.assertTrue(all(call["start_line"] > index["functions"][entry]["start_line"] for call in low_level))
        query = lookup(index, entry, include_callers=True, include_callees=True, depth=2)
        validate_schema(ROOT, "code-context-query.schema.json", query)
        self.assertIn(callee, query["functions"])
        self.assertTrue(any(edge["kind"] == "delegatecall" for edge in query["unresolved_edges"]))

        writes = [write for write in index["storage_writes"] if write["function"] in {entry, helper}]
        self.assertTrue(writes)
        self.assertTrue(all(write["variable"].endswith(".value") or write["variable"] == "value" for write in writes))
        self.assertTrue(all(write["start_line"] > index["functions"][write["function"]]["start_line"] for write in writes))
        self.assertNotIn("local", {write["variable"] for write in index["storage_writes"]})
        self.assertIn("local", index["functions"][entry]["local_writes"])

        self.assertIn(next(key for key in index["functions"] if key.endswith("::Base.auth()")), index["modifiers"])
        self.assertTrue(any(key.endswith("::Main.overloaded(uint256)") for key in index["functions"]))
        self.assertTrue(any(key.endswith("::Main.overloaded(address)") for key in index["functions"]))

        with self.assertRaisesRegex(ValueError, "ambiguous"):
            lookup(index, "Duplicate.same(uint256)")
        expanded = lookup(index, entry, include_callees=True)
        self.assertIn(entry, expanded["functions"])
        self.assertIn(helper, expanded["functions"])
        capped = lookup(index, entry, include_callees=True, depth=3, max_nodes=2)
        self.assertTrue(capped["truncated"])
        index["functions"][callee]["internal_calls"] = [entry]
        cycled = lookup(index, entry, include_callees=True, depth=50)
        self.assertLessEqual(len(cycled["functions"]), len(index["functions"]))
        self.assertFalse(cycled["truncated"])

    def test_index_paths_are_collision_safe_and_host_independent(self) -> None:
        solc = shutil.which("solc")
        if solc is None:
            self.fail("real Slither code-index coverage requires solc")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "src"
            for subdir in (source / "a", source / "b"):
                subdir.mkdir(parents=True)
            (source / "Main.sol").write_text(
                'pragma solidity ^0.8.0; import "./a/Shared.sol"; import "./b/Shared.sol"; contract Main {}',
                encoding="utf-8",
            )
            for subdir, name in ((source / "a", "SharedA"), (source / "b", "SharedB")):
                (subdir / "Shared.sol").write_text(
                    f"pragma solidity ^0.8.0; contract {name} {{ function ping() external pure returns (uint256) {{ return 1; }} }}",
                    encoding="utf-8",
                )
            slither = Slither(str(source / "Main.sol"), solc=solc)
            files, _ = scope_inventory(source)
            index = build_code_index(slither, source, root, set(files), "a" * 64, "b" * 64)
            self.assertEqual(index["target_root"], "build://src")
            self.assertEqual(index["build_root"], "build://")
            self.assertEqual(
                {record["file"] for record in index["contracts"].values()},
                {"build://src/Main.sol", "build://src/a/Shared.sol", "build://src/b/Shared.sol"},
            )
            self.assertEqual(len(index["functions"]), 2)
            self.assertEqual(
                {key.split("::", 1)[0] for key in index["functions"]},
                {"build://src/a/Shared.sol", "build://src/b/Shared.sol"},
            )

    def test_dependency_paths_inside_build_root_are_not_reduced_to_basenames(self) -> None:
        solc = shutil.which("solc")
        if solc is None:
            self.fail("real Slither code-index coverage requires solc")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "src"
            vendor = root / "vendor"
            source.mkdir()
            vendor.mkdir()
            target = root / "Target.sol"
            target.write_text(
                'pragma solidity ^0.8.0; import "./vendor/Shared.sol"; contract Target { Shared shared; }',
                encoding="utf-8",
            )
            (vendor / "Shared.sol").write_text(
                "pragma solidity ^0.8.0; contract Shared { function ping() external pure returns (uint256) { return 1; } }",
                encoding="utf-8",
            )
            slither = Slither(str(target), solc=solc)
            index = build_code_index(slither, root, root, {"Target.sol"}, "a" * 64, "b" * 64)
            self.assertTrue(any(record["file"] == "build://vendor/Shared.sol" for record in index["contracts"].values()))
            self.assertTrue(all(not str(value.get("file", "")).startswith("/") for value in index["contracts"].values()))
            self.assertTrue(all(not str(value.get("file", "")).startswith("/") for value in index["functions"].values()))


if __name__ == "__main__":
    unittest.main()
