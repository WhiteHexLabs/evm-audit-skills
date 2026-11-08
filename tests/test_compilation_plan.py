"""Regression tests for multi-target Recon coverage and identity binding."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from helpers import ROOT

from evm_audit_runtime.compilation import (
    CompilationPlanError,
    compilation_plan_digest,
    normalize_compilation_plan,
    public_plan,
)
from scripts.audit_artifacts import validate_schema
from scripts.recon import build_feature_map
from scripts.select_checks import SelectionInputError, validate_recon_context


def _fixture_project(root: Path) -> tuple[Path, dict]:
    for relative in ("core/Core.sol", "legacy/Legacy.sol"):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("pragma solidity ^0.8.0; contract Fixture {}\n", encoding="utf-8")
    return root / "core/Core.sol", {
        "schema_version": 1,
        "units": [
            {
                "id": "legacy",
                "target": "legacy/Legacy.sol",
                "scope_roots": ["legacy"],
                "expected_compiler_versions": ["0.8.0"],
            },
            {
                "id": "core",
                "target": "core/Core.sol",
                "scope_roots": ["core"],
                "expected_compiler_versions": ["0.8.0"],
            },
        ],
    }


class CompilationPlanTests(TestCase):
    def test_plan_is_canonicalized_and_duplicate_configuration_is_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            _, raw = _fixture_project(root)
            normalized = normalize_compilation_plan(raw, audit_root=root, build_root=root)
            self.assertEqual([unit["id"] for unit in normalized["units"]], ["core", "legacy"])
            self.assertEqual(public_plan(normalized)["units"][0]["scope_roots"], ["core"])
            self.assertEqual(compilation_plan_digest(normalized), compilation_plan_digest(normalized))
            duplicate = {**raw, "units": [raw["units"][0], raw["units"][0]]}
            with self.assertRaisesRegex(CompilationPlanError, "duplicate compilation unit id"):
                normalize_compilation_plan(duplicate, audit_root=root, build_root=root)

    def test_multi_target_recon_aggregates_complete_coverage_and_selector_accepts_it(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            target, raw_plan = _fixture_project(root)

            def fake_slither(path: str, **_kwargs):
                source = Path(path).resolve()
                filename = SimpleNamespace(absolute=str(source))
                unit = SimpleNamespace(filenames=[filename], compiler_version="0.8.0")
                return SimpleNamespace(
                    contracts=[],
                    crytic_compile=SimpleNamespace(compilation_units={source.name: unit}),
                )

            with patch("scripts.recon.ensure_slither_import", return_value=fake_slither), patch(
                "scripts.recon.importlib.metadata.version", return_value="test"
            ):
                feature_map = build_feature_map(
                    ROOT,
                    target,
                    None,
                    True,
                    audit_root=root,
                    build_root=root,
                    source_trust="TRUSTED",
                    compilation_plan=raw_plan,
                )
            recon = feature_map["recon_context"]
            self.assertTrue(recon["compilation_complete"])
            self.assertEqual(recon["uncompiled_paths"], [])
            self.assertEqual(recon["recon_quality"]["failed_units"], [])
            self.assertEqual([item["status"] for item in recon["compilation_targets"]], ["COMPLETE", "COMPLETE"])
            validate_schema(ROOT, "feature-map.schema.json", feature_map)
            checked = validate_recon_context(recon, root, (), build_root=root)
            self.assertEqual(checked["compilation_input_digest"], recon["compilation_input_digest"])

    def test_failed_target_keeps_global_absence_filtering_disabled(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            target, raw_plan = _fixture_project(root)

            def fake_slither(path: str, **_kwargs):
                source = Path(path).resolve()
                if source.name == "Legacy.sol":
                    raise RuntimeError("compiler failed for legacy target")
                filename = SimpleNamespace(absolute=str(source))
                unit = SimpleNamespace(filenames=[filename], compiler_version="0.8.0")
                return SimpleNamespace(
                    contracts=[],
                    crytic_compile=SimpleNamespace(compilation_units={source.name: unit}),
                )

            with patch("scripts.recon.ensure_slither_import", return_value=fake_slither), patch(
                "scripts.recon.importlib.metadata.version", return_value="test"
            ):
                feature_map = build_feature_map(
                    ROOT,
                    target,
                    None,
                    True,
                    audit_root=root,
                    build_root=root,
                    source_trust="TRUSTED",
                    compilation_plan=raw_plan,
                )
            recon = feature_map["recon_context"]
            self.assertFalse(recon["compilation_complete"])
            self.assertFalse(recon["recon_quality"]["absence_filtering_complete"])
            self.assertIn("legacy/Legacy.sol", recon["uncompiled_paths"])
            self.assertEqual(recon["compilation_targets"][1]["status"], "FAILED")
            self.assertEqual(feature_map["features"]["uses-payable"]["status"], "UNKNOWN")
            with self.assertRaisesRegex(SelectionInputError, "complete compilation"):
                validate_recon_context(recon, root, (), build_root=root, require_complete=True)


if __name__ == "__main__":
    import unittest

    unittest.main()
