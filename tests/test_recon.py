#!/usr/bin/env python3
"""Tests for Slither-backed reconnaissance and compilation safety."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.recon import DETECTOR_IMPLEMENTATIONS, SAFE_ABSENCE_IMPLEMENTATIONS, build_feature_map, load_detector_config

from helpers import ROOT, load_json


def run_recon(target: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    solc = shutil.which("solc") or "solc"
    return subprocess.run(
        [sys.executable, "scripts/recon.py", str(target), "--solc", solc, *extra],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )


class ReconTests(unittest.TestCase):
    def test_detector_registry_matches_python_implementations(self) -> None:
        features = set(load_json(ROOT / "data/features.json")["features"])
        detectors = load_detector_config(ROOT, features)
        self.assertTrue(detectors)
        for feature, detector in detectors.items():
            with self.subTest(feature=feature):
                if detector["mode"] == "structural":
                    self.assertIn(detector["implementation"], DETECTOR_IMPLEMENTATIONS)
                    if detector["absence_capable"]:
                        self.assertIn(detector["implementation"], SAFE_ABSENCE_IMPLEMENTATIONS)
                else:
                    self.assertTrue(detector["terms"])

    def test_recon_uses_slither_evidence_and_confirms_supported_absence(self) -> None:
        result = run_recon(ROOT / "tests/fixtures/recon/ReconFixture.sol")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(
            payload["recon_context"]["recon_quality"]["compilation_provenance"],
            "EXACT_COMPILATION_CLOSURE",
        )
        feature_map = payload["features"]
        for feature in (
            "uses-assembly",
            "uses-create2",
            "uses-delegatecall",
            "uses-dynamic-loop",
            "uses-erc20",
            "uses-erc4626",
            "uses-merkle",
            "uses-msg-value",
            "uses-oracle",
            "uses-payable",
            "uses-proxy",
            "uses-signature",
        ):
            with self.subTest(feature=feature):
                self.assertEqual(feature_map[feature]["status"], "PRESENT")
                self.assertTrue(feature_map[feature]["evidence"])
        self.assertEqual(feature_map["uses-flash-loan"]["status"], "UNKNOWN")
        self.assertEqual(feature_map["uses-arbitrary-external-call"]["status"], "UNKNOWN")
        self.assertEqual(feature_map["uses-access-control"]["status"], "PRESENT")

    def test_recon_only_confirms_structurally_safe_absence(self) -> None:
        result = run_recon(ROOT / "tests/fixtures/recon/Empty.sol")
        self.assertEqual(result.returncode, 0, result.stderr)
        features = json.loads(result.stdout)["features"]
        for feature in ("uses-assembly", "uses-msg-value", "uses-payable"):
            self.assertEqual(features[feature]["status"], "ABSENT_CONFIRMED")
        for feature in (
            "uses-dynamic-loop",
            "uses-delegatecall",
            "uses-proxy",
            "uses-oracle",
            "uses-signature",
            "uses-reentrancy-callback",
            "uses-arbitrary-external-call",
            "uses-multicall",
        ):
            self.assertEqual(features[feature]["status"], "UNKNOWN")

    def test_incomplete_compilation_uses_conservative_degraded_routing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            feature_path = Path(temp_dir) / "feature-map.json"
            recon = run_recon(
                ROOT / "tests/fixtures/recon/Empty.sol",
                "--audit-root",
                ".",
                "--source-trust",
                "TRUSTED",
                "--output",
                str(feature_path),
            )
            self.assertEqual(recon.returncode, 0, recon.stderr)
            self.assertFalse(load_json(feature_path)["recon_context"]["compilation_complete"])
            result = subprocess.run(
                [
                    sys.executable,
                    "scripts/select_checks.py",
                    "--feature-map",
                    str(feature_path),
                    "--target-root",
                    str(ROOT),
                    "--domain",
                    "evm-audit-general",
                    "--manifest-out",
                    str(Path(temp_dir) / "manifest.json"),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = load_json(Path(temp_dir) / "manifest.json")
            self.assertEqual(
                manifest["feature_map"]["recon_context"]["recon_quality"]["mode"],
                "CONSERVATIVE_DEGRADED",
            )
            self.assertEqual(manifest["filtered_count"], 0)

            strict = subprocess.run(
                [
                    sys.executable,
                    "scripts/select_checks.py",
                    "--feature-map",
                    str(feature_path),
                    "--target-root",
                    str(ROOT),
                    "--domain",
                    "evm-audit-general",
                    "--require-complete-compilation",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(strict.returncode, 0)
            self.assertIn("complete compilation", strict.stderr)

    def test_recon_rejects_input_change_before_output_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "project"
            target = project / "Target.sol"
            feature_map = Path(directory) / "feature-map.json"
            code_index = Path(directory) / "code-index.json"
            project.mkdir()
            target.write_text("pragma solidity ^0.8.24; contract Target {}\n", encoding="utf-8")
            fake_slither = SimpleNamespace(
                contracts=[],
                crytic_compile=SimpleNamespace(compilation_units={}),
            )
            original_digests = __import__("scripts.recon", fromlist=["compilation_digests"]).compilation_digests

            def digest_and_mutate(*args, **kwargs):
                value = original_digests(*args, **kwargs)
                target.write_text(target.read_text(encoding="utf-8") + "// changed during Recon\n", encoding="utf-8")
                return value

            def fake_index(_slither, scope_root, build_root, _audit_files, source_digest, compilation_digest, managed_output_root=None):
                return {
                    "schema_version": 2,
                    "target_root": str(scope_root),
                    "build_root": str(build_root),
                    "source_digest": source_digest,
                    "compilation_input_digest": compilation_digest,
                    "contracts": {}, "functions": {}, "inheritance": {},
                    "external_calls": [], "storage_writes": [], "modifiers": {}, "source_ranges": {},
                }

            with patch("scripts.recon.ensure_slither_import", return_value=lambda *_args, **_kwargs: fake_slither), \
                patch("scripts.recon.compilation_digests", side_effect=digest_and_mutate), \
                patch("scripts.recon.build_code_index", side_effect=fake_index):
                with self.assertRaisesRegex(ValueError, "changed during Recon"):
                    build_feature_map(
                        ROOT,
                        target,
                        None,
                        False,
                        build_root=project,
                        code_index_out=code_index,
                        feature_map_out=feature_map,
                    )
            self.assertFalse(feature_map.exists())
            self.assertFalse(code_index.exists())


if __name__ == "__main__":
    unittest.main()
