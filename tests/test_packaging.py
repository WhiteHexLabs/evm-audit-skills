#!/usr/bin/env python3
"""Smoke-test the supported suite installation layout."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.scope_context import find_suite_root


ROOT = Path(__file__).resolve().parents[1]


class PackagingTests(unittest.TestCase):
    def test_proof_worker_keeps_deterministic_proof_independent_of_runnable_poc(self) -> None:
        """The proof worker must not make runnable PoC a universal proof gate.

        Deterministic proof (trace, invariant, calculation, test) is enough
        for `CONFIRMED`; source retention is mandatory only when the proof
        itself is source-backed; High/Critical PoC reporting stays with the
        controller pipeline. This pins the worker template to the canonical
        review contract instead of a stricter local lifecycle.
        """
        template = ROOT / "skills" / "evm-audit-master" / "agents" / "evm-audit-worker-proof.md"
        text = template.read_text(encoding="utf-8")
        self.assertIn("trace, invariant violation, calculation, or test", text)
        self.assertNotIn("before claiming proof", text)
        self.assertIn("if the proof itself uses", text)
        self.assertIn("<run-dir>/poc/", text)
        self.assertIn("check-review-contract.runtime.md", text)
        self.assertIn("controller/reporting pipeline", text)

    def test_suite_symlinks_resolve_shared_runtime_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="evm-audit-suite-") as temp_dir:
            skills_root = Path(temp_dir) / "skills"
            suite = skills_root / "evm-audit-skills"
            shutil.copytree(ROOT, suite, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
            skills_root.mkdir(exist_ok=True)
            for domain in sorted((suite / "skills").glob("evm-audit-*")):
                (skills_root / domain.name).symlink_to(domain, target_is_directory=True)

            for link in sorted(skills_root.glob("evm-audit-*/SKILL.md")):
                resolved = link.resolve()
                self.assertTrue(resolved.exists(), link)
                self.assertEqual(suite.resolve(), find_suite_root(resolved))
                text = resolved.read_text(encoding="utf-8")
                if resolved.parent.name == "evm-audit-master":
                    self.assertTrue((suite / "data" / "features.json").exists())
                    self.assertTrue((suite / "scripts" / "select_checks.py").exists())
                    for agent in ("evm-audit-worker-flash", "evm-audit-worker-deep", "evm-audit-worker-proof"):
                        template = suite / "skills" / "evm-audit-master" / "agents" / f"{agent}.md"
                        self.assertTrue(template.is_file(), template)
                        self.assertIn("model:", template.read_text(encoding="utf-8"))
                else:
                    self.assertTrue((suite / "skills" / "evm-audit-master" / "references" / "check-review-contract.runtime.md").exists())
                    self.assertNotIn("use the canonical IDs from `../data/canonical-checks.json`", text)

            feature_map = suite / "feature-map.json"
            recon = subprocess.run(
                [sys.executable, "scripts/recon.py", "tests/fixtures/recon/Empty.sol", "--output", str(feature_map)],
                cwd=suite,
                capture_output=True,
                text=True,
            )
            self.assertEqual(recon.returncode, 0, recon.stderr)
            result = subprocess.run(
                [sys.executable, "scripts/select_checks.py", "--feature-map", str(feature_map), "--target-root", "tests/fixtures/recon/Empty.sol", "--domain", "evm-audit-erc4626", "--format", "json"],
                cwd=suite,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
