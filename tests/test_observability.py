#!/usr/bin/env python3
"""Regression tests for controller progress and machine-output boundaries."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

from helpers import EMPTY_TARGET, ROOT
from scripts.audit_run import (
    STAGE_PROGRESS,
    _log_current_state,
    _run,
    _stage_result,
    progress_metadata,
)
from evm_audit_runtime.controller_state import TOTAL_DISPLAY_PHASES, display_stage
from scripts.codex_model_profile import STAGES
from scripts.runtime_log import configure, stage


class ObservabilityTests(unittest.TestCase):
    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, *arguments],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def init_run(self, run_dir: Path, *extra: str) -> subprocess.CompletedProcess[str]:
        return self.run_cli(
            "scripts/audit_run.py",
            "init",
            str(EMPTY_TARGET),
            "--run-dir",
            str(run_dir),
            "--audit-root",
            str(EMPTY_TARGET),
            "--domain",
            "evm-audit-general",
            *extra,
        )

    def test_default_controller_output_is_compact_json_plus_progress(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self.init_run(Path(directory) / "run")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["next"]["stage"], "DOMAIN_CONTEXT")
        self.assertEqual(
            payload["next"]["progress"],
            {
                "step": 2,
                "total": 6,
                "label": "Context Analysis",
                "summary": "4 required context fields need resolution",
            },
        )
        history = payload["progress_history"]
        self.assertEqual(
            [entry["stage"] for entry in history],
            ["RECON", "ROUTING", "DOMAIN_CONTEXT"],
        )
        self.assertEqual(
            [entry["state"] for entry in history],
            ["COMPLETED", "COMPLETED", "CURRENT"],
        )
        self.assertEqual(
            [entry["progress"]["step"] for entry in history],
            [1, 1, 2],
        )
        self.assertEqual(
            [entry["progress"]["total"] for entry in history],
            [6, 6, 6],
        )
        self.assertEqual(history[-1]["progress"], payload["next"]["progress"])
        self.assertEqual(
            history[-1]["recommended_execution"],
            payload["next"]["recommended_execution"],
        )
        self.assertIn("Solidity files analyzed", history[0]["progress"]["summary"])
        self.assertIn("checks selected", history[1]["progress"]["summary"])
        self.assertIn("EVM AUDIT :: PROJECT ANALYSIS", result.stderr)
        self.assertEqual(result.stderr.count("EVM AUDIT :: PROJECT ANALYSIS"), 2)
        self.assertIn("Next required phase: Context Analysis", result.stderr)
        self.assertIn("Codex model: gpt-5.6-luna", result.stderr)
        self.assertIn("Handoff: controller does not switch the active Codex model", result.stderr)
        self.assertNotIn("EVM AUDIT :: RECON", result.stderr)
        self.assertNotIn("EVM AUDIT :: ROUTING", result.stderr)
        self.assertNotIn("Feature Map ready", result.stderr)
        self.assertIsInstance(payload, dict)

    def test_init_history_exposes_domain_resolution_as_step_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            result = self.run_cli(
                "scripts/audit_run.py",
                "init",
                str(EMPTY_TARGET),
                "--run-dir",
                str(run_dir),
                "--audit-root",
                str(EMPTY_TARGET),
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        history = payload["progress_history"]
        self.assertEqual(payload["next"]["stage"], "DOMAIN_RESOLUTION")
        self.assertEqual(
            [(entry["stage"], entry["progress"]["step"]) for entry in history],
            [("RECON", 1), ("ROUTING", 1), ("DOMAIN_RESOLUTION", 2)],
        )
        self.assertEqual(history[-1]["state"], "CURRENT")

    def test_quiet_keeps_json_and_errors_visible(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self.init_run(Path(directory) / "run", "--quiet")
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertIsInstance(payload, dict)
            self.assertEqual(payload["next"]["progress"]["label"], "Context Analysis")
            self.assertEqual(payload["next"]["recommended_execution"]["model"], "gpt-5.6-luna")
            self.assertEqual(
                [entry["progress"]["step"] for entry in payload["progress_history"]],
                [1, 1, 2],
            )
            self.assertEqual(result.stderr, "")

            missing = self.run_cli(
                "scripts/audit_run.py",
                "status",
                "--run-dir",
                str(Path(directory) / "missing"),
                "--quiet",
            )
        self.assertNotEqual(missing.returncode, 0)
        self.assertEqual(missing.stdout, "")
        self.assertIn("ERROR:", missing.stderr)

    def test_verbose_forwards_low_level_diagnostics_without_polluting_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self.init_run(Path(directory) / "run", "--verbose")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Feature Map ready", result.stderr)
        self.assertIn("[DOMAIN] evm-audit-general", result.stderr)
        self.assertIsInstance(json.loads(result.stdout), dict)

    def test_child_stderr_is_hidden_by_default_and_forwarded_in_verbose(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts = root / "scripts"
            scripts.mkdir()
            (scripts / "child.py").write_text(
                "import sys\n"
                "print('child diagnostic', file=sys.stderr)\n"
                "print('{\"ok\": true}')\n",
                encoding="utf-8",
            )

            default_stderr = io.StringIO()
            with redirect_stderr(default_stderr):
                result = _run(root, "child.py", [])
            self.assertEqual(result.stdout.strip(), '{"ok": true}')
            self.assertNotIn("child diagnostic", default_stderr.getvalue())

            verbose_stderr = io.StringIO()
            with redirect_stderr(verbose_stderr):
                _run(root, "child.py", [], verbose=True)
            self.assertIn("child diagnostic", verbose_stderr.getvalue())

    def test_failing_child_keeps_a_concise_reason(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts = root / "scripts"
            scripts.mkdir()
            (scripts / "child.py").write_text(
                "import sys\n"
                "print('ERROR: incomplete compilation coverage', file=sys.stderr)\n"
                "sys.exit(2)\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "child.py failed: incomplete compilation coverage"):
                _run(root, "child.py", [])

    def test_stage_results_use_one_canonical_progress_mapping(self) -> None:
        expected = {
            "RECON": (1, "Project Analysis"),
            "ROUTING": (1, "Project Analysis"),
            "DOMAIN_RESOLUTION": (2, "Context Analysis"),
            "DOMAIN_CONTEXT": (2, "Context Analysis"),
            "SCREEN": (3, "Initial Review"),
            "DEEP_REVIEW": (4, "Deep Audit"),
            "PROOF": (5, "Vulnerability Validation"),
            "REPORT": (6, "Final Report"),
        }
        self.assertEqual(set(STAGE_PROGRESS), set(STAGES))
        self.assertEqual({metadata["step"] for metadata in STAGE_PROGRESS.values()}, set(range(1, TOTAL_DISPLAY_PHASES + 1)))
        self.assertEqual({stage: metadata["label"] for stage, metadata in STAGE_PROGRESS.items()}, {stage: label for stage, (_, label) in expected.items()})
        self.assertEqual(display_stage("PROOF"), "Vulnerability Validation")
        with self.assertRaisesRegex(ValueError, "unknown audit stage"):
            display_stage("UNKNOWN")
        self.assertEqual(
            {
                stage: (metadata["step"], metadata["label"])
                for stage, metadata in STAGE_PROGRESS.items()
            },
            expected,
        )
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            for stage_name, (step, label) in expected.items():
                result = _stage_result(run_dir, stage_name, summary=f"{label} summary")
                self.assertEqual(
                    result["progress"],
                    {"step": step, "total": 6, "label": label, "summary": f"{label} summary"},
                )
                self.assertEqual(result["stage"], stage_name)
            self.assertEqual(
                _stage_result(run_dir, "DEEP_REVIEW")["recommended_execution"],
                {"provider": "codex", "model": "gpt-5.6-luna", "reasoning_effort": "max"},
            )
            self.assertEqual(
                _stage_result(run_dir, "PROOF")["recommended_execution"],
                {"provider": "codex", "model": "gpt-5.6-luna", "reasoning_effort": "max"},
            )

        self.assertEqual(
            progress_metadata("PROOF"),
            {"step": 5, "total": 6, "label": "Vulnerability Validation", "summary": "Vulnerability Validation stage"},
        )

    def test_domain_substages_keep_distinct_labels_at_step_three(self) -> None:
        for stage_name, label in (
            ("DOMAIN_RESOLUTION", "Context Analysis"),
            ("DOMAIN_CONTEXT", "Context Analysis"),
        ):
            with self.subTest(stage=stage_name):
                result = _stage_result(Path("/tmp/run"), stage_name)
                self.assertEqual(result["progress"]["step"], 2)
                self.assertEqual(result["progress"]["total"], 6)
                self.assertEqual(result["progress"]["label"], label)

    def test_verbose_stage_output_exposes_internal_substage_without_promoting_it(self) -> None:
        output = io.StringIO()
        configure(verbose=True)
        with redirect_stderr(output):
            stage("RECON", step=99, total=99, detail="test detail")
        configure()
        rendered = output.getvalue()
        self.assertIn("EVM AUDIT :: PROJECT ANALYSIS", rendered)
        self.assertIn("[1/6] Project Analysis · Recon", rendered)
        self.assertNotIn("EVM AUDIT :: RECON", rendered)
        with self.assertRaisesRegex(ValueError, "unknown audit stage"):
            stage("UNKNOWN")

    def test_init_next_status_and_report_keep_quiet_stdout_as_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            init = self.init_run(run_dir, "--quiet")
            next_result = self.run_cli(
                "scripts/audit_run.py", "next", "--run-dir", str(run_dir), "--quiet"
            )
            status = self.run_cli(
                "scripts/audit_run.py", "status", "--run-dir", str(run_dir), "--quiet"
            )
            report = self.run_cli(
                "scripts/audit_run.py", "report", "--run-dir", str(run_dir), "--quiet"
            )

        self.assertEqual(init.returncode, 0, init.stderr)
        self.assertEqual(next_result.returncode, 0, next_result.stderr)
        self.assertNotEqual(report.returncode, 0)
        for result in (init, next_result, status):
            self.assertEqual(result.stderr, "")
            self.assertIsInstance(json.loads(result.stdout), dict)
        self.assertEqual(json.loads(next_result.stdout)["progress"]["label"], "Context Analysis")
        self.assertEqual(json.loads(status.stdout)["progress"]["label"], "Context Analysis")
        self.assertEqual(report.stdout, "")
        self.assertIn("ERROR:", report.stderr)

    def test_state_logging_matches_current_stage_without_false_completion(self) -> None:
        manifest = {
            "deferred_domains": [{"domain": "evm-audit-bridges"}],
            "required_context_requirements": {"evm-audit-general": {"price": {}}},
        }
        coverage = {
            "selected": ["A"],
            "screen_not_applicable": [],
            "deep_candidates": ["A", "B"],
            "deep_reviewed": ["A"],
            "suspicious": [],
            "confirmed": [],
        }
        cases = (
            ("INCOMPLETE_DOMAIN_ROUTING", "EVM AUDIT :: CONTEXT ANALYSIS", None, manifest, None),
            ("INCOMPLETE_CONTEXT", "EVM AUDIT :: CONTEXT ANALYSIS", None, {**manifest, "deferred_domains": []}, None),
            ("INCOMPLETE_COVERAGE", "EVM AUDIT :: INITIAL REVIEW", None, {**manifest, "deferred_domains": []}, {}),
            ("INCOMPLETE_REVIEW", "EVM AUDIT :: DEEP AUDIT", None, {**manifest, "deferred_domains": []}, {}),
            ("INCOMPLETE_REVIEW", "EVM AUDIT :: VULNERABILITY VALIDATION", ["A"], {**manifest, "deferred_domains": []}, {}),
            ("COMPLETE_CLEAN", "EVM AUDIT :: FINAL REPORT", "Audit complete", {**manifest, "deferred_domains": []}, {}),
        )
        for status, expected_stage, expected_success, current_manifest, current_context in cases:
            with self.subTest(status=status, expected_stage=expected_stage):
                current = {"status": status, "complete": status == "COMPLETE_CLEAN", "clean": True, "coverage": coverage}
                if expected_success == ["A"]:
                    current["coverage"] = {**coverage, "deep_reviewed": ["A", "B"], "suspicious": ["A"]}
                output = io.StringIO()
                configure()
                with redirect_stderr(output):
                    _log_current_state(current, current_manifest, None, current_context)
                rendered = output.getvalue()
                self.assertIn(expected_stage, rendered)
                if expected_success == "Audit complete":
                    self.assertIn(expected_success, rendered)
                else:
                    self.assertNotIn("Audit complete", rendered)


if __name__ == "__main__":
    unittest.main()
