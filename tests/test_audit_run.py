#!/usr/bin/env python3
"""Tests for the deterministic audit-run controller."""

from __future__ import annotations

import json
import hashlib
import multiprocessing
import queue
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from helpers import EMPTY_TARGET, ROOT, build_manifest
from evm_audit_runtime.reporting import derive_issue_candidates, derive_poc_required_ids
import scripts.audit_run as audit_controller
from scripts.audit_artifacts import check_body_hash, json_text
from scripts.render_runtime import domain_context_template, screen_results_template
from scripts.review_ledger import append
from support.run_fixtures import make_clean_review_state, make_confirmed_state


def _report_worker(run_dir: str, result_queue: object) -> None:
    try:
        audit_controller.report_run(ROOT, Path(run_dir))
        result_queue.put(("ok", ""))
    except BaseException as exc:  # pragma: no cover - asserted by the parent
        result_queue.put(("error", repr(exc)))


def _publication_lock_worker(run_dir: str, ready: object, result_queue: object) -> None:
    ready.wait(10)
    try:
        with audit_controller._report_publication_lock(Path(run_dir)):
            result_queue.put(("acquired", time.monotonic()))
    except BaseException as exc:  # pragma: no cover - asserted by the parent
        result_queue.put(("error", repr(exc)))


class AuditRunTests(unittest.TestCase):
    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, *arguments],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    @staticmethod
    def read(path: Path) -> dict:
        return json.loads(path.read_text(encoding="utf-8"))

    def prepare_clean_run(self, run_dir: Path) -> None:
        make_clean_review_state(run_dir)

    def prepare_finding_run(
        self, run_dir: Path, severities: list[str], *, include_poc: bool = True
    ) -> tuple[dict, dict, dict, dict, dict | None]:
        return make_confirmed_state(run_dir, severities, include_poc=include_poc)

    def test_report_bundle_write_failures_never_commit_mixed_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_clean_run(run_dir)
            result = self.run_cli("scripts/audit_run.py", "report", "--run-dir", str(run_dir))
            self.assertEqual(result.returncode, 0, result.stderr)
            values = audit_controller.paths(run_dir)
            manifest = self.read(values["manifest"])
            state = self.read(values["audit_state"])
            bundle_status = audit_controller._report_bundle_status(ROOT, values, manifest, state)
            self.assertTrue(bundle_status["current"], bundle_status)
            original_pointer = values["report_current"].read_bytes()
            generation = values["report_generations"] / json.loads(original_pointer)["generation"]
            original_generation = {
                path.relative_to(generation): path.read_bytes()
                for path in generation.iterdir()
                if path.is_file()
            }
            original_atomic_text = audit_controller.atomic_write_text
            original_atomic_json = audit_controller.atomic_write_json

            def fail_report(path: Path, content: str) -> None:
                if path.name == "AUDIT-REPORT.md":
                    raise OSError("report write failure")
                original_atomic_text(path, content)

            with patch.object(audit_controller, "atomic_write_text", side_effect=fail_report):
                with self.assertRaisesRegex(OSError, "report write failure"):
                    audit_controller.report_run(ROOT, run_dir)
            self.assertEqual(values["report_current"].read_bytes(), original_pointer)
            self.assertEqual(
                {path.relative_to(generation): path.read_bytes() for path in generation.iterdir() if path.is_file()},
                original_generation,
            )
            self.assertTrue(audit_controller._report_bundle_status(ROOT, values, manifest, state)["current"])

            def fail_issue(path: Path, value: dict) -> None:
                if path.name == "issue-candidates.json":
                    raise OSError("issue-candidates write failure")
                original_atomic_json(path, value)

            with patch.object(audit_controller, "atomic_write_json", side_effect=fail_issue):
                with self.assertRaisesRegex(OSError, "issue-candidates write failure"):
                    audit_controller.report_run(ROOT, run_dir)
            self.assertEqual(values["report_current"].read_bytes(), original_pointer)
            self.assertTrue(audit_controller._report_bundle_status(ROOT, values, manifest, state)["current"])

            def fail_bundle(path: Path, value: dict) -> None:
                if path.name == "report-bundle.json":
                    raise OSError("metadata write failure")
                original_atomic_json(path, value)

            with patch.object(audit_controller, "atomic_write_json", side_effect=fail_bundle):
                with self.assertRaisesRegex(OSError, "metadata write failure"):
                    audit_controller.report_run(ROOT, run_dir)
            self.assertEqual(values["report_current"].read_bytes(), original_pointer)
            self.assertTrue(audit_controller._report_bundle_status(ROOT, values, manifest, state)["current"])

            audit_controller.report_run(ROOT, run_dir)
            self.assertEqual(values["report_current"].read_bytes(), original_pointer)

    def test_report_result_points_to_current_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_clean_run(run_dir)
            run_dir = run_dir.resolve()
            result = audit_controller.report_run(ROOT, run_dir)
            pointer = self.read(run_dir / "report-current.json")
            generation = run_dir / "report-generations" / pointer["generation"]
            self.assertEqual(result["generation"], pointer["generation"])
            self.assertEqual(result["report"], str(generation / "AUDIT-REPORT.md"))
            self.assertEqual(result["issue_candidates"], str(generation / "issue-candidates.json"))
            self.assertEqual(result["report_bundle_path"], str(generation / "report-bundle.json"))
            self.assertEqual(result["report_current"], str(run_dir / "report-current.json"))
            self.assertTrue(result["convenience"]["synced"])

    def test_convenience_copy_failure_returns_authoritative_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_clean_run(run_dir)
            run_dir = run_dir.resolve()
            original = audit_controller.atomic_write_bytes

            def fail_convenience(path: Path, content: bytes) -> None:
                if path == run_dir / "AUDIT-REPORT.md":
                    raise OSError("convenience report copy failure")
                original(path, content)

            with patch.object(audit_controller, "atomic_write_bytes", side_effect=fail_convenience):
                result = audit_controller.report_run(ROOT, run_dir)
            self.assertFalse(result["convenience"]["synced"])
            self.assertIn(str(run_dir / "AUDIT-REPORT.md"), result["convenience"]["failed_paths"])
            self.assertTrue(Path(result["report"]).is_file())
            self.assertTrue(audit_controller._report_bundle_status(
                ROOT,
                audit_controller.paths(run_dir),
                self.read(run_dir / "routing/manifest.json"),
                self.read(run_dir / "audit-state.json"),
            )["current"])

    def test_status_reports_authoritative_report_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_clean_run(run_dir)
            run_dir = run_dir.resolve()
            audit_controller.report_run(ROOT, run_dir)
            result = audit_controller.status_run(ROOT, run_dir, emit=False, include_execution=True)
            pointer = self.read(run_dir / "report-current.json")
            generation = run_dir / "report-generations" / pointer["generation"]
            authority = result["report_generation"]
            self.assertEqual(authority["status"], "CURRENT")
            self.assertEqual(authority["generation"], pointer["generation"])
            self.assertEqual(authority["report"], str(generation / "AUDIT-REPORT.md"))
            self.assertEqual(authority["issue_candidates"], str(generation / "issue-candidates.json"))
            self.assertEqual(authority["bundle"], str(generation / "report-bundle.json"))
            self.assertEqual(authority["current_pointer"], str(run_dir / "report-current.json"))

    def test_report_lock_is_cross_process(self) -> None:
        context = multiprocessing.get_context("spawn")
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_clean_run(run_dir)
            ready = context.Event()
            result_queue = context.Queue()
            process = context.Process(target=_publication_lock_worker, args=(str(run_dir), ready, result_queue))
            with audit_controller._report_publication_lock(run_dir):
                process.start()
                ready.set()
                with self.assertRaises(queue.Empty):
                    result_queue.get(timeout=0.25)
            kind, detail = result_queue.get(timeout=10)
            process.join(10)
            self.assertEqual(process.exitcode, 0)
            self.assertEqual(kind, "acquired", detail)

    def test_report_lock_does_not_silently_disable_on_windows(self) -> None:
        import scripts.review_ledger as review_ledger

        with tempfile.TemporaryDirectory() as directory:
            with patch.object(review_ledger, "fcntl", None), patch.object(review_ledger, "msvcrt", None):
                with self.assertRaisesRegex(RuntimeError, "locking is unavailable"):
                    with audit_controller._report_publication_lock(Path(directory)):
                        pass

    def test_concurrent_report_publications_leave_pointer_and_convenience_copies_consistent(self) -> None:
        context = multiprocessing.get_context("spawn")
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_clean_run(run_dir)
            result_queue = context.Queue()
            processes = [
                context.Process(target=_report_worker, args=(str(run_dir), result_queue))
                for _ in range(2)
            ]
            for process in processes:
                process.start()
            outcomes = [result_queue.get(timeout=30) for _ in processes]
            for process in processes:
                process.join(30)
                self.assertEqual(process.exitcode, 0)
            self.assertEqual(
                [kind for kind, _ in outcomes],
                ["ok", "ok"],
                f"concurrent publication outcomes: {outcomes!r}",
            )
            pointer = self.read(run_dir / "report-current.json")
            generation = run_dir / "report-generations" / pointer["generation"]
            for name in ("AUDIT-REPORT.md", "issue-candidates.json", "report-bundle.json"):
                self.assertEqual((run_dir / name).read_bytes(), (generation / name).read_bytes())

    def test_report_aborts_if_review_state_changes_before_pointer_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_clean_run(run_dir)
            run_dir = run_dir.resolve()
            values = audit_controller.paths(run_dir)
            original_status = audit_controller.status_run
            calls = 0

            def changed_status(*args: object, **kwargs: object) -> dict:
                nonlocal calls
                calls += 1
                state = original_status(*args, **kwargs)
                if calls == 2:
                    return {**state, "review_state_digest": "0" * 64}
                return state

            with patch.object(audit_controller, "status_run", side_effect=changed_status):
                with self.assertRaisesRegex(ValueError, "changed during report publication"):
                    audit_controller.report_run(ROOT, run_dir)
            self.assertFalse(values["report_current"].exists())
            self.assertFalse(any(values["report_generations"].glob("generation-*")))

    def test_complete_report_cannot_return_success_with_stale_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_clean_run(run_dir)
            original = audit_controller._report_bundle_status

            def stale(*args: object, **kwargs: object) -> dict:
                result = original(*args, **kwargs)
                return {**result, "status": "STALE", "current": False, "message": "changed after commit"}

            with patch.object(audit_controller, "_report_bundle_status", side_effect=stale):
                with self.assertRaisesRegex(ValueError, "report publication is stale"):
                    audit_controller.report_run(ROOT, run_dir)

    def test_post_pointer_poc_source_change_rolls_back_previous_current_pointer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_finding_run(run_dir, ["High"])
            audit_controller.report_run(ROOT, run_dir)
            values = audit_controller.paths(run_dir)
            original_pointer = values["report_current"].read_bytes()
            original_details = values["finding_details"].read_bytes()
            source = next((run_dir / "poc").rglob("*.t.sol"))
            original_source = source.read_bytes()
            details = self.read(values["finding_details"])
            details["findings"][0]["description"] += " changed"
            values["finding_details"].write_text(json_text(details), encoding="utf-8")
            original_write = audit_controller.atomic_write_json

            def write_and_tamper(path: Path, value: dict) -> None:
                original_write(path, value)
                if path.resolve() == values["report_current"].resolve():
                    source.write_bytes(original_source + b"// changed after pointer\n")

            with patch.object(audit_controller, "atomic_write_json", side_effect=write_and_tamper):
                with self.assertRaisesRegex(ValueError, "report publication is stale"):
                    audit_controller.report_run(ROOT, run_dir)
            self.assertEqual(values["report_current"].read_bytes(), original_pointer)
            values["finding_details"].write_bytes(original_details)
            source.write_bytes(original_source)
            self.assertTrue(audit_controller._report_bundle_status(
                ROOT, values, self.read(values["manifest"]), self.read(values["audit_state"])
            )["current"])

    def test_post_pointer_failure_removes_first_report_pointer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_finding_run(run_dir, ["High"])
            values = audit_controller.paths(run_dir)
            source = next((run_dir / "poc").rglob("*.t.sol"))
            original_source = source.read_bytes()
            original_write = audit_controller.atomic_write_json

            def write_and_tamper(path: Path, value: dict) -> None:
                original_write(path, value)
                if path.resolve() == values["report_current"].resolve():
                    source.write_bytes(original_source + b"// changed after pointer\n")

            with patch.object(audit_controller, "atomic_write_json", side_effect=write_and_tamper):
                with self.assertRaisesRegex(ValueError, "report publication is stale"):
                    audit_controller.report_run(ROOT, run_dir)
            self.assertFalse(values["report_current"].exists())
            source.write_bytes(original_source)

    def test_tmp_generation_without_pointer_is_ignored_as_uncommitted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_clean_run(run_dir)
            values = audit_controller.paths(run_dir)
            staging = values["report_generations"] / ".tmp-crashed-publication"
            staging.mkdir(parents=True)
            manifest = self.read(values["manifest"])
            state = self.read(values["audit_state"])
            status = audit_controller._report_bundle_status(ROOT, values, manifest, state)
            self.assertEqual(status["status"], "ABSENT", status)
            self.assertFalse(status["current"])
            self.assertIn(staging.name, status["staging_artifacts"])

    def test_pointer_write_failure_after_rename_is_retryable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_clean_run(run_dir)
            run_dir = run_dir.resolve()
            values = audit_controller.paths(run_dir)
            original = audit_controller.atomic_write_json

            def fail_pointer(path: Path, value: dict) -> None:
                if path == values["report_current"]:
                    raise OSError("pointer write failure")
                original(path, value)

            with patch.object(audit_controller, "atomic_write_json", side_effect=fail_pointer):
                with self.assertRaisesRegex(OSError, "pointer write failure"):
                    audit_controller.report_run(ROOT, run_dir)
            self.assertFalse(values["report_current"].exists())
            self.assertFalse(any(values["report_generations"].glob("generation-*")))
            audit_controller.report_run(ROOT, run_dir)
            self.assertTrue(values["report_current"].exists())

    def test_orphan_generation_is_reported_but_not_current(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_clean_run(run_dir)
            audit_controller.report_run(ROOT, run_dir)
            values = audit_controller.paths(run_dir)
            orphan = values["report_generations"] / "generation-orphan"
            orphan.mkdir()
            manifest = self.read(values["manifest"])
            state = self.read(values["audit_state"])
            status = audit_controller._report_bundle_status(ROOT, values, manifest, state)
            self.assertTrue(status["current"], status)
            self.assertIn(orphan.name, status["orphaned_generations"])
            self.assertNotEqual(status["generation"], orphan.name)

    def test_identical_report_reuses_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_clean_run(run_dir)
            first = audit_controller.report_run(ROOT, run_dir)
            pointer = (run_dir / "report-current.json").read_bytes()
            pointer_value = json.loads(pointer)
            self.assertEqual(pointer_value["generation"], f"generation-{pointer_value['report_bundle_sha256']}")
            generations = sorted(path.name for path in (run_dir / "report-generations").glob("generation-*"))
            second = audit_controller.report_run(ROOT, run_dir)
            self.assertEqual((run_dir / "report-current.json").read_bytes(), pointer)
            self.assertEqual(
                sorted(path.name for path in (run_dir / "report-generations").glob("generation-*")),
                generations,
            )
            self.assertEqual(first["generation"], second["generation"])

    def test_changed_report_inputs_create_new_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_clean_run(run_dir)
            audit_controller.report_run(ROOT, run_dir)
            before = self.read(run_dir / "report-current.json")
            screen_path = run_dir / "reviews/screen-results.json"
            screen = self.read(screen_path)
            screen["results"][0].update(result="CANDIDATE", scope_complete=False, evidence=[])
            screen_path.write_text(json.dumps(screen, indent=2) + "\n", encoding="utf-8")
            result = audit_controller.report_run(ROOT, run_dir)
            after = self.read(run_dir / "report-current.json")
            self.assertNotEqual(after["generation"], before["generation"])
            self.assertEqual(result["generation"], after["generation"])

    def test_status_marks_medium_report_stale_after_severity_changes_to_high(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            _, _, severity, _, _ = self.prepare_finding_run(run_dir, ["Medium"], include_poc=False)
            audit_controller.report_run(ROOT, run_dir)
            severity["decisions"][next(iter(severity["decisions"]))]["severity"] = "High"
            (run_dir / "reviews/severity-decisions.json").write_text(json_text(severity), encoding="utf-8")
            result = audit_controller.status_run(ROOT, run_dir, emit=False, include_execution=True)
            self.assertFalse(result["report_generation"]["current"])
            self.assertEqual(result["report_generation"]["status"], "STALE")
            self.assertTrue(result["poc_policy"]["pending_ids"])

    def test_status_marks_high_report_stale_after_severity_changes_to_medium(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            _, _, severity, _, _ = self.prepare_finding_run(run_dir, ["High"])
            audit_controller.report_run(ROOT, run_dir)
            severity["decisions"][next(iter(severity["decisions"]))]["severity"] = "Medium"
            (run_dir / "reviews/severity-decisions.json").write_text(json_text(severity), encoding="utf-8")
            result = audit_controller.status_run(ROOT, run_dir, emit=False, include_execution=True)
            self.assertFalse(result["report_generation"]["current"])
            self.assertEqual(result["report_generation"]["status"], "STALE")

    def test_status_marks_report_stale_after_finding_details_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_finding_run(run_dir, ["Medium"], include_poc=False)
            audit_controller.report_run(ROOT, run_dir)
            details_path = run_dir / "reviews/finding-details.json"
            details = self.read(details_path)
            details["findings"][0]["description"] += " changed"
            details_path.write_text(json_text(details), encoding="utf-8")
            result = audit_controller.status_run(ROOT, run_dir, emit=False, include_execution=True)
            self.assertFalse(result["report_generation"]["current"])
            self.assertEqual(result["report_generation"]["status"], "STALE")

    def test_status_marks_report_stale_after_current_poc_artifact_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_finding_run(run_dir, ["High"])
            audit_controller.report_run(ROOT, run_dir)
            poc_path = run_dir / "reviews/poc-evidence.json"
            poc = self.read(poc_path)
            poc["findings"][0]["result_summary"] += " changed"
            poc_path.write_text(json_text(poc), encoding="utf-8")
            result = audit_controller.status_run(ROOT, run_dir, emit=False, include_execution=True)
            self.assertFalse(result["report_generation"]["current"])
            self.assertEqual(result["report_generation"]["status"], "STALE")

    def test_existing_content_address_with_mismatched_contents_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_clean_run(run_dir)
            audit_controller.report_run(ROOT, run_dir)
            pointer_path = run_dir / "report-current.json"
            pointer = self.read(pointer_path)
            bundle_path = run_dir / "report-generations" / pointer["generation"] / "report-bundle.json"
            bundle_path.write_bytes(b"{}\n")
            with self.assertRaisesRegex(ValueError, "mismatched contents"):
                audit_controller.report_run(ROOT, run_dir)
            self.assertEqual(self.read(pointer_path), pointer)

    def test_generation_rename_is_durable_before_pointer_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_clean_run(run_dir)
            run_dir = run_dir.resolve()
            events: list[str] = []
            original_json = audit_controller.atomic_write_json

            def durable(source: Path, destination: Path) -> bool:
                events.append("rename")
                source.replace(destination)
                return True

            def write_json(path: Path, value: dict) -> None:
                if path == run_dir / "report-current.json":
                    self.assertEqual(events, ["rename"])
                    events.append("pointer")
                original_json(path, value)

            with patch.object(audit_controller, "durable_replace_directory", side_effect=durable), patch.object(
                audit_controller, "atomic_write_json", side_effect=write_json
            ):
                audit_controller.report_run(ROOT, run_dir)
            self.assertEqual(events, ["rename", "pointer"])

    def test_internal_status_skips_report_resynthesis(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_clean_run(run_dir)
            audit_controller.report_run(ROOT, run_dir)
            with patch.object(audit_controller, "synthesize", side_effect=AssertionError("unexpected synthesis")):
                state = audit_controller.status_run(ROOT, run_dir, emit=False)
            self.assertEqual(state["status"], "COMPLETE_CLEAN")

    def test_reports_list_diagnoses_staging_and_orphans(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_clean_run(run_dir)
            audit_controller.report_run(ROOT, run_dir)
            values = audit_controller.paths(run_dir)
            first = self.read(values["report_current"])["generation"]
            screen = self.read(values["screen_results"])
            screen["results"][0].update(result="CANDIDATE", scope_complete=False, evidence=[])
            values["screen_results"].write_text(json.dumps(screen, indent=2) + "\n", encoding="utf-8")
            audit_controller.report_run(ROOT, run_dir)
            staging = values["report_generations"] / ".tmp-crashed-publication"
            staging.mkdir()
            result = audit_controller.reports_run(ROOT, run_dir, list_only=True)
            self.assertIn(first, result["orphaned_generations"])
            self.assertIn(staging.name, result["staging_artifacts"])

    def test_reports_gc_dry_run_and_apply_preserve_current_and_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_clean_run(run_dir)
            audit_controller.report_run(ROOT, run_dir)
            values = audit_controller.paths(run_dir)
            first = self.read(values["report_current"])["generation"]
            screen = self.read(values["screen_results"])
            screen["results"][0].update(result="CANDIDATE", scope_complete=False, evidence=[])
            values["screen_results"].write_text(json.dumps(screen, indent=2) + "\n", encoding="utf-8")
            audit_controller.report_run(ROOT, run_dir)
            current = self.read(values["report_current"])["generation"]
            staging = values["report_generations"] / ".tmp-crashed-publication"
            unknown = values["report_generations"] / "unrelated-directory"
            staging.mkdir()
            unknown.mkdir()
            dry_run = audit_controller.reports_run(ROOT, run_dir, gc=True, dry_run=True)
            self.assertIn(first, dry_run["gc"]["candidates"])
            self.assertIn(staging.name, dry_run["gc"]["candidates"])
            self.assertFalse(dry_run["gc"]["applied"])
            self.assertTrue(staging.exists())
            applied = audit_controller.reports_run(ROOT, run_dir, gc=True, apply=True)
            self.assertTrue(applied["gc"]["applied"])
            self.assertFalse(staging.exists())
            self.assertTrue(unknown.exists())
            self.assertTrue((values["report_generations"] / current).exists())

    def test_reports_gc_refuses_when_current_pointer_cannot_be_validated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_clean_run(run_dir)
            audit_controller.report_run(ROOT, run_dir)
            values = audit_controller.paths(run_dir)
            generations = values["report_generations"]
            pointer_path = values["report_current"]
            protected = self.read(pointer_path)["generation"]
            original_pointer = pointer_path.read_bytes()
            # A corrupted pointer must never let GC delete every verified generation.
            pointer_path.write_text("{not valid json\n", encoding="utf-8")
            before = sorted(path.name for path in generations.iterdir())
            with self.assertRaisesRegex(ValueError, "refusing report GC"):
                audit_controller.reports_run(ROOT, run_dir, gc=True, apply=True)
            self.assertEqual(sorted(path.name for path in generations.iterdir()), before)
            self.assertTrue((generations / protected).is_dir())
            # A valid pointer whose current generation directory is missing must also refuse GC.
            pointer_path.write_bytes(original_pointer)
            shutil.rmtree(generations / protected)
            with self.assertRaisesRegex(ValueError, "refusing report GC"):
                audit_controller.reports_run(ROOT, run_dir, gc=True, apply=True)
            # The dry-run preview is equally protected.
            with self.assertRaisesRegex(ValueError, "refusing report GC"):
                audit_controller.reports_run(ROOT, run_dir, gc=True, dry_run=True)
            # Listing remains a diagnostic command and does not raise.
            listed = audit_controller.reports_run(ROOT, run_dir, list_only=True)
            self.assertEqual(listed["stage"], "REPORTS")

    def test_legacy_top_level_outputs_require_explicit_republication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_clean_run(run_dir)
            values = audit_controller.paths(run_dir)
            values["report"].write_text("legacy report\n", encoding="utf-8")
            values["issue_candidates"].write_text("{}\n", encoding="utf-8")
            values["report_bundle"].write_text("{}\n", encoding="utf-8")
            manifest = self.read(values["manifest"])
            state = self.read(values["audit_state"])
            self.assertEqual(audit_controller._report_bundle_status(ROOT, values, manifest, state)["status"], "ABSENT")
            result = audit_controller.report_run(ROOT, run_dir)
            self.assertTrue(Path(result["report"]).is_file())
            self.assertTrue(values["report_current"].exists())

    def test_report_pointer_reporting_digest_is_bound_to_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_clean_run(run_dir)
            audit_controller.report_run(ROOT, run_dir)
            values = audit_controller.paths(run_dir)
            pointer = self.read(values["report_current"])
            pointer["reporting_inputs_sha256"] = "0" * 64
            values["report_current"].write_text(json_text(pointer), encoding="utf-8")
            status = audit_controller._report_bundle_status(
                ROOT, values, self.read(values["manifest"]), self.read(values["audit_state"])
            )
            self.assertFalse(status["current"])
            self.assertIn("reporting inputs do not match", status["message"])

    def test_failed_override_restores_all_authoring_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = root / "run"
            self.prepare_finding_run(run_dir, ["Medium"], include_poc=False)
            audit_controller.report_run(ROOT, run_dir)
            values = audit_controller.paths(run_dir)
            severity_override = root / "severity.json"
            details_override = root / "details.json"
            severity_override.write_bytes(values["severity_decisions"].read_bytes())
            details_override.write_bytes(values["finding_details"].read_bytes())
            before = {
                key: (values[key].exists(), values[key].read_bytes() if values[key].exists() else None)
                for key in ("severity_decisions", "finding_details", "poc_evidence", "report_current")
            }
            original = audit_controller.atomic_write_bytes

            def fail_after_first(path: Path, content: bytes) -> None:
                if path.resolve() == values["severity_decisions"].resolve():
                    original(path, content)
                elif path.resolve() == values["finding_details"].resolve():
                    raise OSError("details override failure")
                else:
                    original(path, content)

            with patch.object(audit_controller, "atomic_write_bytes", side_effect=fail_after_first):
                with self.assertRaisesRegex(OSError, "details override failure"):
                    audit_controller.report_run(ROOT, run_dir, severity_override, details_override)
            for key, (existed, content) in before.items():
                self.assertEqual(values[key].exists(), existed, key)
                if existed:
                    self.assertEqual(values[key].read_bytes(), content, key)
            manifest = self.read(values["manifest"])
            state = self.read(values["audit_state"])
            self.assertTrue(audit_controller._report_bundle_status(ROOT, values, manifest, state)["current"])

    def test_failed_high_to_medium_override_does_not_retire_current_poc(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = root / "run"
            _, _, severity, _, _ = self.prepare_finding_run(run_dir, ["High"])
            audit_controller.report_run(ROOT, run_dir)
            values = audit_controller.paths(run_dir)
            poc_before = values["poc_evidence"].read_bytes()
            severity["decisions"][next(iter(severity["decisions"]))]["severity"] = "Medium"
            severity_override = root / "severity-medium.json"
            details_override = root / "details.json"
            severity_override.write_bytes(json_text(severity).encode("utf-8"))
            details_override.write_bytes(values["finding_details"].read_bytes())
            original = audit_controller.atomic_write_bytes

            def fail_details(path: Path, content: bytes) -> None:
                if path.resolve() == values["finding_details"].resolve():
                    raise OSError("details override failure")
                original(path, content)

            with patch.object(audit_controller, "atomic_write_bytes", side_effect=fail_details):
                with self.assertRaisesRegex(OSError, "details override failure"):
                    audit_controller.report_run(ROOT, run_dir, severity_override, details_override)
            self.assertEqual(values["poc_evidence"].read_bytes(), poc_before)

    def test_e2e_confirmed_high_with_poc(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_finding_run(run_dir, ["High"])
            result = audit_controller.report_run(ROOT, run_dir)
            generation = Path(result["report"]).parent
            source = next((run_dir / "poc").rglob("*.t.sol"))
            snapshot = generation / "poc-sources" / f"{hashlib.sha256(source.read_bytes()).hexdigest()}.sol"
            self.assertEqual(snapshot.read_bytes(), source.read_bytes())
            source.unlink()
            listed = audit_controller.reports_run(ROOT, run_dir, list_only=True)
            current = next(item for item in listed["generations"] if item["current"])
            self.assertTrue(current["verified"], current)

    def test_verify_poc_is_explicit_and_uses_structured_argv(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_finding_run(run_dir, ["High"])
            trusted_forge = Path(directory) / "trusted-forge"
            trusted_forge.write_bytes(b"trusted forge")
            trusted_forge.chmod(trusted_forge.stat().st_mode | stat.S_IXUSR)
            completed = subprocess.CompletedProcess(
                ["forge", "test"], 0, stdout=b"passed", stderr=b""
            )
            real_run = audit_controller.subprocess.run

            def run_command(command, **kwargs):
                if command and Path(command[0]) == trusted_forge:
                    return completed
                return real_run(command, **kwargs)

            with patch.object(audit_controller, "_trusted_executable", return_value=trusted_forge), patch.object(
                audit_controller.subprocess, "run", side_effect=run_command
            ) as runner:
                result = audit_controller.verify_poc(ROOT, run_dir)
            self.assertEqual(result["state"], "PASSED")
            receipt = self.read(run_dir / "reviews/poc-verification.json")
            self.assertEqual(receipt["state"], "PASSED")
            self.assertNotIn("stdout", receipt)
            call = runner.call_args
            self.assertFalse(call.kwargs["shell"])
            # Recorded commands run inside a disposable copy of the build tree, never in the audited tree.
            build_root = Path(self.read(run_dir / "routing/manifest.json")["feature_map"]["recon_context"]["build_root"])
            workspace = Path(call.kwargs["cwd"])
            self.assertNotEqual(workspace, build_root, "verify-poc must not run inside the authoritative build root")
            self.assertTrue(workspace.parent.name.startswith(".verify-poc-"), str(workspace))
            self.assertEqual(workspace.name, "project")
            self.assertFalse(workspace.exists(), "isolated PoC workspace must be removed after verification")

    def test_reports_cli_defaults_gc_to_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_clean_run(run_dir)
            listed = self.run_cli("scripts/audit_run.py", "reports", "--run-dir", str(run_dir), "--list")
            self.assertEqual(listed.returncode, 0, listed.stderr)
            self.assertEqual(json.loads(listed.stdout)["stage"], "REPORTS")
            preview = self.run_cli("scripts/audit_run.py", "reports", "--run-dir", str(run_dir), "--gc", "--dry-run")
            self.assertEqual(preview.returncode, 0, preview.stderr)
            self.assertTrue(json.loads(preview.stdout)["gc"]["dry_run"])

    def test_first_report_failure_does_not_create_fake_current_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_clean_run(run_dir)
            values = audit_controller.paths(run_dir)
            original_atomic_text = audit_controller.atomic_write_text

            def fail_report(path: Path, content: str) -> None:
                if path.name == "AUDIT-REPORT.md":
                    raise OSError("first report write failure")
                original_atomic_text(path, content)

            with patch.object(audit_controller, "atomic_write_text", side_effect=fail_report):
                with self.assertRaisesRegex(OSError, "first report write failure"):
                    audit_controller.report_run(ROOT, run_dir)
            self.assertFalse(values["report_current"].exists())
            self.assertFalse(any(values["report_generations"].glob("generation-*")))
            audit_controller.report_run(ROOT, run_dir)
            self.assertTrue(values["report_current"].exists())

    def test_bundle_rederivation_accepts_official_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_clean_run(run_dir)
            audit_controller.report_run(ROOT, run_dir)
            values = audit_controller.paths(run_dir)
            manifest = self.read(values["manifest"])
            state = self.read(values["audit_state"])
            status = audit_controller._report_bundle_status(ROOT, values, manifest, state)
            self.assertEqual(status["status"], "CURRENT", status)
            self.assertTrue(status["generation"])

    def test_bundle_rejects_coordinated_report_and_marker_edit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_clean_run(run_dir)
            audit_controller.report_run(ROOT, run_dir)
            values = audit_controller.paths(run_dir)
            manifest = self.read(values["manifest"])
            state = self.read(values["audit_state"])
            pointer = self.read(values["report_current"])
            generation = values["report_generations"] / pointer["generation"]
            report_path = generation / "AUDIT-REPORT.md"
            report_path.write_text(report_path.read_text(encoding="utf-8") + "tampered\n", encoding="utf-8")
            bundle_path = generation / "report-bundle.json"
            bundle = self.read(bundle_path)
            bundle["report_sha256"] = hashlib.sha256(report_path.read_bytes()).hexdigest()
            bundle_path.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
            pointer["report_bundle_sha256"] = hashlib.sha256(bundle_path.read_bytes()).hexdigest()
            values["report_current"].write_text(json.dumps(pointer, indent=2) + "\n", encoding="utf-8")
            status = audit_controller._report_bundle_status(ROOT, values, manifest, state)
            self.assertEqual(status["status"], "STALE", status)

    def test_init_failures_leave_no_partial_run_and_allow_safe_retry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            for failure_args in (
                ["--solc", str(parent / "missing-solc")],
                ["--domain", "evm-audit-does-not-exist"],
            ):
                run_dir = parent / ("run-" + str(len(list(parent.iterdir()))))
                result = self.run_cli(
                    "scripts/audit_run.py", "init", str(EMPTY_TARGET), "--run-dir", str(run_dir),
                    "--audit-root", str(EMPTY_TARGET), *failure_args,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(run_dir.exists())
                result = self.run_cli(
                    "scripts/audit_run.py", "init", str(EMPTY_TARGET), "--run-dir", str(run_dir),
                    "--audit-root", str(EMPTY_TARGET), "--domain", "evm-audit-general",
                )
                self.assertEqual(result.returncode, 0, result.stderr)

            existing = parent / "existing"
            existing.mkdir()
            keep = existing / "keep.txt"
            keep.write_text("user content", encoding="utf-8")
            result = self.run_cli(
                "scripts/audit_run.py", "init", str(EMPTY_TARGET), "--run-dir", str(existing),
                "--audit-root", str(EMPTY_TARGET), "--domain", "evm-audit-general",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(keep.read_text(encoding="utf-8"), "user content")

    def test_sanitized_init_leaves_no_temporary_trees_in_authoritative_locations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            project = parent / "repo"
            (project).mkdir()
            (project / "Target.sol").write_text("contract Target {}\n", encoding="utf-8")
            (project / ".git").write_text("gitdir: elsewhere\n", encoding="utf-8")
            run_dir = parent / "run"
            result = self.run_cli(
                "scripts/audit_run.py",
                "init",
                str(project / "Target.sol"),
                "--run-dir",
                str(run_dir),
                "--audit-root",
                str(project / "Target.sol"),
                "--domain",
                "evm-audit-general",
                "--source-trust",
                "UNKNOWN",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((run_dir / "routing/manifest.json").is_file())
            leftovers = [
                str(path)
                for path in list(project.rglob("*.sanitized-source"))
                + list(parent.glob("*.sanitized-source"))
                + list(project.rglob("*.init-*"))
                + list(parent.glob("*.publish-*"))
                + list(project.rglob("evm-audit-init-*"))
            ]
            self.assertEqual(leftovers, [])

    def test_init_defaults_to_project_local_output_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = (Path(directory) / "protocol").resolve()
            (project / "src").mkdir(parents=True)
            (project / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            (project / "src" / "Protocol.sol").write_text(
                "contract Protocol {}\n", encoding="utf-8"
            )
            output = project / ".evm-auditor-work"
            result = self.run_cli(
                "scripts/audit_run.py",
                "init",
                str(project),
                "--domain",
                "evm-audit-general",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["run_dir"], str(output))
            self.assertEqual(payload["output_dir"], str(output))
            self.assertEqual(payload["report_path"], str(output / "AUDIT-REPORT.md"))
            self.assertTrue((output / "routing/manifest.json").is_file())
            layout = json.loads((output / "config/run-layout.json").read_text(encoding="utf-8"))
            self.assertEqual(layout["location_mode"], "PROJECT_LOCAL")
            self.assertEqual(layout["workspace_root"], str(project))
            self.assertEqual(layout["output_root"], str(output))
            # The existing-run alias addresses the same bundle.
            status = self.run_cli(
                "scripts/audit_run.py", "status", "--output-dir", str(output)
            )
            self.assertEqual(status.returncode, 0, status.stderr)
            self.assertEqual(json.loads(status.stdout)["location"]["run_dir"], str(output))
            # Runtime views render inside the managed subtree without
            # triggering the stale-target gate.
            self.assertFalse(list(project.glob("*.verify-poc-*")))
            followup = self.run_cli(
                "scripts/audit_run.py", "next", "--output-dir", str(output)
            )
            self.assertEqual(followup.returncode, 0, followup.stderr)

    def test_init_supports_relative_and_absolute_custom_output_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = (Path(directory) / "protocol").resolve()
            (project / "src").mkdir(parents=True)
            (project / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            (project / "src" / "Protocol.sol").write_text(
                "contract Protocol {}\n", encoding="utf-8"
            )
            relative = self.run_cli(
                "scripts/audit_run.py",
                "init",
                str(project),
                "--domain",
                "evm-audit-general",
                "--output-dir",
                "security/audit-001",
            )
            self.assertEqual(relative.returncode, 0, relative.stderr)
            custom = project / "security" / "audit-001"
            self.assertEqual(json.loads(relative.stdout)["output_dir"], str(custom))
            self.assertTrue((custom / "routing/manifest.json").is_file())
            self.assertEqual(
                json.loads((custom / "config/run-layout.json").read_text(encoding="utf-8"))["location_mode"],
                "PROJECT_LOCAL",
            )
            external = (Path(directory) / "external-audit").resolve()
            absolute = self.run_cli(
                "scripts/audit_run.py",
                "init",
                str(project),
                "--domain",
                "evm-audit-general",
                "--output-dir",
                str(external),
            )
            self.assertEqual(absolute.returncode, 0, absolute.stderr)
            self.assertEqual(json.loads(absolute.stdout)["output_dir"], str(external))
            self.assertEqual(
                json.loads((external / "config/run-layout.json").read_text(encoding="utf-8"))["location_mode"],
                "EXTERNAL",
            )

    def test_init_rejects_conflicting_and_unsafe_output_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = (Path(directory) / "protocol").resolve()
            (project / "src").mkdir(parents=True)
            (project / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            (project / "src" / "Protocol.sol").write_text(
                "contract Protocol {}\n", encoding="utf-8"
            )
            common = (
                "scripts/audit_run.py",
                "init",
                str(project),
                "--domain",
                "evm-audit-general",
            )
            both = self.run_cli(*common, "--output-dir", "a", "--run-dir", "b")
            self.assertNotEqual(both.returncode, 0)
            self.assertIn("not allowed with argument --output-dir", both.stderr)
            project_root = self.run_cli(*common, "--output-dir", ".")
            self.assertNotEqual(project_root.returncode, 0)
            self.assertIn("build root", project_root.stderr)
            self.assertFalse((project / "routing").exists())

    def test_poc_workspace_excludes_the_managed_run_subtree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = (Path(directory) / "protocol").resolve()
            (project / "src").mkdir(parents=True)
            (project / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            (project / "src" / "Protocol.sol").write_text(
                "contract Protocol {}\n", encoding="utf-8"
            )
            run_dir = project / ".evm-auditor-work"
            (run_dir / "poc").mkdir(parents=True)
            (run_dir / "poc" / "Exploit.t.sol").write_text(
                "contract ExploitTest {}\n", encoding="utf-8"
            )
            (run_dir / "AUDIT-REPORT.md").write_text("# report\n", encoding="utf-8")
            workspace = audit_controller._isolated_poc_workspace(project, run_dir)
            try:
                self.assertFalse((workspace / ".evm-auditor-work").exists())
                self.assertTrue((workspace / "src" / "Protocol.sol").is_file())
                # The disposable workspace never lands inside the audited tree.
                self.assertNotEqual(workspace.parent, project)
                self.assertEqual(list(project.glob(".verify-poc-*")), [])
            finally:
                shutil.rmtree(workspace.parent, ignore_errors=True)

    def test_e2e_clean_audit(self) -> None:
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
                "--domain",
                "evm-audit-general",
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            self.assertIn("DOMAIN_CONTEXT", result.stdout)
            self.assertEqual(
                json.loads(result.stdout)["next"]["recommended_execution"],
                {"provider": "codex", "model": "gpt-5.6-luna", "reasoning_effort": "max"},
            )
            result = self.run_cli("scripts/audit_run.py", "next", "--run-dir", str(run_dir))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("DOMAIN_CONTEXT", result.stdout)
            self.assertEqual(json.loads(result.stdout)["progress"]["label"], "Context Analysis")
            context_path = run_dir / "reviews/domain-context.json"
            context = self.read(context_path)
            for requirements in context["domains"].values():
                for item in requirements.values():
                    item.update(
                        status="KNOWN",
                        value="fixture",
                        evidence=[{"kind": "scope", "location": "fixture", "reason": "known context"}],
                    )
            context_path.write_text(json.dumps(context, indent=2) + "\n", encoding="utf-8")

            result = self.run_cli("scripts/audit_run.py", "next", "--run-dir", str(run_dir))
            self.assertEqual(result.returncode, 0, result.stderr)
            screen_payload = json.loads(result.stdout)
            self.assertEqual(screen_payload["progress"]["step"], 3)
            self.assertEqual(screen_payload["progress"]["label"], "Initial Review")
            screen_path = run_dir / "reviews/screen-results.json"
            screen = self.read(screen_path)
            for item in screen["results"]:
                item.update(
                    result="NOT_APPLICABLE_CONFIRMED",
                    scope_complete=True,
                    evidence=[
                        {"kind": "scope", "location": "fixture", "reason": "complete scope"},
                        {"kind": "inheritance", "location": "fixture", "reason": "trigger absent"},
                    ],
                )
            screen_path.write_text(json.dumps(screen, indent=2) + "\n", encoding="utf-8")

            result = self.run_cli("scripts/audit_run.py", "next", "--run-dir", str(run_dir))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("COMPLETE_CLEAN", result.stdout)
            report_payload = json.loads(result.stdout)
            self.assertEqual(report_payload["progress"]["step"], 6)
            self.assertEqual(report_payload["progress"]["label"], "Final Report")
            self.assertEqual(
                report_payload["recommended_execution"],
                {"provider": "codex", "model": "gpt-5.6-luna", "reasoning_effort": "max"},
            )
            manifest = self.read(run_dir / "routing/manifest.json")
            state = self.read(run_dir / "audit-state.json")
            identity = {
                "schema_version": 2,
                "routing_snapshot_id": manifest["routing_snapshot_id"],
                "review_state_digest": state["review_state_digest"],
                **{
                    key: manifest["audit_context"][key]
                    for key in ("registry_sha256", "source_digest", "compilation_input_digest")
                },
            }
            severity_path = run_dir / "severity-decisions.json"
            severity_path.write_text(json.dumps({**identity, "decisions": {}}) + "\n", encoding="utf-8")
            details_path = run_dir / "finding-details.json"
            details_path.write_text(json.dumps({**identity, "findings": []}) + "\n", encoding="utf-8")
            result = self.run_cli(
                "scripts/audit_run.py",
                "report",
                "--run-dir",
                str(run_dir),
                "--severity-decisions",
                str(severity_path),
                "--finding-details",
                str(details_path),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report_command = json.loads(result.stdout)
            self.assertEqual(report_command["progress"]["step"], 6)
            self.assertEqual(report_command["progress"]["label"], "Final Report")
            report = (run_dir / "AUDIT-REPORT.md").read_text(encoding="utf-8")
            self.assertIn("COMPLETE_CLEAN", report)
            self.assertTrue((run_dir / "issue-candidates.json").exists())
            previous_report = (run_dir / "AUDIT-REPORT.md").read_text(encoding="utf-8")
            previous_issues = (run_dir / "issue-candidates.json").read_text(encoding="utf-8")
            bad_severity = run_dir / "bad-severity.json"
            bad_severity.write_text("{\n", encoding="utf-8")
            result = self.run_cli(
                "scripts/audit_run.py",
                "report",
                "--run-dir",
                str(run_dir),
                "--severity-decisions",
                str(bad_severity),
                "--finding-details",
                str(details_path),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((run_dir / "AUDIT-REPORT.md").read_text(encoding="utf-8"), previous_report)
            self.assertEqual((run_dir / "issue-candidates.json").read_text(encoding="utf-8"), previous_issues)
            result = self.run_cli(
                "scripts/audit_run.py",
                "report",
                "--run-dir",
                str(run_dir),
                "--severity-decisions",
                str(severity_path),
                "--finding-details",
                str(details_path),
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_invalid_optional_code_index_does_not_block_authoritative_status(self) -> None:
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
                "--domain",
                "evm-audit-general",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            code_index = run_dir / "recon/code-index.json"
            original = code_index.read_text(encoding="utf-8")
            result = self.run_cli("scripts/audit_run.py", "status", "--run-dir", str(run_dir))
            self.assertEqual(result.returncode, 0, result.stderr)
            current = json.loads(result.stdout)
            self.assertEqual(current["navigation"]["status"], "CURRENT")
            authoritative_status = current["status"]
            for invalid in ({"broken": True}, {**json.loads(original), "source_digest": "0" * 64}):
                code_index.write_text(json.dumps(invalid) + "\n", encoding="utf-8")
                result = self.run_cli("scripts/audit_run.py", "status", "--run-dir", str(run_dir))
                self.assertEqual(result.returncode, 0, result.stderr)
                payload = json.loads(result.stdout)
                self.assertEqual(payload["navigation"]["status"], "TAMPERED")
                self.assertFalse(payload["navigation"]["available"])
                self.assertEqual(payload["status"], authoritative_status)
                self.assertNotEqual(payload["status"], "INVALID_SNAPSHOT")
            code_index.write_text(original, encoding="utf-8")
            result = self.run_cli("scripts/audit_run.py", "status", "--run-dir", str(run_dir))
            self.assertEqual(json.loads(result.stdout)["navigation"]["status"], "CURRENT")
            code_index.unlink()
            result = self.run_cli("scripts/audit_run.py", "status", "--run-dir", str(run_dir))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["navigation"]["status"], "MISSING")

    def test_unbound_missing_code_index_is_reported_absent(self) -> None:
        _, _, _, manifest = build_manifest()
        with tempfile.TemporaryDirectory() as directory:
            values = {"code_index": Path(directory) / "recon/code-index.json"}
            status = audit_controller._optional_code_index_status(ROOT, values, manifest)
        self.assertEqual(status["status"], "ABSENT")
        self.assertFalse(status["available"])

    def test_finding_report_snapshots_inputs_and_requires_both_for_current_bundle(self) -> None:
        registry, _, _, manifest = build_manifest()
        screen = screen_results_template(manifest)
        candidate_id = screen["results"][0]["canonical_id"]
        evidence = [
            {"kind": "scope", "location": "fixture", "reason": "complete scope"},
            {"kind": "inheritance", "location": "fixture", "reason": "screen disposition"},
        ]
        for item in screen["results"]:
            if item["canonical_id"] == candidate_id:
                item.update(result="CANDIDATE", scope_complete=False, evidence=[])
            else:
                item.update(result="NOT_APPLICABLE_CONFIRMED", scope_complete=True, evidence=evidence)
        domain_context = domain_context_template(manifest)
        for requirements in domain_context["domains"].values():
            for item in requirements.values():
                item.update(status="KNOWN", value="fixture", evidence=[evidence[0]])
        context = {**manifest["audit_context"], "routing_snapshot_id": manifest["routing_snapshot_id"]}
        route = next(item for item in manifest["selected"] if item["canonical_id"] == candidate_id)
        check = next(item for item in registry["checks"] if item["canonical_id"] == candidate_id)
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            values = audit_controller.paths(run_dir)
            values["manifest"].parent.mkdir(parents=True)
            values["domain_context"].parent.mkdir(parents=True, exist_ok=True)
            values["context"].write_text(json.dumps(context) + "\n", encoding="utf-8")
            values["manifest"].write_text(json.dumps(manifest) + "\n", encoding="utf-8")
            values["domain_context"].write_text(json.dumps(domain_context) + "\n", encoding="utf-8")
            values["screen_results"].write_text(json.dumps(screen) + "\n", encoding="utf-8")
            deep = {
                "record_type": "review",
                "schema_version": 7,
                "canonical_id": candidate_id,
                "owner_domain": route["owner_domain"],
                "check_body_hash": check_body_hash(check),
                "review_stage": "DEEP_REVIEW",
                "status": "SUSPICIOUS",
                "code_path": "fixture entry",
                "unresolved_reason": "proof pending",
                "evidence": [{"kind": "manual", "location": "fixture", "reason": "deep review"}],
            }
            ledger = run_dir / "reviews/review-evm-audit-general.jsonl"
            append(ledger, manifest, deep, registry, {candidate_id}, domain_context=domain_context, screen_results=screen)
            proof = {
                **deep,
                "review_stage": "PROOF",
                "status": "CONFIRMED",
                "applicability": "APPLICABLE - fixture",
                "preconditions": "fixture state",
                "exploitability": "fixture path is reachable",
                "impact": "fixture impact",
                "proof": "deterministic fixture trace",
                "evidence": [{"kind": "trace", "location": "fixture", "reason": "proof trace"}],
            }
            append(ledger, manifest, proof, registry, {candidate_id}, domain_context=domain_context, screen_results=screen)
            state = audit_controller.status_run(ROOT, run_dir, emit=False)
            self.assertEqual(state["status"], "COMPLETE_WITH_FINDINGS")
            identity = {
                "schema_version": 2,
                "routing_snapshot_id": manifest["routing_snapshot_id"],
                "review_state_digest": state["review_state_digest"],
                **{
                    key: manifest["audit_context"][key]
                    for key in ("registry_sha256", "source_digest", "compilation_input_digest")
                },
            }
            severity = {
                **identity,
                "decisions": {
                    candidate_id: {
                        "severity": "Medium",
                        "rationale": "fixture proof",
                        "dimensions": {
                            "impact": "fund_loss", "exploitability": "permissionless", "privileges": "none",
                            "capital_required": "none", "repeatability": "one_shot", "user_interaction": "none",
                            "loss_bound": "single_user", "protocol_exposure": "single_position", "recoverability": "irreversible",
                        },
                    }
                },
            }
            details = {
                **identity,
                "findings": [{
                    "canonical_id": candidate_id,
                    "location": "Fixture.sol:1",
                    "description": "fixture finding",
                    "recommendation": "fix fixture",
                }],
            }
            severity_path = run_dir / "external-severity.json"
            details_path = run_dir / "external-details.json"
            severity_path.write_text(json.dumps(severity, indent=2) + "\n", encoding="utf-8")
            details_path.write_text(json.dumps(details, indent=2) + "\n", encoding="utf-8")
            report = audit_controller.report_run(ROOT, run_dir, severity_path, details_path)
            self.assertTrue(report["complete"])
            self.assertEqual(values["report_input_severity"].read_bytes(), severity_path.read_bytes())
            self.assertEqual(values["report_input_details"].read_bytes(), details_path.read_bytes())
            bundle_status = audit_controller._report_bundle_status(ROOT, values, manifest, state)
            self.assertTrue(bundle_status["current"], bundle_status)
            generation = values["report_generations"] / json.loads(values["report_current"].read_bytes())["generation"]
            details_snapshot = generation / "finding-details.json"
            details_bytes = details_snapshot.read_bytes()
            details_snapshot.write_bytes(details_bytes + b"\n")
            self.assertFalse(audit_controller._report_bundle_status(ROOT, values, manifest, state)["current"])
            details_snapshot.write_bytes(details_bytes)
            self.assertTrue(audit_controller._report_bundle_status(ROOT, values, manifest, state)["current"])
            details_snapshot.unlink()
            self.assertFalse(audit_controller._report_bundle_status(ROOT, values, manifest, state)["current"])

    def test_failed_finding_report_preserves_previous_current_generation(self) -> None:
        registry, _, _, manifest = build_manifest()
        screen = screen_results_template(manifest)
        candidate_id = screen["results"][0]["canonical_id"]
        evidence = [
            {"kind": "scope", "location": "fixture", "reason": "complete scope"},
            {"kind": "inheritance", "location": "fixture", "reason": "screen disposition"},
        ]
        for item in screen["results"]:
            is_candidate = item["canonical_id"] == candidate_id
            item.update(
                result="CANDIDATE" if is_candidate else "NOT_APPLICABLE_CONFIRMED",
                scope_complete=not is_candidate,
                evidence=[] if is_candidate else evidence,
            )
        domain_context = domain_context_template(manifest)
        for requirements in domain_context["domains"].values():
            for item in requirements.values():
                item.update(status="KNOWN", value="fixture", evidence=[evidence[0]])
        context = {**manifest["audit_context"], "routing_snapshot_id": manifest["routing_snapshot_id"]}
        route = next(item for item in manifest["selected"] if item["canonical_id"] == candidate_id)
        check = next(item for item in registry["checks"] if item["canonical_id"] == candidate_id)
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            values = audit_controller.paths(run_dir)
            values["manifest"].parent.mkdir(parents=True)
            values["domain_context"].parent.mkdir(parents=True, exist_ok=True)
            values["context"].write_text(json.dumps(context) + "\n", encoding="utf-8")
            values["manifest"].write_text(json.dumps(manifest) + "\n", encoding="utf-8")
            values["domain_context"].write_text(json.dumps(domain_context) + "\n", encoding="utf-8")
            values["screen_results"].write_text(json.dumps(screen) + "\n", encoding="utf-8")
            deep = {
                "record_type": "review", "schema_version": 7, "canonical_id": candidate_id,
                "owner_domain": route["owner_domain"], "check_body_hash": check_body_hash(check),
                "review_stage": "DEEP_REVIEW", "status": "SUSPICIOUS", "code_path": "fixture entry",
                "unresolved_reason": "proof pending", "evidence": [{"kind": "manual", "location": "fixture", "reason": "deep review"}],
            }
            ledger = run_dir / "reviews/review-evm-audit-general.jsonl"
            append(ledger, manifest, deep, registry, {candidate_id}, domain_context=domain_context, screen_results=screen)
            proof = {
                **deep, "review_stage": "PROOF", "status": "CONFIRMED",
                "applicability": "APPLICABLE - fixture", "preconditions": "fixture state",
                "exploitability": "fixture path is reachable", "impact": "fixture impact",
                "proof": "deterministic fixture trace", "evidence": [{"kind": "trace", "location": "fixture", "reason": "proof trace"}],
            }
            append(ledger, manifest, proof, registry, {candidate_id}, domain_context=domain_context, screen_results=screen)
            state = audit_controller.status_run(ROOT, run_dir, emit=False)
            identity = {
                "schema_version": 2, "routing_snapshot_id": manifest["routing_snapshot_id"],
                "review_state_digest": state["review_state_digest"],
                **{key: manifest["audit_context"][key] for key in ("registry_sha256", "source_digest", "compilation_input_digest")},
            }
            severity_path = run_dir / "severity.json"
            severity_path.write_text(json.dumps({**identity, "decisions": {
                candidate_id: {
                    "severity": "Medium", "rationale": "fixture proof", "dimensions": {
                        "impact": "fund_loss", "exploitability": "permissionless", "privileges": "none",
                        "capital_required": "none", "repeatability": "one_shot", "user_interaction": "none",
                        "loss_bound": "single_user", "protocol_exposure": "single_position", "recoverability": "irreversible",
                    },
                },
            }}) + "\n", encoding="utf-8")
            details_path = run_dir / "details.json"
            details_path.write_text(json.dumps({**identity, "findings": [{
                "canonical_id": candidate_id, "location": "Fixture.sol:1", "description": "fixture finding", "recommendation": "fix fixture",
            }]}) + "\n", encoding="utf-8")
            prepared = audit_controller.prepare_report_publication(ROOT, run_dir, severity_path, details_path)
            audit_controller.commit_report_publication(ROOT, run_dir, prepared)

            def snapshot() -> tuple[bytes, dict[Path, bytes]]:
                pointer = values["report_current"].read_bytes()
                generation = values["report_generations"] / json.loads(pointer)["generation"]
                return pointer, {
                    path.relative_to(generation): path.read_bytes()
                    for path in generation.iterdir()
                    if path.is_file()
                }

            failure_cases = (
                ("severity", "bytes", "severity-decisions.json"),
                ("details", "bytes", "finding-details.json"),
                ("report", "text", "AUDIT-REPORT.md"),
                ("issues", "json", "issue-candidates.json"),
                ("bundle", "json", "report-bundle.json"),
            )
            for name, writer, filename in failure_cases:
                with self.subTest(boundary=name):
                    original_pointer, original_generation = snapshot()
                    if writer == "bytes":
                        original = audit_controller.atomic_write_bytes

                        def fail(path: Path, content: bytes, *, original=original, filename=filename) -> None:
                            if path.name == filename:
                                raise OSError(f"{name} write failure")
                            original(path, content)

                        context_manager = patch.object(audit_controller, "atomic_write_bytes", side_effect=fail)
                    elif writer == "text":
                        original = audit_controller.atomic_write_text

                        def fail(path: Path, content: str, *, original=original, filename=filename) -> None:
                            if path.name == filename:
                                raise OSError(f"{name} write failure")
                            original(path, content)

                        context_manager = patch.object(audit_controller, "atomic_write_text", side_effect=fail)
                    else:
                        original = audit_controller.atomic_write_json

                        def fail(path: Path, value: dict, *, original=original, filename=filename) -> None:
                            if path.name == filename:
                                raise OSError(f"{name} write failure")
                            original(path, value)

                        context_manager = patch.object(audit_controller, "atomic_write_json", side_effect=fail)
                    with context_manager:
                        with self.assertRaisesRegex(OSError, f"{name} write failure"):
                            audit_controller.commit_report_publication(ROOT, run_dir, prepared)
                    self.assertEqual(values["report_current"].read_bytes(), original_pointer)
                    self.assertEqual(snapshot()[1], original_generation)
                    self.assertTrue(audit_controller._report_bundle_status(ROOT, values, manifest, state)["current"])

    def test_report_rederives_state_after_current_ledger_is_removed(self) -> None:
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
                "--domain",
                "evm-audit-general",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            context_path = run_dir / "reviews/domain-context.json"
            context = self.read(context_path)
            for requirements in context["domains"].values():
                for item in requirements.values():
                    item.update(
                        status="KNOWN",
                        value="fixture",
                        evidence=[{"kind": "scope", "location": "fixture", "reason": "known context"}],
                    )
            context_path.write_text(json.dumps(context, indent=2) + "\n", encoding="utf-8")

            result = self.run_cli("scripts/audit_run.py", "next", "--run-dir", str(run_dir))
            self.assertEqual(result.returncode, 0, result.stderr)
            screen_path = run_dir / "reviews/screen-results.json"
            screen = self.read(screen_path)
            candidate = screen["results"][0]
            candidate.update(result="CANDIDATE", scope_complete=False, evidence=[])
            evidence = [
                {"kind": "scope", "location": "fixture", "reason": "complete scope"},
                {"kind": "inheritance", "location": "fixture", "reason": "screen disposition"},
            ]
            for item in screen["results"][1:]:
                item.update(result="NOT_APPLICABLE_CONFIRMED", scope_complete=True, evidence=evidence)
            screen_path.write_text(json.dumps(screen, indent=2) + "\n", encoding="utf-8")

            result = self.run_cli("scripts/audit_run.py", "next", "--run-dir", str(run_dir))
            self.assertIn("DEEP_REVIEW", result.stdout)
            deep_payload = json.loads(result.stdout)
            self.assertEqual(deep_payload["progress"]["step"], 4)
            self.assertEqual(deep_payload["progress"]["label"], "Deep Audit")
            self.assertIn("Deep Audit candidates remain", deep_payload["progress"]["summary"])
            self.assertEqual(
                deep_payload["recommended_execution"],
                {"provider": "codex", "model": "gpt-5.6-luna", "reasoning_effort": "max"},
            )
            manifest = self.read(run_dir / "routing/manifest.json")
            route = next(item for item in manifest["selected"] if item["canonical_id"] == candidate["canonical_id"])
            record = {
                "record_type": "review",
                "schema_version": 7,
                "canonical_id": candidate["canonical_id"],
                "owner_domain": route["owner_domain"],
                "check_body_hash": route["check_body_hash"],
                "review_stage": "DEEP_REVIEW",
                "status": "REVIEWED_SAFE",
                "applicability": "APPLICABLE - fixture",
                "code_path": "fixture entry",
                "preconditions": "fixture state",
                "exploitability": "guard holds",
                "impact": "none",
                "proof": "fixture invariant",
                "preserved_invariant": "fixture invariant",
                "evidence": [{"kind": "test", "location": "fixture", "reason": "test evidence"}],
            }
            ledger = run_dir / "reviews/review-evm-audit-general.jsonl"
            append(
                ledger,
                manifest,
                record,
                self.read(ROOT / "data/canonical-checks.json"),
                {candidate["canonical_id"]},
                domain_context=context,
                screen_results=screen,
            )

            result = self.run_cli("scripts/audit_run.py", "next", "--run-dir", str(run_dir))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("COMPLETE_CLEAN", result.stdout)
            result = self.run_cli("scripts/audit_run.py", "report", "--run-dir", str(run_dir))
            self.assertEqual(result.returncode, 0, result.stderr)
            ledger.unlink()

            result = self.run_cli("scripts/audit_run.py", "report", "--run-dir", str(run_dir))
            self.assertNotEqual(result.returncode, 0)
            state = self.read(run_dir / "audit-state.json")
            self.assertEqual(state["status"], "INCOMPLETE_REVIEW")
            self.assertFalse(state["complete"])
            report = (run_dir / "AUDIT-REPORT.md").read_text(encoding="utf-8")
            self.assertIn("# INCOMPLETE AUDIT", report)
            self.assertNotIn("COMPLETE_CLEAN", report)

    def test_e2e_recon_to_report(self) -> None:
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
                "--domain",
                "evm-audit-general",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            poc_path = run_dir / "poc/RetainedPoC.t.sol"
            poc_source = """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

contract RetainedPoC {
    function proof() external pure returns (uint256) {
        return 1;
    }
}
"""
            poc_path.parent.mkdir(parents=True)
            poc_path.write_text(poc_source, encoding="utf-8")
            poc_location = poc_path.relative_to(run_dir).as_posix()
            context_path = run_dir / "reviews/domain-context.json"
            context = self.read(context_path)
            for requirements in context["domains"].values():
                for item in requirements.values():
                    item.update(
                        status="KNOWN",
                        value="fixture",
                        evidence=[{"kind": "scope", "location": "fixture", "reason": "known context"}],
                    )
            context_path.write_text(json.dumps(context, indent=2) + "\n", encoding="utf-8")
            self.run_cli("scripts/audit_run.py", "next", "--run-dir", str(run_dir))
            screen_path = run_dir / "reviews/screen-results.json"
            screen = self.read(screen_path)
            candidate = screen["results"][0]
            candidate.update(result="CANDIDATE", scope_complete=False, evidence=[])
            evidence = [
                {"kind": "scope", "location": "fixture", "reason": "complete scope"},
                {"kind": "inheritance", "location": "fixture", "reason": "screen disposition"},
            ]
            for item in screen["results"][1:]:
                item.update(result="NOT_APPLICABLE_CONFIRMED", scope_complete=True, evidence=evidence)
            screen_path.write_text(json.dumps(screen, indent=2) + "\n", encoding="utf-8")
            result = self.run_cli("scripts/audit_run.py", "next", "--run-dir", str(run_dir))
            self.assertIn("DEEP_REVIEW", result.stdout)
            self.assertEqual(
                json.loads(result.stdout)["recommended_execution"],
                {"provider": "codex", "model": "gpt-5.6-luna", "reasoning_effort": "max"},
            )

            manifest = self.read(run_dir / "routing/manifest.json")
            route = next(item for item in manifest["selected"] if item["canonical_id"] == candidate["canonical_id"])
            suspicious = {
                "record_type": "review",
                "schema_version": 7,
                "canonical_id": candidate["canonical_id"],
                "owner_domain": route["owner_domain"],
                "check_body_hash": route["check_body_hash"],
                "review_stage": "DEEP_REVIEW",
                "status": "SUSPICIOUS",
                "applicability": "APPLICABLE - fixture",
                "code_path": "fixture entry",
                "preconditions": "fixture state",
                "exploitability": "alternate path unresolved",
                "impact": "potential issue",
                "proof": "proof pending",
                "unresolved_reason": "proof pending",
                "evidence": [{"kind": "manual", "location": "fixture", "reason": "deep review"}],
            }
            ledger = run_dir / "reviews/review-evm-audit-general.jsonl"
            append(
                ledger,
                manifest,
                suspicious,
                self.read(ROOT / "data/canonical-checks.json"),
                {candidate["canonical_id"]},
                domain_context=context,
                screen_results=screen,
            )
            result = self.run_cli("scripts/audit_run.py", "next", "--run-dir", str(run_dir))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("PROOF", result.stdout)
            self.assertIn(candidate["canonical_id"], result.stdout)
            proof_payload = json.loads(result.stdout)
            self.assertEqual(proof_payload["progress"]["step"], 5)
            self.assertEqual(proof_payload["progress"]["label"], "Vulnerability Validation")
            self.assertIn("suspicious findings require Vulnerability Validation", proof_payload["progress"]["summary"])
            proof_views = [Path(path) for path in proof_payload["runtime_views"]]
            self.assertEqual(len(proof_views), 1)
            self.assertTrue(proof_views[0].exists())
            proof_text = proof_views[0].read_text(encoding="utf-8")
            self.assertIn(f"[{candidate['canonical_id']}]", proof_text)
            self.assertNotIn("REVIEWED_SAFE", proof_text)
            proof_views[0].write_text(proof_text + "\nTAMPERED\n", encoding="utf-8")
            regenerated = self.run_cli("scripts/audit_run.py", "next", "--run-dir", str(run_dir))
            self.assertEqual(regenerated.returncode, 0, regenerated.stderr)
            self.assertNotIn("TAMPERED", proof_views[0].read_text(encoding="utf-8"))
            proof_mtime = proof_views[0].stat().st_mtime_ns
            cached = self.run_cli("scripts/audit_run.py", "next", "--run-dir", str(run_dir))
            self.assertEqual(cached.returncode, 0, cached.stderr)
            self.assertEqual(proof_views[0].stat().st_mtime_ns, proof_mtime)
            self.assertEqual(
                proof_payload["recommended_execution"],
                {"provider": "codex", "model": "gpt-5.6-luna", "reasoning_effort": "max"},
            )
            resolved = {
                **{key: value for key, value in suspicious.items() if key != "unresolved_reason"},
                "review_stage": "PROOF",
                "status": "CONFIRMED",
                "applicability": "APPLICABLE - fixture",
                "preconditions": "fixture state",
                "exploitability": "fixture path is reachable",
                "impact": "fixture impact",
                "proof": f"POC source retained at {poc_location}; fixture invariant holds",
                "evidence": [{"kind": "test", "location": poc_location, "reason": "proof source and test result"}],
            }
            append(
                ledger,
                manifest,
                resolved,
                self.read(ROOT / "data/canonical-checks.json"),
                {candidate["canonical_id"]},
                domain_context=context,
                screen_results=screen,
            )
            result = self.run_cli("scripts/audit_run.py", "next", "--run-dir", str(run_dir))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("REPORT", result.stdout)
            self.assertIn("COMPLETE_WITH_FINDINGS", result.stdout)
            report_payload = json.loads(result.stdout)
            self.assertEqual(report_payload["progress"]["step"], 6)
            self.assertEqual(report_payload["progress"]["label"], "Final Report")
            state = self.read(run_dir / "audit-state.json")
            manifest = self.read(run_dir / "routing/manifest.json")
            identity = {
                "schema_version": 2, "artifact_state": "COMPLETED",
                "routing_snapshot_id": manifest["routing_snapshot_id"],
                "review_state_digest": state["review_state_digest"],
                **{key: manifest["audit_context"][key] for key in ("registry_sha256", "source_digest", "compilation_input_digest")},
            }
            candidate_id = candidate["canonical_id"]
            severity = {
                **identity,
                "decisions": {
                    candidate_id: {
                        "severity": "High", "rationale": "retained fixture PoC proves impact",
                        "dimensions": {
                            "impact": "fund_loss", "exploitability": "permissionless", "privileges": "none",
                            "capital_required": "none", "repeatability": "one_shot", "user_interaction": "none",
                            "loss_bound": "single_user", "protocol_exposure": "single_position", "recoverability": "irreversible",
                        },
                    }
                },
            }
            details = {
                **identity,
                "findings": [{
                    "canonical_id": candidate_id, "location": "RetainedPoC.t.sol:4",
                    "description": "The retained fixture proves the confirmed finding.",
                    "recommendation": "Fix the fixture target path.",
                }],
            }
            severity_bytes = json_text(severity).encode("utf-8")
            (run_dir / "reviews/severity-decisions.json").write_bytes(severity_bytes)
            (run_dir / "reviews/finding-details.json").write_text(json_text(details), encoding="utf-8")
            poc = {
                "artifact_type": "poc-evidence", "schema_version": 1, "artifact_state": "COMPLETED",
                "routing_snapshot_id": manifest["routing_snapshot_id"], "review_snapshot_id": state["review_snapshot_id"],
                "review_state_digest": state["review_state_digest"],
                **{key: manifest["audit_context"][key] for key in ("registry_sha256", "source_digest", "compilation_input_digest")},
                "severity_decisions_sha256": hashlib.sha256(severity_bytes).hexdigest(),
                "findings": [{
                    "canonical_id": candidate_id, "severity": "High", "runner": "foundry",
                    "command": "forge test --match-test testExploit -vvv",
                    "sources": [{"path": poc_location, "sha256": hashlib.sha256(poc_path.read_bytes()).hexdigest()}],
                    "entrypoint": "testExploit", "expected_result": "The exploit reproduces the confirmed defect.",
                    "result_summary": "The retained fixture reproduced the confirmed defect.",
                }],
            }
            (run_dir / "reviews/poc-evidence.json").write_text(json_text(poc), encoding="utf-8")
            for _ in range(2):
                result = self.run_cli("scripts/audit_run.py", "report", "--run-dir", str(run_dir))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(poc_path.read_text(encoding="utf-8"), poc_source)
                self.assertIn(poc_location, (run_dir / "reviews/review-evm-audit-general.jsonl").read_text(encoding="utf-8"))
                self.assertIn(poc_location, Path(json.loads(result.stdout)["report"]).read_text(encoding="utf-8"))

    def test_e2e_confirmed_medium_audit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_finding_run(run_dir, ["Medium"], include_poc=False)
            result = self.run_cli("scripts/audit_run.py", "report", "--run-dir", str(run_dir))
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertTrue(payload["complete"])
            pointer = self.read(run_dir / "report-current.json")
            self.assertEqual(pointer["schema_version"], 3)
            self.assertIsNotNone(pointer["reporting_inputs_sha256"])
            self.assertEqual(payload["report_generation"]["status"], "CURRENT")
            report = (run_dir / "report-generations" / pointer["generation"] / "AUDIT-REPORT.md").read_text(encoding="utf-8")
            self.assertIn("**Severity:** Medium", report)
            generation_root = run_dir / "report-generations" / pointer["generation"]
            self.assertEqual(
                self.read(generation_root / "issue-candidates.json")["findings"][0]["severity"],
                "Medium",
            )
            self.assertIsNone(self.read(generation_root / "report-bundle.json")["poc_evidence_sha256"])
            self.assertFalse((run_dir / "reviews/poc-evidence.json").exists())

    def test_documented_report_cli_high_auto_discovers_poc(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_finding_run(run_dir, ["High"])
            result = self.run_cli("scripts/audit_run.py", "report", "--run-dir", str(run_dir))
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertTrue(payload["complete"])
            self.assertEqual(payload["report_generation"]["status"], "CURRENT")
            self.assertIn("poc_evidence", payload["report_generation"])

    def test_low_policy_emits_no_issue_or_poc(self) -> None:
        decisions = {"FIXTURE": {"severity": "Low"}}
        self.assertEqual(derive_poc_required_ids(["FIXTURE"], decisions), [])
        self.assertEqual(derive_issue_candidates(["FIXTURE"], decisions), [])

    def test_info_policy_emits_no_issue_or_poc(self) -> None:
        decisions = {"FIXTURE": {"severity": "Info"}}
        self.assertEqual(derive_poc_required_ids(["FIXTURE"], decisions), [])
        self.assertEqual(derive_issue_candidates(["FIXTURE"], decisions), [])

    def test_high_report_rejects_missing_poc(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_finding_run(run_dir, ["High"], include_poc=False)
            with self.assertRaisesRegex(ValueError, "INCOMPLETE_POC"):
                audit_controller.report_run(ROOT, run_dir)
            self.assertFalse((run_dir / "report-current.json").exists())

    def test_missing_high_poc_preserves_previous_current_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            _, _, severity, _, _ = self.prepare_finding_run(run_dir, ["Medium"], include_poc=False)
            audit_controller.report_run(ROOT, run_dir)
            pointer = (run_dir / "report-current.json").read_bytes()
            severity["decisions"][next(iter(severity["decisions"]))]["severity"] = "High"
            (run_dir / "reviews/severity-decisions.json").write_text(json_text(severity), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "INCOMPLETE_POC"):
                audit_controller.report_run(ROOT, run_dir)
            self.assertEqual((run_dir / "report-current.json").read_bytes(), pointer)
            self.assertFalse(audit_controller._report_bundle_status(
                ROOT,
                audit_controller.paths(run_dir),
                self.read(run_dir / "routing/manifest.json"),
                self.read(run_dir / "audit-state.json"),
            )["current"])

    def test_missing_high_poc_exposes_per_id_reason_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            _, state, _, _, _ = self.prepare_finding_run(run_dir, ["High"], include_poc=False)
            result = audit_controller.status_run(ROOT, run_dir, emit=False, include_execution=True)
            canonical_id = state["coverage"]["confirmed"][0]
            self.assertEqual(
                result["poc_policy"]["poc_errors"],
                [{"canonical_id": canonical_id, "code": "POC_METADATA_MISSING"}],
            )

    def test_critical_report_rejects_missing_poc(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_finding_run(run_dir, ["Critical"], include_poc=False)
            with self.assertRaisesRegex(ValueError, "INCOMPLETE_POC"):
                audit_controller.report_run(ROOT, run_dir)
            self.assertFalse((run_dir / "report-current.json").exists())

    def test_high_report_accepts_valid_poc_and_snapshots_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            _, _, _, _, poc = self.prepare_finding_run(run_dir, ["High"])
            result = audit_controller.report_run(ROOT, run_dir)
            generation = Path(result["report"])
            self.assertIsNotNone(poc)
            self.assertIn("**PoC:** `poc/", generation.read_text(encoding="utf-8"))
            self.assertEqual(
                (generation.parent / "poc-evidence.json").read_bytes(),
                (run_dir / "reviews/poc-evidence.json").read_bytes(),
            )
            bundle = self.read(Path(result["report_bundle_path"]))
            self.assertEqual(bundle["poc_evidence_sha256"], hashlib.sha256((generation.parent / "poc-evidence.json").read_bytes()).hexdigest())

    def test_tampered_high_poc_blocks_republication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            self.prepare_finding_run(run_dir, ["High"])
            audit_controller.report_run(ROOT, run_dir)
            pointer = (run_dir / "report-current.json").read_bytes()
            source = next((run_dir / "poc").rglob("*.t.sol"))
            source.write_text(source.read_text(encoding="utf-8") + "// tampered\n", encoding="utf-8")
            status = audit_controller._report_bundle_status(
                ROOT,
                audit_controller.paths(run_dir),
                self.read(run_dir / "routing/manifest.json"),
                self.read(run_dir / "audit-state.json"),
            )
            self.assertEqual(status["status"], "STALE")
            with self.assertRaisesRegex(ValueError, "source hash"):
                audit_controller.report_run(ROOT, run_dir)
            self.assertEqual((run_dir / "report-current.json").read_bytes(), pointer)

    def test_severity_change_invalidates_old_poc_projection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            _, _, severity, _, _ = self.prepare_finding_run(run_dir, ["High"])
            audit_controller.report_run(ROOT, run_dir)
            severity["decisions"][next(iter(severity["decisions"]))]["severity"] = "Medium"
            severity_path = run_dir / "reviews/severity-decisions.json"
            severity_path.write_text(json_text(severity), encoding="utf-8")
            result = audit_controller.report_run(ROOT, run_dir)
            bundle = self.read(Path(result["report_bundle_path"]))
            self.assertIsNone(bundle["poc_evidence_sha256"])
            self.assertFalse((run_dir / "reviews/poc-evidence.json").exists())
            severity["decisions"][next(iter(severity["decisions"]))]["severity"] = "High"
            severity_path.write_text(json_text(severity), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "INCOMPLETE_POC"):
                audit_controller.report_run(ROOT, run_dir)

    def test_poc_template_is_created_only_after_high_severity_is_complete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            manifest, state, severity, _, _ = self.prepare_finding_run(run_dir, ["High"], include_poc=False)
            candidate_id = next(iter(severity["decisions"]))
            severity_path = run_dir / "reviews/severity-decisions.json"
            severity_path.write_text(json_text(audit_controller._reporting_payloads(manifest, state)["severity"]), encoding="utf-8")
            first = audit_controller.next_step(ROOT, run_dir, emit=False)
            self.assertNotIn("poc_evidence", first.get("templates", {}))
            self.assertFalse((run_dir / "reviews/poc-evidence.json").exists())
            severity_path.write_text(json_text(severity), encoding="utf-8")
            second = audit_controller.next_step(ROOT, run_dir, emit=False)
            poc_path = run_dir / "reviews/poc-evidence.json"
            self.assertEqual(second["required_inputs"], ["severity-decisions", "finding-details", "poc-evidence"])
            self.assertEqual(self.read(poc_path)["artifact_state"], "TEMPLATE")
            self.assertEqual(second["poc_policy"]["required_ids"], [candidate_id])

    def test_completed_poc_is_archived_when_severity_identity_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            manifest, state, severity, _, _ = self.prepare_finding_run(run_dir, ["High"])
            audit_controller.next_step(ROOT, run_dir, emit=False)
            severity["decisions"][next(iter(severity["decisions"]))]["severity"] = "Critical"
            (run_dir / "reviews/severity-decisions.json").write_text(json_text(severity), encoding="utf-8")
            result = audit_controller.next_step(ROOT, run_dir, emit=False)
            self.assertEqual(result["template_status"]["poc_evidence"], "ARCHIVED_STALE_ARTIFACT")
            self.assertTrue(any((run_dir / "reviews").glob("poc-evidence.stale-*.json")))
            self.assertEqual(self.read(run_dir / "reviews/poc-evidence.json")["artifact_state"], "TEMPLATE")

    def test_invalid_completed_poc_is_not_reported_as_current_completed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            _, _, _, _, _ = self.prepare_finding_run(run_dir, ["High"])
            source = next((run_dir / "poc").rglob("*.t.sol"))
            source.write_text(source.read_text(encoding="utf-8") + "// invalidated\n", encoding="utf-8")
            result = audit_controller.next_step(ROOT, run_dir, emit=False)
            self.assertEqual(result["template_status"]["poc_evidence"], "INVALID_COMPLETED")
            self.assertNotEqual(result["template_status"]["poc_evidence"], "CURRENT_COMPLETED")
            self.assertTrue(result["poc_policy"]["pending_ids"])

    def test_mixed_severity_report_requires_exact_high_critical_pocs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            _, _, severity, _, poc = self.prepare_finding_run(
                run_dir, ["Low", "Medium", "High", "Critical"]
            )
            self.assertIsNotNone(poc)
            poc_path = run_dir / "reviews/poc-evidence.json"
            original_poc = poc_path.read_bytes()
            partial = json.loads(original_poc.decode("utf-8"))
            critical = next(item for item in partial["findings"] if item["severity"] == "Critical")
            critical_source = run_dir / critical["sources"][0]["path"]
            critical_source_bytes = critical_source.read_bytes()
            critical_source.unlink()
            partial["findings"] = [item for item in partial["findings"] if item["severity"] != "Critical"]
            poc_path.write_text(json_text(partial), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "INCOMPLETE_POC"):
                audit_controller.report_run(ROOT, run_dir)
            self.assertFalse((run_dir / "report-current.json").exists())
            poc_path.write_bytes(original_poc)
            critical_source.parent.mkdir(parents=True, exist_ok=True)
            critical_source.write_bytes(critical_source_bytes)
            result = audit_controller.report_run(ROOT, run_dir)
            report = Path(result["report"]).read_text(encoding="utf-8")
            issues = self.read(Path(result["issue_candidates"]))
            self.assertIn("**Severity:** Low", report)
            self.assertIn("**Severity:** Medium", report)
            self.assertIn("**Severity:** High", report)
            self.assertIn("**Severity:** Critical", report)
            self.assertEqual(
                {item["severity"] for item in issues["findings"]},
                {"Critical", "High", "Medium"},
            )


if __name__ == "__main__":
    unittest.main()
