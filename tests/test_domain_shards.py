"""Tests for per-Domain shard authoring and merge (orchestrated parallel audits)."""

from __future__ import annotations

import json
import multiprocessing
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

from helpers import ROOT, build_manifest
from scripts.audit_artifacts import load_json
from scripts.render_runtime import domain_context_template, screen_results_template, selected_entries

DOMAINS = ("evm-audit-general", "evm-audit-erc20")


def _run_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *arguments],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )


def _make_run(directory: Path) -> tuple[Path, dict[str, Any]]:
    """Materialize a minimal run directory carrying a valid two-domain manifest."""
    _, _, _, manifest = build_manifest(domains=DOMAINS)
    run_dir = directory / "run"
    (run_dir / "routing").mkdir(parents=True)
    (run_dir / "routing" / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return run_dir, manifest


def _worker_inputs(manifest: dict[str, Any]) -> tuple[dict[str, list[dict[str, Any]]], dict[str, dict[str, Any]]]:
    """Author complete per-Domain worker inputs: all-CANDIDATE screen results and KNOWN context."""
    screen_inputs: dict[str, list[dict[str, Any]]] = {}
    for entry in selected_entries(manifest):
        screen_inputs.setdefault(entry["owner_domain"], []).append(
            {"canonical_id": entry["canonical_id"], "result": "CANDIDATE", "scope_complete": False, "evidence": []}
        )
    context_inputs: dict[str, dict[str, Any]] = {}
    template = domain_context_template(manifest)
    evidence = [{"kind": "scope", "location": "fixture", "reason": "complete scope"}]
    for domain, requirements in template["domains"].items():
        context_inputs[domain] = {
            key: {"status": "KNOWN", "value": "fixture", "evidence": evidence}
            for key in requirements
        }
    return screen_inputs, context_inputs


def _write_shards(run_dir: Path, manifest: dict[str, Any], directory: Path, *, skip_screen: str | None = None, skip_context: str | None = None) -> None:
    screen_inputs, context_inputs = _worker_inputs(manifest)
    for domain, results in screen_inputs.items():
        if domain == skip_screen:
            continue
        source = directory / f"screen-{domain}.json"
        source.write_text(json.dumps({"results": results}) + "\n", encoding="utf-8")
        result = _run_cli("scripts/domain_shards.py", "write-screen-shard", "--run-dir", str(run_dir), "--domain", domain, "--input", str(source))
        assert result.returncode == 0, result.stderr
    for domain, context in context_inputs.items():
        if domain == skip_context:
            continue
        source = directory / f"context-{domain}.json"
        source.write_text(json.dumps({"context": context}) + "\n", encoding="utf-8")
        result = _run_cli("scripts/domain_shards.py", "write-context-shard", "--run-dir", str(run_dir), "--domain", domain, "--input", str(source))
        assert result.returncode == 0, result.stderr


class DomainShardsTests(unittest.TestCase):
    def test_roundtrip_write_merge_and_idempotent_remerge(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            run_dir, manifest = _make_run(directory)
            _write_shards(run_dir, manifest, directory)

            status = _run_cli("scripts/domain_shards.py", "status", "--run-dir", str(run_dir))
            self.assertEqual(status.returncode, 0, status.stderr)
            self.assertTrue(json.loads(status.stdout)["merge_ready"])

            merged = _run_cli("scripts/domain_shards.py", "merge", "--run-dir", str(run_dir))
            self.assertEqual(merged.returncode, 0, merged.stderr)
            payload = json.loads(merged.stdout)
            self.assertEqual(payload["screen_shard_domains"], sorted(DOMAINS))
            self.assertEqual(payload["selected_count"], manifest["selected_count"])
            self.assertEqual(payload["candidate_count"], manifest["selected_count"])
            self.assertEqual(len(payload["review_snapshot_id"]), 64)

            global_screen = load_json(run_dir / "reviews/screen-results.json")
            self.assertEqual(len(global_screen["results"]), manifest["selected_count"])
            ids = [entry["canonical_id"] for entry in global_screen["results"]]
            self.assertEqual(ids, sorted(ids), "merged results must be deterministically ordered")
            global_context = load_json(run_dir / "reviews/domain-context.json")
            self.assertEqual(sorted(global_context["domains"]), sorted(DOMAINS))

            again = _run_cli("scripts/domain_shards.py", "merge", "--run-dir", str(run_dir))
            self.assertEqual(again.returncode, 0, again.stderr)
            self.assertFalse(json.loads(again.stdout)["screen_results_replaced"])
            self.assertEqual(load_json(run_dir / "reviews/screen-results.json"), global_screen)

    def test_screen_shard_rejects_foreign_and_missing_checks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            run_dir, manifest = _make_run(directory)
            screen_inputs, _ = _worker_inputs(manifest)
            domain = DOMAINS[0]
            foreign = list(screen_inputs[domain]) + [
                {"canonical_id": screen_inputs[DOMAINS[1]][0]["canonical_id"], "result": "CANDIDATE", "scope_complete": False, "evidence": []}
            ]
            source = directory / "foreign.json"
            source.write_text(json.dumps({"results": foreign}) + "\n", encoding="utf-8")
            result = _run_cli("scripts/domain_shards.py", "write-screen-shard", "--run-dir", str(run_dir), "--domain", domain, "--input", str(source))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not own", result.stderr)

            missing = screen_inputs[domain][1:]
            source.write_text(json.dumps({"results": missing}) + "\n", encoding="utf-8")
            result = _run_cli("scripts/domain_shards.py", "write-screen-shard", "--run-dir", str(run_dir), "--domain", domain, "--input", str(source))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing checks", result.stderr)

    def test_screen_shard_rejects_unsupported_domain_and_weak_absence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            run_dir, manifest = _make_run(directory)
            screen_inputs, _ = _worker_inputs(manifest)
            source = directory / "input.json"
            source.write_text(json.dumps({"results": screen_inputs[DOMAINS[0]]}) + "\n", encoding="utf-8")
            result = _run_cli("scripts/domain_shards.py", "write-screen-shard", "--run-dir", str(run_dir), "--domain", "evm-audit-proxies", "--input", str(source))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("owns no selected checks", result.stderr)

            weak = [dict(screen_inputs[DOMAINS[0]][0])]
            weak[0]["result"] = "NOT_APPLICABLE_CONFIRMED"
            weak[0]["scope_complete"] = True
            weak[0]["evidence"] = []
            source.write_text(json.dumps({"results": weak}) + "\n", encoding="utf-8")
            result = _run_cli("scripts/domain_shards.py", "write-screen-shard", "--run-dir", str(run_dir), "--domain", DOMAINS[0], "--input", str(source))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("screen-shard", result.stderr)

    def test_context_shard_requires_exact_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            run_dir, manifest = _make_run(directory)
            _, context_inputs = _worker_inputs(manifest)
            domain = DOMAINS[0]
            keys = sorted(context_inputs[domain])
            incomplete = {key: context_inputs[domain][key] for key in keys[1:]}
            source = directory / "context.json"
            source.write_text(json.dumps({"context": incomplete}) + "\n", encoding="utf-8")
            result = _run_cli("scripts/domain_shards.py", "write-context-shard", "--run-dir", str(run_dir), "--domain", domain, "--input", str(source))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing keys", result.stderr)

            extra = dict(incomplete)
            extra["not-a-required-key"] = {"status": "KNOWN", "value": "x", "evidence": [{"kind": "scope", "location": "f", "reason": "r"}]}
            source.write_text(json.dumps({"context": extra}) + "\n", encoding="utf-8")
            result = _run_cli("scripts/domain_shards.py", "write-context-shard", "--run-dir", str(run_dir), "--domain", domain, "--input", str(source))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unexpected keys", result.stderr)

    def test_merge_requires_every_domain_shard(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            run_dir, manifest = _make_run(directory)
            _write_shards(run_dir, manifest, directory, skip_screen=DOMAINS[1])
            result = _run_cli("scripts/domain_shards.py", "merge", "--run-dir", str(run_dir))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(f"missing screen shard for Domain '{DOMAINS[1]}'", result.stderr)
            self.assertFalse((run_dir / "reviews/screen-results.json").exists(), "failed merge must not write global artifacts")

    def test_stale_shard_is_rejected_at_merge(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            run_dir, manifest = _make_run(directory)
            _write_shards(run_dir, manifest, directory)
            shard_path = run_dir / f"reviews/shards/screen-{DOMAINS[0]}.json"
            shard = load_json(shard_path)
            shard["routing_snapshot_id"] = "0" * 64
            shard_path.write_text(json.dumps(shard) + "\n", encoding="utf-8")
            result = _run_cli("scripts/domain_shards.py", "merge", "--run-dir", str(run_dir))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("different routing snapshot", result.stderr)

    def test_merge_refuses_hand_edited_global_then_force(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            run_dir, manifest = _make_run(directory)
            _write_shards(run_dir, manifest, directory)
            # Pre-create the global files as hand-edited content that is neither
            # the template nor the merged shards.
            hand_edited_screen = screen_results_template(manifest)
            hand_edited_screen["results"] = hand_edited_screen["results"][:1]
            (run_dir / "reviews").mkdir(exist_ok=True)
            (run_dir / "reviews/screen-results.json").write_text(json.dumps(hand_edited_screen) + "\n", encoding="utf-8")
            result = _run_cli("scripts/domain_shards.py", "merge", "--run-dir", str(run_dir))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("neither the generated template nor the merged shards", result.stderr)
            forced = _run_cli("scripts/domain_shards.py", "merge", "--run-dir", str(run_dir), "--force")
            self.assertEqual(forced.returncode, 0, forced.stderr)
            self.assertTrue(json.loads(forced.stdout)["screen_results_replaced"])

    def test_merge_accepts_generated_templates_in_place(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            run_dir, manifest = _make_run(directory)
            (run_dir / "reviews").mkdir(exist_ok=True)
            (run_dir / "reviews/screen-results.json").write_text(json.dumps(screen_results_template(manifest)) + "\n", encoding="utf-8")
            (run_dir / "reviews/domain-context.json").write_text(json.dumps(domain_context_template(manifest)) + "\n", encoding="utf-8")
            _write_shards(run_dir, manifest, directory)
            result = _run_cli("scripts/domain_shards.py", "merge", "--run-dir", str(run_dir))
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertTrue(payload["screen_results_replaced"])
            self.assertEqual(payload["candidate_count"], manifest["selected_count"])

    def test_status_reports_missing_shards(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            run_dir, manifest = _make_run(directory)
            result = _run_cli("scripts/domain_shards.py", "status", "--run-dir", str(run_dir))
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertFalse(payload["merge_ready"])
            self.assertEqual(payload["missing_screen_shards"], sorted(DOMAINS))
            self.assertEqual(payload["missing_context_shards"], sorted(DOMAINS))


def _concurrent_worker(directory: str, run_dir: str, domain: str, mode: str) -> None:
    if mode == "screen":
        _, _, _, manifest = build_manifest(domains=DOMAINS)
        screen_inputs, _ = _worker_inputs(manifest)
        source = Path(directory) / f"parallel-screen-{domain}.json"
        source.write_text(json.dumps({"results": screen_inputs[domain]}) + "\n", encoding="utf-8")
        command = ["scripts/domain_shards.py", "write-screen-shard", "--run-dir", run_dir, "--domain", domain, "--input", str(source)]
    else:
        command = ["scripts/domain_shards.py", "merge", "--run-dir", run_dir]
    result = _run_cli(*command)
    if result.returncode != 0:
        raise AssertionError(result.stderr)


class DomainShardsConcurrencyTests(unittest.TestCase):
    def test_concurrent_shard_writes_and_merges_stay_consistent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            run_dir, manifest = _make_run(directory)
            _, context_inputs = _worker_inputs(manifest)
            # One context shard per domain, written up front; screen shards are
            # written by four concurrent workers (two per domain).
            for domain, context in context_inputs.items():
                source = directory / f"context-{domain}.json"
                source.write_text(json.dumps({"context": context}) + "\n", encoding="utf-8")
                result = _run_cli("scripts/domain_shards.py", "write-context-shard", "--run-dir", str(run_dir), "--domain", domain, "--input", str(source))
                self.assertEqual(result.returncode, 0, result.stderr)
            context = multiprocessing.get_context("spawn")
            workers = [
                context.Process(target=_concurrent_worker, args=(str(directory), str(run_dir), domain, "screen"))
                for domain in DOMAINS * 2
            ]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=120)
                self.assertEqual(worker.exitcode, 0)
            mergers = [
                context.Process(target=_concurrent_worker, args=(str(directory), str(run_dir), "", "merge"))
                for _ in range(2)
            ]
            for merger in mergers:
                merger.start()
            for merger in mergers:
                merger.join(timeout=120)
                self.assertEqual(merger.exitcode, 0)
            global_screen = load_json(run_dir / "reviews/screen-results.json")
            self.assertEqual(len(global_screen["results"]), manifest["selected_count"])
            ids = [entry["canonical_id"] for entry in global_screen["results"]]
            self.assertEqual(len(ids), len(set(ids)))
            from scripts.audit_artifacts import validate_schema

            validate_schema(ROOT, "screen-results.schema.json", global_screen)
            validate_schema(ROOT, "domain-context.schema.json", load_json(run_dir / "reviews/domain-context.json"))


if __name__ == "__main__":
    unittest.main()
