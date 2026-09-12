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
            status_payload = json.loads(status.stdout)
            self.assertTrue(status_payload["context_merge_ready"])
            self.assertFalse(
                status_payload["merge_ready"],
                "screen readiness requires the authoritative domain-context artifact",
            )

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

    def test_stage_merges_are_staged_idempotent_and_gated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            run_dir, manifest = _make_run(directory)

            # merge-screen without an authoritative context file must fail
            # without writing any global artifact.
            early = _run_cli("scripts/domain_shards.py", "merge-screen", "--run-dir", str(run_dir))
            self.assertNotEqual(early.returncode, 0)
            self.assertIn("run merge-context first", early.stderr)
            self.assertFalse((run_dir / "reviews/screen-results.json").exists())

            _write_shards(run_dir, manifest, directory)

            # Context merge writes only the authoritative context artifact.
            context = _run_cli("scripts/domain_shards.py", "merge-context", "--run-dir", str(run_dir))
            self.assertEqual(context.returncode, 0, context.stderr)
            context_payload = json.loads(context.stdout)
            self.assertEqual(context_payload["context_shard_domains"], sorted(DOMAINS))
            self.assertTrue((run_dir / "reviews/domain-context.json").exists())
            self.assertFalse((run_dir / "reviews/screen-results.json").exists())
            self.assertNotIn("review_snapshot_id", context_payload)

            # Screen merge requires the authoritative context, then derives
            # the review snapshot after both artifacts are valid.
            screen = _run_cli("scripts/domain_shards.py", "merge-screen", "--run-dir", str(run_dir))
            self.assertEqual(screen.returncode, 0, screen.stderr)
            screen_payload = json.loads(screen.stdout)
            self.assertEqual(screen_payload["candidate_count"], manifest["selected_count"])
            self.assertEqual(len(screen_payload["review_snapshot_id"]), 64)
            self.assertTrue((run_dir / "reviews/screen-results.json").exists())

            # Both stage merges are idempotent.
            for command in ("merge-context", "merge-screen"):
                repeat = _run_cli("scripts/domain_shards.py", command, "--run-dir", str(run_dir))
                self.assertEqual(repeat.returncode, 0, repeat.stderr)
                payload = json.loads(repeat.stdout)
                replaced_key = "domain_context_replaced" if command == "merge-context" else "screen_results_replaced"
                self.assertFalse(payload[replaced_key])

    def test_failed_stage_merge_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            run_dir, manifest = _make_run(directory)
            _write_shards(run_dir, manifest, directory, skip_screen=DOMAINS[1])
            context = _run_cli("scripts/domain_shards.py", "merge-context", "--run-dir", str(run_dir))
            self.assertEqual(context.returncode, 0, context.stderr)
            missing = _run_cli("scripts/domain_shards.py", "merge-screen", "--run-dir", str(run_dir))
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn(f"missing screen shard for Domain '{DOMAINS[1]}'", missing.stderr)
            self.assertFalse((run_dir / "reviews/screen-results.json").exists())

            # A later failure must not overwrite an existing valid artifact.
            authoritative = load_json(run_dir / "reviews/domain-context.json")
            shard_path = run_dir / f"reviews/shards/context-{DOMAINS[0]}.json"
            shard_path.write_text("{ not json", encoding="utf-8")
            failed = _run_cli("scripts/domain_shards.py", "merge-context", "--run-dir", str(run_dir))
            self.assertNotEqual(failed.returncode, 0)
            self.assertEqual(load_json(run_dir / "reviews/domain-context.json"), authoritative)

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
            self.assertFalse(payload["context_merge_ready"])
            self.assertFalse(payload["screen_merge_ready"])
            self.assertEqual(payload["missing_screen_shards"], sorted(DOMAINS))
            self.assertEqual(payload["missing_context_shards"], sorted(DOMAINS))

    def test_status_never_reports_invalid_shards_as_ready(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            run_dir, manifest = _make_run(directory)
            _write_shards(run_dir, manifest, directory)

            def status() -> dict[str, Any]:
                result = _run_cli("scripts/domain_shards.py", "status", "--run-dir", str(run_dir))
                self.assertEqual(result.returncode, 0, result.stderr)
                return json.loads(result.stdout)

            payload = status()
            self.assertTrue(payload["context_merge_ready"])
            self.assertFalse(payload["screen_merge_ready"], "screen merge needs authoritative context first")

            # Stale routing snapshot: present but invalid must not be ready.
            shard_path = run_dir / f"reviews/shards/screen-{DOMAINS[0]}.json"
            shard = load_json(shard_path)
            shard["routing_snapshot_id"] = "0" * 64
            shard_path.write_text(json.dumps(shard) + "\n", encoding="utf-8")
            payload = status()
            self.assertFalse(payload["merge_ready"])
            self.assertIn(DOMAINS[0], payload["invalid_screen_shards"])
            diagnostic = next(e for e in payload["screen_shards"] if e["owner_domain"] == DOMAINS[0])
            self.assertFalse(diagnostic["valid"])
            self.assertIn("different routing snapshot", diagnostic["error"])

            # Malformed JSON: diagnosed, never crashes the command.
            shard_path.write_text("{ not json", encoding="utf-8")
            payload = status()
            self.assertFalse(payload["merge_ready"])
            self.assertIn(DOMAINS[0], payload["invalid_screen_shards"])

            # Wrong owner: present but invalid.
            shard_path.write_text(json.dumps({**shard, "routing_snapshot_id": manifest["routing_snapshot_id"], "owner_domain": DOMAINS[1]}) + "\n", encoding="utf-8")
            payload = status()
            self.assertFalse(payload["merge_ready"])

            # Restore validity; incomplete exact coverage (missing checks).
            _write_shards(run_dir, manifest, directory)
            shard = load_json(shard_path)
            shard["results"] = shard["results"][1:]
            shard_path.write_text(json.dumps(shard) + "\n", encoding="utf-8")
            payload = status()
            self.assertFalse(payload["merge_ready"])
            self.assertIn(DOMAINS[0], payload["invalid_screen_shards"])

            # Fully valid shards plus authoritative context make screen ready.
            _write_shards(run_dir, manifest, directory)
            _run_cli("scripts/domain_shards.py", "merge-context", "--run-dir", str(run_dir))
            payload = status()
            self.assertTrue(payload["context_merge_ready"])
            self.assertTrue(payload["screen_merge_ready"])
            self.assertTrue(payload["merge_ready"])
            self.assertEqual(payload["global_domain_context"], {"present": True, "valid": True})

    def test_status_gates_screen_readiness_on_authoritative_context(self) -> None:
        """``status`` must diagnose the authoritative context with merge-screen's contract.

        Mere existence of ``reviews/domain-context.json`` is not readiness:
        every mutation below leaves ``screen_merge_ready`` false, the status
        diagnostic explains why, and ``merge-screen`` rejects the same state.
        """
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            run_dir, manifest = _make_run(directory)
            _write_shards(run_dir, manifest, directory)
            merged = _run_cli("scripts/domain_shards.py", "merge-context", "--run-dir", str(run_dir))
            self.assertEqual(merged.returncode, 0, merged.stderr)
            context_path = run_dir / "reviews/domain-context.json"

            def assert_invalid_context_rejected() -> dict[str, Any]:
                status = _run_cli("scripts/domain_shards.py", "status", "--run-dir", str(run_dir))
                self.assertEqual(status.returncode, 0, f"status must not crash: {status.stderr}")
                payload = json.loads(status.stdout)
                self.assertTrue(payload["context_merge_ready"])
                self.assertFalse(payload["screen_merge_ready"], payload["global_domain_context"])
                self.assertFalse(payload["merge_ready"])
                diagnostic = payload["global_domain_context"]
                self.assertFalse(diagnostic["valid"])
                self.assertTrue(diagnostic["error"])
                merge = _run_cli("scripts/domain_shards.py", "merge-screen", "--run-dir", str(run_dir))
                self.assertNotEqual(merge.returncode, 0)
                self.assertEqual(merge.stderr.strip().splitlines()[-1].removeprefix("ERROR: ").strip(), diagnostic["error"])
                self.assertFalse((run_dir / "reviews/screen-results.json").exists())
                return diagnostic

            # Missing authoritative context.
            valid_context = load_json(context_path)
            context_path.unlink()
            diagnostic = assert_invalid_context_rejected()
            self.assertFalse(diagnostic["present"])
            self.assertIn("run merge-context first", diagnostic["error"])

            def restore() -> None:
                context_path.write_text(json.dumps(valid_context) + "\n", encoding="utf-8")

            # Malformed authoritative JSON.
            context_path.write_text("{ not json", encoding="utf-8")
            diagnostic = assert_invalid_context_rejected()
            self.assertTrue(diagnostic["present"])

            # Stale routing snapshot identity.
            restore()
            stale = load_json(context_path)
            stale["routing_snapshot_id"] = "0" * 64
            context_path.write_text(json.dumps(stale) + "\n", encoding="utf-8")
            diagnostic = assert_invalid_context_rejected()
            self.assertIn("mismatched routing_snapshot_id", diagnostic["error"])

            # Wrong artifact identity digest.
            restore()
            foreign = load_json(context_path)
            foreign["registry_sha256"] = "1" * 64
            context_path.write_text(json.dumps(foreign) + "\n", encoding="utf-8")
            diagnostic = assert_invalid_context_rejected()
            self.assertIn("mismatched registry_sha256", diagnostic["error"])

            # Unresolved required context.
            restore()
            unresolved = load_json(context_path)
            domain_requirements = unresolved["domains"][DOMAINS[0]]
            first_key = sorted(domain_requirements)[0]
            domain_requirements[first_key]["status"] = "UNKNOWN"
            domain_requirements[first_key].pop("value", None)
            context_path.write_text(json.dumps(unresolved) + "\n", encoding="utf-8")
            diagnostic = assert_invalid_context_rejected()
            self.assertIn(f"{DOMAINS[0]}.{first_key}", diagnostic["error"])

            # Restoring the merged content makes the exact same state ready
            # again, and merge-context can republish it from the shards.
            restore()
            status = _run_cli("scripts/domain_shards.py", "status", "--run-dir", str(run_dir))
            self.assertEqual(status.returncode, 0, status.stderr)
            payload = json.loads(status.stdout)
            self.assertTrue(payload["screen_merge_ready"])
            self.assertTrue(payload["merge_ready"])
            self.assertEqual(payload["global_domain_context"], {"present": True, "valid": True})
            republished = _run_cli("scripts/domain_shards.py", "merge-context", "--run-dir", str(run_dir))
            self.assertEqual(republished.returncode, 0, republished.stderr)


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
    def test_parallel_shard_writes_then_concurrent_merge_attempts_stay_consistent(self) -> None:
        """Parallel per-Domain writes, worker quiescence, then serialized merges.

        The supported orchestration never merges while workers are still
        writing; this test exercises exactly that ordering.
        """
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            run_dir, manifest = _make_run(directory)
            _, context_inputs = _worker_inputs(manifest)
            # One context shard per domain, written up front; screen shards
            # are written by one parallel worker per owner Domain.
            for domain, context in context_inputs.items():
                source = directory / f"context-{domain}.json"
                source.write_text(json.dumps({"context": context}) + "\n", encoding="utf-8")
                result = _run_cli("scripts/domain_shards.py", "write-context-shard", "--run-dir", str(run_dir), "--domain", domain, "--input", str(source))
                self.assertEqual(result.returncode, 0, result.stderr)
            context = multiprocessing.get_context("spawn")
            workers = [
                context.Process(target=_concurrent_worker, args=(str(directory), str(run_dir), domain, "screen"))
                for domain in DOMAINS
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

    def test_duplicate_same_domain_shard_writes_are_atomic(self) -> None:
        """Concurrent rewrites of one Domain's shard never leave torn output.

        Duplicate same-Domain writers are not part of normal orchestration;
        this pins the atomic-write property that makes shard re-authoring
        safe. Normal dispatch uses exactly one worker per Domain.
        """
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            run_dir, manifest = _make_run(directory)
            context = multiprocessing.get_context("spawn")
            workers = [
                context.Process(target=_concurrent_worker, args=(str(directory), str(run_dir), DOMAINS[0], "screen"))
                for _ in range(4)
            ]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=120)
                self.assertEqual(worker.exitcode, 0)
            shard = load_json(run_dir / f"reviews/shards/screen-{DOMAINS[0]}.json")
            expected = {entry["canonical_id"] for entry in _worker_inputs(manifest)[0][DOMAINS[0]]}
            self.assertEqual({entry["canonical_id"] for entry in shard["results"]}, expected)


if __name__ == "__main__":
    unittest.main()
