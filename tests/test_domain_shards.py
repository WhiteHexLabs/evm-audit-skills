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


def _make_run(directory: Path, domains: tuple[str, ...] = DOMAINS) -> tuple[Path, dict[str, Any]]:
    """Materialize a minimal run directory carrying a valid multi-domain manifest."""
    _, _, _, manifest = build_manifest(domains=domains)
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


    def test_status_gates_context_readiness_on_unresolved_required_context(self) -> None:
        """``status`` must predict merge-context's outcome from the shard content.

        A schema-valid shard that leaves a required key UNKNOWN - or one that
        only fails the merged-artifact validation - is not merge-ready, and
        ``status`` must agree with the merge that rejects it.
        """
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            run_dir, manifest = _make_run(directory)
            _write_shards(run_dir, manifest, directory)
            _, context_inputs = _worker_inputs(manifest)
            domain = sorted(context_inputs)[0]
            key = sorted(context_inputs[domain])[0]
            evidence = [{"kind": "scope", "location": "fixture", "reason": "complete scope"}]

            def rewrite_shard(entry: dict[str, Any]) -> None:
                source = directory / f"context-{domain}-edited.json"
                source.write_text(
                    json.dumps({"context": {**context_inputs[domain], key: entry}}) + "\n",
                    encoding="utf-8",
                )
                result = _run_cli(
                    "scripts/domain_shards.py", "write-context-shard",
                    "--run-dir", str(run_dir), "--domain", domain, "--input", str(source),
                )
                self.assertEqual(result.returncode, 0, result.stderr)

            def status_payload() -> dict[str, Any]:
                status = _run_cli("scripts/domain_shards.py", "status", "--run-dir", str(run_dir))
                self.assertEqual(status.returncode, 0, f"status must not crash: {status.stderr}")
                return json.loads(status.stdout)

            # A required key left UNKNOWN is accepted at write time (truthful
            # worker output) but can never be reported merge-ready.
            rewrite_shard({"status": "UNKNOWN"})
            payload = status_payload()
            self.assertFalse(payload["context_merge_ready"], payload["context_merge_diagnostic"])
            self.assertFalse(payload["merge_ready"])
            self.assertEqual(payload["unresolved_context"], [f"{domain}.{key}"])
            entry = next(item for item in payload["context_shards"] if item["owner_domain"] == domain)
            self.assertTrue(entry["valid"], "an UNKNOWN shard is valid data, not a malformed shard")
            self.assertEqual(entry["unresolved_required"], [f"{domain}.{key}"])
            self.assertIn(
                f"merged context remains UNKNOWN for: {domain}.{key}",
                payload["context_merge_diagnostic"]["error"],
            )
            merge = _run_cli("scripts/domain_shards.py", "merge-context", "--run-dir", str(run_dir))
            self.assertNotEqual(merge.returncode, 0)
            self.assertIn(f"merged context remains UNKNOWN for: {domain}.{key}", merge.stderr)
            self.assertFalse((run_dir / "reviews/domain-context.json").exists())

            # A KNOWN entry with an empty value passes the shard schema but
            # fails the merged-artifact validation; status stays diagnostic.
            rewrite_shard({"status": "KNOWN", "value": "", "evidence": evidence})
            payload = status_payload()
            self.assertFalse(payload["context_merge_ready"], payload["context_merge_diagnostic"])
            self.assertIn(
                f"{domain}.{key} KNOWN requires value and evidence",
                payload["context_merge_diagnostic"]["error"],
            )
            merge = _run_cli("scripts/domain_shards.py", "merge-context", "--run-dir", str(run_dir))
            self.assertNotEqual(merge.returncode, 0)
            self.assertIn(f"{domain}.{key} KNOWN requires value and evidence", merge.stderr)

            # Resolving the key restores readiness and merge-context succeeds.
            rewrite_shard({"status": "KNOWN", "value": "fixture", "evidence": evidence})
            payload = status_payload()
            self.assertTrue(payload["context_merge_ready"], payload["context_merge_diagnostic"])
            self.assertEqual(payload["unresolved_context"], [])
            self.assertTrue(all("unresolved_required" not in item for item in payload["context_shards"]))
            republished = _run_cli("scripts/domain_shards.py", "merge-context", "--run-dir", str(run_dir))
            self.assertEqual(republished.returncode, 0, republished.stderr)


class ContextShardTrustedAbsenceTests(unittest.TestCase):
    """Write-time trusted-absence validation for context shards.

    Every shipped Domain policy permits ``scope + inheritance`` and excludes
    ``source``, so ``evm-audit-oracles.heartbeat`` reproduces the reported
    failure class: a schema-valid ``NOT_APPLICABLE`` whose evidence violates
    the owning Domain's ``trusted_absence_policy``.
    """

    DOMAINS = ("evm-audit-oracles", "evm-audit-general")

    SCOPE_EVIDENCE = [{"kind": "scope", "location": "complete scope", "reason": "complete scope was inspected"}]
    SOURCE_EVIDENCE = [{"kind": "source", "location": "Oracle.sol", "reason": "heartbeat reference not found"}]
    INHERITANCE_EVIDENCE = [{"kind": "inheritance", "location": "contracts/", "reason": "no oracle interface is inherited"}]

    def make_run(self, directory: Path) -> tuple[Path, dict[str, Any]]:
        return _make_run(directory, domains=self.DOMAINS)

    def context_inputs(self, manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
        template = domain_context_template(manifest)
        return {
            domain: {
                key: {"status": "KNOWN", "value": "fixture", "evidence": self.SCOPE_EVIDENCE}
                for key in requirements
            }
            for domain, requirements in template["domains"].items()
        }

    def write_context(self, run_dir: Path, directory: Path, domain: str, context: dict[str, Any], *, tag: str = "") -> subprocess.CompletedProcess[str]:
        source = directory / f"context-{domain}{tag}.json"
        source.write_text(json.dumps({"context": context}) + "\n", encoding="utf-8")
        return _run_cli(
            "scripts/domain_shards.py", "write-context-shard",
            "--run-dir", str(run_dir), "--domain", domain, "--input", str(source),
        )

    def write_all_context(self, run_dir: Path, directory: Path, manifest: dict[str, Any]) -> None:
        for domain, context in sorted(self.context_inputs(manifest).items()):
            result = self.write_context(run_dir, directory, domain, context)
            self.assertEqual(result.returncode, 0, result.stderr)

    def status(self, run_dir: Path) -> dict[str, Any]:
        result = _run_cli("scripts/domain_shards.py", "status", "--run-dir", str(run_dir))
        self.assertEqual(result.returncode, 0, f"status must not crash: {result.stderr}")
        return json.loads(result.stdout)

    def test_unknown_entry_remains_writable_but_blocks_merge(self) -> None:
        """Test A: UNKNOWN is truthful writable shard data, never merge-ready."""
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            run_dir, manifest = self.make_run(directory)
            inputs = self.context_inputs(manifest)
            domain, key = "evm-audit-oracles", "heartbeat"
            inputs[domain][key] = {"status": "UNKNOWN"}
            for name, context in sorted(inputs.items()):
                result = self.write_context(run_dir, directory, name, context)
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((run_dir / f"reviews/shards/context-{domain}.json").exists())

            payload = self.status(run_dir)
            self.assertFalse(payload["context_merge_ready"])
            self.assertEqual(payload["unresolved_context"], [f"{domain}.{key}"])
            entry = next(item for item in payload["context_shards"] if item["owner_domain"] == domain)
            self.assertTrue(entry["valid"], "an UNKNOWN shard is valid data, not a malformed shard")
            self.assertEqual(entry["unresolved_required"], [f"{domain}.{key}"])

            merge = _run_cli("scripts/domain_shards.py", "merge-context", "--run-dir", str(run_dir))
            self.assertNotEqual(merge.returncode, 0)
            self.assertIn(f"merged context remains UNKNOWN for: {domain}.{key}", merge.stderr)
            self.assertFalse((run_dir / "reviews/domain-context.json").exists())

    def test_policy_valid_trusted_absence_is_accepted_and_merges(self) -> None:
        """Test B: scope + inheritance trusted absence passes the Domain policy."""
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            run_dir, manifest = self.make_run(directory)
            inputs = self.context_inputs(manifest)
            domain, key = "evm-audit-oracles", "heartbeat"
            inputs[domain][key] = {
                "status": "NOT_APPLICABLE",
                "scope_complete": True,
                "evidence": self.SCOPE_EVIDENCE + self.INHERITANCE_EVIDENCE,
            }
            for name, context in sorted(inputs.items()):
                result = self.write_context(run_dir, directory, name, context)
                self.assertEqual(result.returncode, 0, result.stderr)

            self.assertTrue(self.status(run_dir)["context_merge_ready"])
            merge = _run_cli("scripts/domain_shards.py", "merge-context", "--run-dir", str(run_dir))
            self.assertEqual(merge.returncode, 0, merge.stderr)
            merged = load_json(run_dir / "reviews/domain-context.json")
            self.assertEqual(
                merged["domains"][domain][key]["status"], "NOT_APPLICABLE",
            )

    def test_disallowed_absence_evidence_kind_is_rejected_at_write_time(self) -> None:
        """Test C: scope + source is schema-valid but policy-invalid; nothing is persisted."""
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            run_dir, manifest = self.make_run(directory)
            inputs = self.context_inputs(manifest)
            domain, key = "evm-audit-oracles", "heartbeat"
            inputs[domain][key] = {
                "status": "NOT_APPLICABLE",
                "scope_complete": True,
                "evidence": self.SCOPE_EVIDENCE + self.SOURCE_EVIDENCE,
            }
            result = self.write_context(run_dir, directory, domain, inputs[domain])
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(f"{domain}.{key}", result.stderr)
            self.assertIn("trusted_absence_policy", result.stderr)
            self.assertFalse(
                (run_dir / f"reviews/shards/context-{domain}.json").exists(),
                "an invalid shard must not be persisted",
            )
            payload = self.status(run_dir)
            self.assertIn(domain, payload["missing_context_shards"])
            self.assertFalse(payload["context_merge_ready"])

    def test_missing_scope_evidence_is_rejected_at_write_time(self) -> None:
        """Test D: exclusion-dimension evidence alone never proves absence."""
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            run_dir, manifest = self.make_run(directory)
            inputs = self.context_inputs(manifest)
            domain, key = "evm-audit-oracles", "heartbeat"
            inputs[domain][key] = {
                "status": "NOT_APPLICABLE",
                "scope_complete": True,
                "evidence": self.INHERITANCE_EVIDENCE,
            }
            result = self.write_context(run_dir, directory, domain, inputs[domain])
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("requires scope evidence", result.stderr)
            self.assertFalse((run_dir / f"reviews/shards/context-{domain}.json").exists())

    def test_incomplete_scope_is_rejected_at_write_time(self) -> None:
        """Test E: scope_complete must be true for trusted absence."""
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            run_dir, manifest = self.make_run(directory)
            inputs = self.context_inputs(manifest)
            domain, key = "evm-audit-oracles", "heartbeat"
            inputs[domain][key] = {
                "status": "NOT_APPLICABLE",
                "scope_complete": False,
                "evidence": self.SCOPE_EVIDENCE + self.INHERITANCE_EVIDENCE,
            }
            result = self.write_context(run_dir, directory, domain, inputs[domain])
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((run_dir / f"reviews/shards/context-{domain}.json").exists())

    def test_missing_exclusion_dimension_is_rejected_at_write_time(self) -> None:
        """Test F: scope evidence alone never proves absence."""
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            run_dir, manifest = self.make_run(directory)
            inputs = self.context_inputs(manifest)
            domain, key = "evm-audit-oracles", "heartbeat"
            inputs[domain][key] = {
                "status": "NOT_APPLICABLE",
                "scope_complete": True,
                "evidence": self.SCOPE_EVIDENCE,
            }
            result = self.write_context(run_dir, directory, domain, inputs[domain])
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("exclusion dimension", result.stderr)
            self.assertFalse((run_dir / f"reviews/shards/context-{domain}.json").exists())

    def test_failed_replacement_preserves_prior_valid_shard(self) -> None:
        """Test G: a rejected rewrite leaves the existing shard byte-for-byte intact."""
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            run_dir, manifest = self.make_run(directory)
            domain = "evm-audit-oracles"
            valid = self.context_inputs(manifest)[domain]
            result = self.write_context(run_dir, directory, domain, valid)
            self.assertEqual(result.returncode, 0, result.stderr)
            shard_path = run_dir / f"reviews/shards/context-{domain}.json"
            original = shard_path.read_bytes()

            invalid = {
                **valid,
                "heartbeat": {
                    "status": "NOT_APPLICABLE",
                    "scope_complete": True,
                    "evidence": self.SCOPE_EVIDENCE + self.SOURCE_EVIDENCE,
                },
            }
            result = self.write_context(run_dir, directory, domain, invalid, tag="-invalid")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(shard_path.read_bytes(), original)
            leftovers = [path.name for path in shard_path.parent.iterdir() if path.name != shard_path.name]
            self.assertEqual(leftovers, [], "a failed write must leave no partial temporary shard")

    def test_hand_edited_invalid_shard_remains_diagnosable(self) -> None:
        """Test H: write-time validation is backed by status/merge defense in depth."""
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            run_dir, manifest = self.make_run(directory)
            self.write_all_context(run_dir, directory, manifest)
            self.assertTrue(self.status(run_dir)["context_merge_ready"])

            # Bypass the writer entirely, as a hand edit would.
            domain = "evm-audit-oracles"
            shard_path = run_dir / f"reviews/shards/context-{domain}.json"
            shard = load_json(shard_path)
            shard["context"]["heartbeat"] = {
                "status": "NOT_APPLICABLE",
                "scope_complete": True,
                "evidence": self.SCOPE_EVIDENCE + self.SOURCE_EVIDENCE,
            }
            shard_path.write_text(json.dumps(shard) + "\n", encoding="utf-8")

            payload = self.status(run_dir)
            self.assertIn(domain, payload["invalid_context_shards"])
            self.assertFalse(payload["context_merge_ready"])
            entry = next(item for item in payload["context_shards"] if item["owner_domain"] == domain)
            self.assertFalse(entry["valid"])
            self.assertIn("trusted_absence_policy", entry["error"])

            merge = _run_cli("scripts/domain_shards.py", "merge-context", "--run-dir", str(run_dir))
            self.assertNotEqual(merge.returncode, 0)
            self.assertIn("trusted_absence_policy", merge.stderr)
            self.assertFalse((run_dir / "reviews/domain-context.json").exists())


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
