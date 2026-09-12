"""Orchestration lifecycle tests: controller `next` is the wave transition barrier.

These tests drive the actual controller state machine over shard-authored
runs and assert, at every worker-stage transition, the returned stage, the
recommended worker agent, and that the per-owner runtime views a worker must
read exist before dispatch. They also pin the zero-candidate and
no-suspicious fast paths that skip Deep Review and Proof.
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

from helpers import ROOT, build_manifest, load_json, suite_inputs
from scripts.audit_run import main as audit_run_main
from scripts.codex_model_profile import default_profile, write_profile
from scripts.domain_shards import (
    merge_context,
    merge_screen,
    write_context_shard,
    write_screen_shard,
)
from scripts.render_runtime import domain_context_template, selected_entries
from scripts.review_ledger import SCHEMA_VERSION, append, write_ledger

DOMAINS = ("evm-audit-general", "evm-audit-erc20")
ABSENCE_EVIDENCE = [
    {"kind": "scope", "location": "fixture", "reason": "complete scope"},
    {"kind": "inheritance", "location": "fixture", "reason": "domain surface absent"},
]
SCOPE_EVIDENCE = [{"kind": "scope", "location": "fixture", "reason": "complete scope"}]


class OrchestrationLifecycleTests(unittest.TestCase):
    def make_run(self, directory: Path) -> tuple[Path, dict[str, Any]]:
        """Materialize a two-Domain run directory bound to a zcode profile."""
        _, _, _, manifest = build_manifest(domains=DOMAINS)
        run_dir = directory / "run"
        (run_dir / "routing").mkdir(parents=True)
        (run_dir / "routing" / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        (run_dir / "config").mkdir()
        (run_dir / "context.json").write_text(
            json.dumps(
                {**manifest["audit_context"], "routing_snapshot_id": manifest["routing_snapshot_id"]},
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        write_profile(run_dir / "config/codex-model-profile.json", default_profile("zcode"))
        return run_dir, manifest

    def next_stage(self, run_dir: Path) -> dict[str, Any]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = audit_run_main(["next", "--run-dir", str(run_dir), "--quiet"])
        self.assertEqual(code, 0, stderr.getvalue())
        return json.loads(stdout.getvalue())

    def assert_stage(
        self,
        result: dict[str, Any],
        stage: str,
        *,
        agent: str | None,
    ) -> None:
        self.assertEqual(result["stage"], stage)
        execution = result["recommended_execution"]
        self.assertEqual(execution["provider"], "zcode")
        self.assertEqual(
            execution.get("agent"),
            agent,
            f"{stage} handoff must name the shipped worker contract",
        )

    def view_names(self, run_dir: Path, profile: str) -> list[str]:
        runtime = run_dir / "runtime"
        return sorted(path.name for path in runtime.glob(f"{profile}-*.md"))

    def author_context_shards(self, run_dir: Path, directory: Path, manifest: dict[str, Any]) -> None:
        template = domain_context_template(manifest)
        for domain, requirements in sorted(template["domains"].items()):
            context = {
                key: {"status": "KNOWN", "value": "fixture", "evidence": SCOPE_EVIDENCE}
                for key in requirements
            }
            source = directory / f"context-{domain}.json"
            source.write_text(json.dumps({"context": context}) + "\n", encoding="utf-8")
            write_context_shard(ROOT, run_dir, domain, source)

    def author_screen_shards(
        self,
        run_dir: Path,
        directory: Path,
        manifest: dict[str, Any],
        *,
        result: str,
    ) -> None:
        by_domain: dict[str, list[dict[str, Any]]] = {}
        for entry in selected_entries(manifest):
            by_domain.setdefault(entry["owner_domain"], []).append(
                {
                    "canonical_id": entry["canonical_id"],
                    "result": result,
                    "scope_complete": result == "NOT_APPLICABLE_CONFIRMED",
                    "evidence": ABSENCE_EVIDENCE if result == "NOT_APPLICABLE_CONFIRMED" else [],
                }
            )
        for domain, results in sorted(by_domain.items()):
            source = directory / f"screen-{domain}.json"
            source.write_text(json.dumps({"results": results}) + "\n", encoding="utf-8")
            write_screen_shard(ROOT, run_dir, domain, source)

    def deep_records(
        self,
        run_dir: Path,
        manifest: dict[str, Any],
        *,
        suspicious_id: str | None,
    ) -> dict[str, list[dict[str, Any]]]:
        screen = load_json(run_dir / "reviews/screen-results.json")
        routes = {entry["canonical_id"]: entry for entry in manifest["selected"]}
        records: dict[str, list[dict[str, Any]]] = {}
        for entry in screen["results"]:
            canonical_id = entry["canonical_id"]
            record: dict[str, Any] = {
                "record_type": "review",
                "schema_version": SCHEMA_VERSION,
                "canonical_id": canonical_id,
                "owner_domain": routes[canonical_id]["owner_domain"],
                "check_body_hash": routes[canonical_id]["check_body_hash"],
                "review_stage": "DEEP_REVIEW",
                "status": "SUSPICIOUS" if canonical_id == suspicious_id else "REVIEWED_SAFE",
                "applicability": "APPLICABLE — fixture path exists",
                "code_path": "fixture entry",
                "preconditions": "fixture precondition",
                "exploitability": "fixture path is reachable",
                "impact": "fixture impact",
                "proof": "deterministic fixture proof",
                "evidence": [
                    {
                        "kind": "test",
                        "location": "tests/test_orchestration.py",
                        "reason": "deterministic fixture proof",
                    }
                ],
            }
            if canonical_id == suspicious_id:
                record["unresolved_reason"] = "proof is pending"
            else:
                record["preserved_invariant"] = "fixture invariant holds"
            records.setdefault(record["owner_domain"], []).append(record)
        return records

    def write_domain_ledgers(
        self,
        run_dir: Path,
        manifest: dict[str, Any],
        records: dict[str, list[dict[str, Any]]],
    ) -> None:
        registry, _, _ = suite_inputs()
        domain_context = load_json(run_dir / "reviews/domain-context.json")
        screen = load_json(run_dir / "reviews/screen-results.json")
        for domain, domain_records in sorted(records.items()):
            write_ledger(
                run_dir / f"reviews/review-{domain}.jsonl",
                manifest,
                domain_records,
                registry=registry,
                domain_context=domain_context,
                screen_results=screen,
            )

    def append_proof_resolution(
        self,
        run_dir: Path,
        manifest: dict[str, Any],
        canonical_id: str,
        *,
        status: str,
        unresolved_reason: str = "proof is pending",
    ) -> None:
        registry, _, _ = suite_inputs()
        route = next(entry for entry in manifest["selected"] if entry["canonical_id"] == canonical_id)
        record = {
            "record_type": "review",
            "schema_version": SCHEMA_VERSION,
            "canonical_id": canonical_id,
            "owner_domain": route["owner_domain"],
            "check_body_hash": route["check_body_hash"],
            "review_stage": "PROOF",
            "status": status,
            "applicability": "APPLICABLE — fixture path exists",
            "code_path": "fixture entry",
            "preconditions": "fixture precondition",
            "exploitability": "fixture path is reachable",
            "impact": "fixture impact",
            "proof": "deterministic fixture trace proof",
            "evidence": [
                {
                    "kind": "trace",
                    "location": "tests/test_orchestration.py",
                    "reason": "deterministic trace",
                }
            ],
        }
        if status == "SUSPICIOUS":
            record["unresolved_reason"] = unresolved_reason
        elif status != "CONFIRMED":
            record["preserved_invariant"] = "fixture invariant holds"
        append(
            run_dir / f"reviews/review-{route['owner_domain']}.jsonl",
            manifest,
            record,
            registry=registry,
            domain_context=load_json(run_dir / "reviews/domain-context.json"),
            screen_results=load_json(run_dir / "reviews/screen-results.json"),
        )

    def test_candidates_and_suspicious_drive_deep_and_proof_waves(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            run_dir, manifest = self.make_run(directory)

            # Controller head: the context wave handoff names the flash worker.
            result = self.next_stage(run_dir)
            self.assert_stage(result, "DOMAIN_CONTEXT", agent="evm-audit-worker-flash")
            self.assertEqual(self.view_names(run_dir, "deep"), [])
            self.assertEqual(self.view_names(run_dir, "proof"), [])

            self.author_context_shards(run_dir, directory, manifest)
            merge_context(ROOT, run_dir)

            # Barrier A: the merge does not advance the stage; `next` does,
            # and it must return SCREEN with the deep worker contract.
            result = self.next_stage(run_dir)
            self.assert_stage(result, "SCREEN", agent="evm-audit-worker-deep")

            self.author_screen_shards(run_dir, directory, manifest, result="CANDIDATE")
            merge_screen(ROOT, run_dir)

            # Barrier B: `next` renders the deep runtime views before any
            # Deep worker can be dispatched.
            result = self.next_stage(run_dir)
            self.assert_stage(result, "DEEP_REVIEW", agent="evm-audit-worker-deep")
            pending = result["pending"]
            candidate_owners = {
                entry["owner_domain"]
                for entry in selected_entries(manifest)
                if entry["canonical_id"] in set(pending)
            }
            self.assertEqual(
                self.view_names(run_dir, "deep"),
                sorted(f"deep-{owner}.md" for owner in candidate_owners),
            )
            self.assertEqual(self.view_names(run_dir, "proof"), [])

            # Wave C: one SUSPICIOUS record owned by the ERC-20 domain; every
            # other candidate resolves REVIEWED_SAFE.
            erc20_ids = sorted(
                entry["canonical_id"]
                for entry in selected_entries(manifest)
                if entry["owner_domain"] == "evm-audit-erc20"
            )
            suspicious_id = erc20_ids[0]
            self.write_domain_ledgers(
                run_dir, manifest, self.deep_records(run_dir, manifest, suspicious_id=suspicious_id)
            )

            # The suspicious record moves the state to PROOF, and `next`
            # renders proof runtime views for exactly that owner.
            result = self.next_stage(run_dir)
            self.assert_stage(result, "PROOF", agent="evm-audit-worker-proof")
            self.assertEqual(result["pending"], [suspicious_id])
            self.assertEqual(
                result["runtime_views"],
                [str((run_dir / "runtime" / "proof-evm-audit-erc20.md").resolve())],
            )
            self.assertEqual(self.view_names(run_dir, "proof"), ["proof-evm-audit-erc20.md"])

            # Wave D resolves the suspicious record; `next` must reach REPORT
            # and prune the proof views.
            self.append_proof_resolution(run_dir, manifest, suspicious_id, status="CONFIRMED")
            result = self.next_stage(run_dir)
            self.assert_stage(result, "REPORT", agent=None)
            self.assertEqual(self.view_names(run_dir, "proof"), [])

    def test_zero_candidates_skip_deep_review_and_proof(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            run_dir, manifest = self.make_run(directory)

            result = self.next_stage(run_dir)
            self.assert_stage(result, "DOMAIN_CONTEXT", agent="evm-audit-worker-flash")
            self.author_context_shards(run_dir, directory, manifest)
            merge_context(ROOT, run_dir)
            result = self.next_stage(run_dir)
            self.assert_stage(result, "SCREEN", agent="evm-audit-worker-deep")

            self.author_screen_shards(run_dir, directory, manifest, result="NOT_APPLICABLE_CONFIRMED")
            merge_screen(ROOT, run_dir)

            # Stale views from an earlier epoch must be pruned when no
            # candidates remain.
            stale = run_dir / "runtime"
            stale.mkdir(exist_ok=True)
            (stale / "deep-evm-audit-general.md").write_text("stale\n", encoding="utf-8")
            (stale / "proof-evm-audit-general.md").write_text("stale\n", encoding="utf-8")

            result = self.next_stage(run_dir)
            self.assert_stage(result, "REPORT", agent=None)
            self.assertEqual(self.view_names(run_dir, "deep"), [])
            self.assertEqual(self.view_names(run_dir, "proof"), [])
            self.assertFalse((run_dir / "reviews/review-evm-audit-general.jsonl").exists())

    def test_suspicious_revision_bump_re_renders_the_proof_view(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            run_dir, manifest = self.make_run(directory)

            self.next_stage(run_dir)
            self.author_context_shards(run_dir, directory, manifest)
            merge_context(ROOT, run_dir)
            self.next_stage(run_dir)
            self.author_screen_shards(run_dir, directory, manifest, result="CANDIDATE")
            merge_screen(ROOT, run_dir)
            self.next_stage(run_dir)

            erc20_ids = sorted(
                entry["canonical_id"]
                for entry in selected_entries(manifest)
                if entry["owner_domain"] == "evm-audit-erc20"
            )
            suspicious_id = erc20_ids[0]
            self.write_domain_ledgers(
                run_dir, manifest, self.deep_records(run_dir, manifest, suspicious_id=suspicious_id)
            )

            result = self.next_stage(run_dir)
            self.assert_stage(result, "PROOF", agent="evm-audit-worker-proof")
            view = run_dir / "runtime" / "proof-evm-audit-erc20.md"
            rendered = view.read_text(encoding="utf-8")
            self.assertIn("revision `1`", rendered)
            self.assertIn("proof is pending", rendered)
            mtime = view.stat().st_mtime_ns

            # A follow-up SUSPICIOUS revision keeps the record unresolved but
            # changes the ledger content; the proof view must be re-rendered
            # instead of serving the revision-1 view as current.
            self.append_proof_resolution(
                run_dir,
                manifest,
                suspicious_id,
                status="SUSPICIOUS",
                unresolved_reason="revision 2: refined pending reason",
            )
            result = self.next_stage(run_dir)
            self.assert_stage(result, "PROOF", agent="evm-audit-worker-proof")
            self.assertEqual(result["pending"], [suspicious_id])
            rendered = view.read_text(encoding="utf-8")
            self.assertIn("revision `2`", rendered)
            self.assertIn("revision 2: refined pending reason", rendered)
            self.assertNotIn("proof is pending", rendered)
            self.assertNotEqual(view.stat().st_mtime_ns, mtime)

    def test_no_suspicious_records_skip_proof(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            run_dir, manifest = self.make_run(directory)

            self.next_stage(run_dir)
            self.author_context_shards(run_dir, directory, manifest)
            merge_context(ROOT, run_dir)
            self.next_stage(run_dir)
            self.author_screen_shards(run_dir, directory, manifest, result="CANDIDATE")
            merge_screen(ROOT, run_dir)

            result = self.next_stage(run_dir)
            self.assert_stage(result, "DEEP_REVIEW", agent="evm-audit-worker-deep")
            self.write_domain_ledgers(run_dir, manifest, self.deep_records(run_dir, manifest, suspicious_id=None))

            (run_dir / "runtime").mkdir(exist_ok=True)
            (run_dir / "runtime" / "proof-evm-audit-general.md").write_text("stale\n", encoding="utf-8")

            result = self.next_stage(run_dir)
            self.assert_stage(result, "REPORT", agent=None)
            self.assertEqual(self.view_names(run_dir, "proof"), [])


if __name__ == "__main__":
    unittest.main()
