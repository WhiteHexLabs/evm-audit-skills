"""Regression tests for artifact lineage and false-clean boundaries."""

from __future__ import annotations

import hashlib
import errno
import json
import multiprocessing
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.audit_artifacts import (
    atomic_write_json,
    canonical_sha256,
    check_body_hash,
    derive_review_snapshot_id,
    fsync_parent_directory,
    reporting_inputs_digest,
    reporting_inputs_digest_from_hashes,
    validate_generated_artifact_path,
    validate_issue_candidates,
)
from scripts.audit_run import _ensure_reporting_templates, _report_bundle_status, _runtime_view_current, paths as audit_paths
from scripts.render_runtime import domain_context_template, domain_resolution_template, render, runtime_identity, runtime_metadata, screen_results_template
from scripts.review_ledger import append
from evm_audit_runtime.output_layout import validate_managed_output_root
from scripts.scope_context import compilation_digests, resolve_build_root, scope_inventory
from scripts.synthesize_report import main as synthesize_main, synthesize
from scripts.validate_audit_run import validate_run

from helpers import EMPTY_TARGET, ROOT, build_manifest
from scripts.recon import main as recon_main


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _sharing_violation() -> PermissionError:
    error = PermissionError("simulated Windows sharing violation")
    error.winerror = 32
    return error


def _atomic_write_worker(path: str, value: dict, writes: int, result_queue) -> None:
    try:
        for _ in range(writes):
            atomic_write_json(Path(path), value)
        result_queue.put("ok")
    except BaseException as exc:  # pragma: no cover - asserted by the parent
        result_queue.put(repr(exc))


class HardeningTests(unittest.TestCase):
    def issue_artifact(self, manifest: dict, state: dict, findings: list[dict]) -> dict:
        return {
            "schema_version": 2,
            "routing_snapshot_id": manifest["routing_snapshot_id"],
            "review_snapshot_id": state["review_snapshot_id"],
            "review_state_digest": state["review_state_digest"],
            **{
                key: manifest["audit_context"][key]
                for key in ("registry_sha256", "source_digest", "compilation_input_digest")
            },
            "findings": findings,
        }

    def issue_state(self, manifest: dict, confirmed: list[str]) -> dict:
        return {
            "status": "COMPLETE_WITH_FINDINGS",
            "review_snapshot_id": "1" * 64,
            "review_state_digest": "2" * 64,
            "coverage": {"confirmed": confirmed},
        }

    def test_reporting_digest_from_hashes_matches_exact_bytes_helper(self) -> None:
        severity = b"severity\n"
        details = b"details\n"
        poc = b"poc\n"
        self.assertEqual(
            reporting_inputs_digest_from_hashes(
                severity_decisions_sha256=hashlib.sha256(severity).hexdigest(),
                finding_details_sha256=hashlib.sha256(details).hexdigest(),
                poc_evidence_sha256=hashlib.sha256(poc).hexdigest(),
            ),
            reporting_inputs_digest(
                severity_bytes=severity,
                finding_details_bytes=details,
                poc_evidence_bytes=poc,
            ),
        )
        self.assertIsNone(
            reporting_inputs_digest_from_hashes(
                severity_decisions_sha256=None,
                finding_details_sha256=None,
                poc_evidence_sha256=None,
            )
        )

    def test_generated_artifact_paths_respect_the_managed_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            audit = root / "project"
            build = root / "build"
            audit.mkdir()
            build.mkdir()
            # Standalone use keeps the legacy strict rule.
            for candidate in (audit, audit / "run", build / "run"):
                with self.subTest(candidate=candidate):
                    with self.assertRaisesRegex(ValueError, "outside"):
                        validate_generated_artifact_path(
                            candidate,
                            audit_root=audit,
                            build_root=build,
                            label="artifact",
                        )
            managed = build / ".evm-auditor-work"
            validate_generated_artifact_path(
                managed / "report-bundle.json",
                audit_root=audit,
                build_root=build,
                label="artifact",
                managed_output_root=managed,
            )
            # Unmanaged project paths stay forbidden even with a managed root.
            for candidate, pattern in (
                (build / "src" / "evil.json", "managed output root"),
                (managed / ".." / "escape.json", "managed output root"),
                (audit / "evil.json", "managed output root"),
            ):
                with self.subTest(candidate=candidate):
                    with self.assertRaisesRegex(ValueError, pattern):
                        validate_generated_artifact_path(
                            candidate,
                            audit_root=audit,
                            build_root=build,
                            label="artifact",
                            managed_output_root=managed,
                        )

    def test_managed_output_boundary_replaces_total_run_dir_isolation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build = root / "project"
            audit = build / "src"
            audit.mkdir(parents=True)
            with self.assertRaisesRegex(ValueError, "build root"):
                validate_managed_output_root(build, audit_root=audit, build_root=build)
            with self.assertRaisesRegex(ValueError, "narrower audit root"):
                validate_managed_output_root(audit / "run", audit_root=audit, build_root=build)
            self.assertEqual(
                validate_managed_output_root(
                    build / ".evm-auditor-work", audit_root=audit, build_root=build
                ),
                "PROJECT_LOCAL",
            )
            self.assertEqual(
                validate_managed_output_root(root / "run", audit_root=audit, build_root=build),
                "EXTERNAL",
            )

    def test_parent_directory_fsync_only_ignores_unsupported_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.json"
            with patch("scripts.audit_artifacts.os.fsync", side_effect=OSError(errno.EINVAL, "unsupported")):
                self.assertFalse(fsync_parent_directory(path))
            with patch("scripts.audit_artifacts.os.fsync", side_effect=OSError(errno.EIO, "io")):
                with self.assertRaisesRegex(OSError, "io"):
                    fsync_parent_directory(path)

    def test_atomic_write_retries_windows_sharing_violations(self) -> None:
        """A sharing-violation os.replace is retried and still lands atomically."""
        real_replace = os.replace
        state = {"failures": 0}

        def replace_with_transient_conflict(source, target):
            state["failures"] += 1
            if state["failures"] <= 2:
                raise _sharing_violation()
            return real_replace(source, target)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.json"
            with patch("scripts.audit_artifacts.os.replace", side_effect=replace_with_transient_conflict):
                atomic_write_json(path, {"value": 1})
            self.assertEqual(state["failures"], 3)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"value": 1})
            self.assertEqual(
                [item.name for item in path.parent.iterdir()],
                [path.name],
                "a successful retry must not leak temporary files",
            )

        # Permission problems that are not sharing violations fail immediately.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.json"
            with patch("scripts.audit_artifacts.os.replace", side_effect=PermissionError(13, "real permission problem")):
                with self.assertRaisesRegex(PermissionError, "real permission problem"):
                    atomic_write_json(path, {"value": 1})
            self.assertEqual([item.name for item in path.parent.iterdir()], [], "a failed write must not leak temporary files")

    def test_atomic_write_replace_retry_exhaustion_preserves_original_error(self) -> None:
        """Exhausting the sharing-violation budget re-raises and cleans up."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.json"
            path.write_text("previous\n", encoding="utf-8")
            with patch("scripts.audit_artifacts.os.replace", side_effect=_sharing_violation()), patch(
                "scripts.audit_artifacts.ATOMIC_REPLACE_RETRY_SECONDS", 0.0
            ), patch("scripts.audit_artifacts.ATOMIC_REPLACE_RETRY_INTERVAL", 0.0):
                with self.assertRaisesRegex(PermissionError, "simulated Windows sharing violation"):
                    atomic_write_json(path, {"value": 1})
            self.assertEqual(
                [item.name for item in path.parent.iterdir()],
                [path.name],
                "the failed write must leave the previous artifact and no temporaries",
            )
            self.assertEqual(path.read_text(encoding="utf-8"), "previous\n")

    def test_concurrent_atomic_writes_never_corrupt_or_leak_temporaries(self) -> None:
        """Two processes replacing one artifact always leave a valid file.

        On Windows this exercises the real sharing-violation retry path; on
        POSIX it pins the same integrity invariant. Mirrors concurrent
        ``status_run`` callers re-deriving ``audit-state.json``.
        """
        context = multiprocessing.get_context("spawn")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit-state.json"
            payloads = [{"writer": index} for index in range(2)]
            result_queue = context.Queue()
            workers = [
                context.Process(target=_atomic_write_worker, args=(str(path), payload, 40, result_queue))
                for payload in payloads
            ]
            for worker in workers:
                worker.start()
            outcomes = [result_queue.get(timeout=60) for _ in workers]
            for worker in workers:
                worker.join(timeout=60)
                self.assertEqual(worker.exitcode, 0)
            self.assertEqual(outcomes, ["ok", "ok"])
            final = json.loads(path.read_text(encoding="utf-8"))
            self.assertIn(final, payloads)
            self.assertEqual(
                [item.name for item in path.parent.iterdir()],
                [path.name],
                "concurrent replacements must not leak temporary files",
            )

    def test_bundle_rejects_missing_required_high_issue_candidate(self) -> None:
        _, _, _, manifest = build_manifest()
        state = self.issue_state(manifest, ["FINDING-HIGH"])
        severity = {"decisions": {"FINDING-HIGH": {"severity": "High"}}}
        value = self.issue_artifact(manifest, state, [])
        with self.assertRaisesRegex(ValueError, "exact severity projection"):
            validate_issue_candidates(ROOT, manifest, state, value, severity)

    def test_bundle_rejects_low_issue_candidate(self) -> None:
        _, _, _, manifest = build_manifest()
        state = self.issue_state(manifest, ["FINDING-MEDIUM", "FINDING-LOW"])
        severity = {
            "decisions": {
                "FINDING-MEDIUM": {"severity": "Medium"},
                "FINDING-LOW": {"severity": "Low"},
            }
        }
        value = self.issue_artifact(
            manifest,
            state,
            [
                {"canonical_id": "FINDING-MEDIUM", "severity": "Medium"},
                {"canonical_id": "FINDING-LOW", "severity": "High"},
            ],
        )
        with self.assertRaisesRegex(ValueError, "exact severity projection"):
            validate_issue_candidates(ROOT, manifest, state, value, severity)

    def test_bundle_rejects_issue_severity_mismatch(self) -> None:
        _, _, _, manifest = build_manifest()
        state = self.issue_state(manifest, ["FINDING"])
        severity = {"decisions": {"FINDING": {"severity": "High"}}}
        value = self.issue_artifact(manifest, state, [{"canonical_id": "FINDING", "severity": "Medium"}])
        with self.assertRaisesRegex(ValueError, "exact severity projection"):
            validate_issue_candidates(ROOT, manifest, state, value, severity)

    def test_bundle_rejects_issue_candidate_without_severity_decision(self) -> None:
        _, _, _, manifest = build_manifest()
        state = self.issue_state(manifest, ["FINDING-A", "FINDING-B"])
        severity = {"decisions": {"FINDING-A": {"severity": "High"}}}
        value = self.issue_artifact(manifest, state, [{"canonical_id": "FINDING-A", "severity": "High"}])
        with self.assertRaisesRegex(ValueError, "severity decision IDs"):
            validate_issue_candidates(ROOT, manifest, state, value, severity)

    def test_multi_output_clis_reject_exact_and_symlink_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "output.json"
            self.assertEqual(
                recon_main([
                    str(EMPTY_TARGET), "--output", str(output), "--code-index-out", str(output), "--quiet",
                ]),
                1,
            )
            link = root / "link.json"
            link.symlink_to(output)
            self.assertEqual(
                recon_main([
                    str(EMPTY_TARGET), "--output", str(output), "--code-index-out", str(link), "--quiet",
                ]),
                1,
            )
            self.assertEqual(
                synthesize_main([
                    "--manifest", str(root / "missing-manifest.json"),
                    "--screen-results", str(root / "missing-screen.json"),
                    "--domain-context", str(root / "missing-context.json"),
                    "--context", str(root / "missing-audit-context.json"),
                    "--output", str(output), "--issue-candidates-out", str(output),
                ]),
                1,
            )
            self.assertEqual(
                synthesize_main([
                    "--manifest", str(root / "missing-manifest.json"),
                    "--screen-results", str(root / "missing-screen.json"),
                    "--domain-context", str(root / "missing-context.json"),
                    "--context", str(root / "missing-audit-context.json"),
                    "--output", str(output), "--issue-candidates-out", str(link),
                ]),
                1,
            )

    def test_recon_rejects_feature_map_output_over_target(self) -> None:
        self.assertEqual(
            recon_main([str(EMPTY_TARGET), "--output", str(EMPTY_TARGET), "--quiet"]),
            1,
        )

    def test_recon_rejects_code_index_output_over_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "feature-map.json"
            self.assertEqual(
                recon_main([
                    str(EMPTY_TARGET), "--output", str(output),
                    "--code-index-out", str(EMPTY_TARGET), "--quiet",
                ]),
                1,
            )

    def test_recon_rejects_symlink_alias_to_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            alias = root / "Target.sol"
            alias.symlink_to(EMPTY_TARGET)
            output = root / "feature-map.json"
            self.assertEqual(
                recon_main([
                    str(EMPTY_TARGET), "--output", str(output),
                    "--code-index-out", str(alias), "--quiet",
                ]),
                1,
            )

    def test_recon_allows_normal_output_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "recon" / "feature-map.json"
            output.parent.mkdir()
            self.assertEqual(
                recon_main([str(EMPTY_TARGET), "--output", str(output), "--quiet"]),
                0,
            )
            self.assertTrue(output.exists())

    def context(self, manifest: dict, resolution: dict | None = None) -> dict:
        value = domain_context_template(manifest, resolution)
        for requirements in value["domains"].values():
            for item in requirements.values():
                item.update(
                    status="KNOWN",
                    value="fixture",
                    evidence=[{"kind": "scope", "location": "fixture", "reason": "known context"}],
                )
        return value

    def screen(self, manifest: dict, resolution: dict | None = None, *, candidate: bool) -> tuple[dict, str]:
        value = screen_results_template(manifest, resolution)
        candidate_id = value["results"][0]["canonical_id"]
        evidence = [
            {"kind": "scope", "location": "fixture", "reason": "complete scope"},
            {"kind": "inheritance", "location": "fixture", "reason": "screen disposition"},
        ]
        for item in value["results"]:
            if candidate and item["canonical_id"] == candidate_id:
                continue
            item.update(result="NOT_APPLICABLE_CONFIRMED", scope_complete=True, evidence=evidence)
        return value, candidate_id

    def review_record(self, registry: dict, manifest: dict, canonical_id: str, *, confirmed: bool = False) -> dict:
        route = next(item for item in manifest["selected"] if item["canonical_id"] == canonical_id)
        check = next(item for item in registry["checks"] if item["canonical_id"] == canonical_id)
        value = {
            "record_type": "review",
            "schema_version": 7,
            "canonical_id": canonical_id,
            "owner_domain": route["owner_domain"],
            "check_body_hash": check_body_hash(check),
            "review_stage": "PROOF" if confirmed else "DEEP_REVIEW",
            "status": "CONFIRMED" if confirmed else "REVIEWED_SAFE",
            "applicability": "APPLICABLE - fixture",
            "code_path": "fixture entry",
            "preconditions": "fixture state",
            "exploitability": "fixture path is reachable",
            "impact": "fixture impact" if confirmed else "none",
            "proof": "deterministic fixture trace",
            "evidence": [{"kind": "trace", "location": "fixture", "reason": "deterministic trace"}],
        }
        if not confirmed:
            value["preserved_invariant"] = "fixture invariant holds"
        return value

    def append_confirmed_record(
        self, ledger: Path, registry: dict, manifest: dict, candidate_id: str,
        domain_context: dict, screen: dict,
    ) -> None:
        deep = self.review_record(registry, manifest, candidate_id)
        deep.update(
            review_stage="DEEP_REVIEW",
            status="SUSPICIOUS",
            unresolved_reason="proof is pending",
            evidence=[{"kind": "manual", "location": "fixture", "reason": "deep review concern"}],
        )
        append(ledger, manifest, deep, registry, {candidate_id}, domain_context=domain_context, screen_results=screen)
        proof = self.review_record(registry, manifest, candidate_id, confirmed=True)
        proof["revision"] = 2
        append(ledger, manifest, proof, registry, {candidate_id}, domain_context=domain_context, screen_results=screen)

    @staticmethod
    def context_artifact(manifest: dict) -> dict:
        return {**manifest["audit_context"], "routing_snapshot_id": manifest["routing_snapshot_id"]}

    def test_context_and_screen_mutations_stale_existing_review(self) -> None:
        registry, _, _, manifest = build_manifest()
        domain_context = self.context(manifest)
        screen, candidate_id = self.screen(manifest, candidate=True)
        context = self.context_artifact(manifest)
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "review.jsonl"
            append(
                ledger,
                manifest,
                self.review_record(registry, manifest, candidate_id),
                registry,
                {candidate_id},
                domain_context=domain_context,
                screen_results=screen,
            )
            clean = validate_run(ROOT, manifest, registry, screen, None, domain_context, context, [ledger])
            self.assertEqual(clean["status"], "COMPLETE_CLEAN")

            first_domain = next(iter(domain_context["domains"]))
            first_key = next(iter(domain_context["domains"][first_domain]))
            domain_context["domains"][first_domain][first_key]["value"] = "changed context"
            stale_context = validate_run(ROOT, manifest, registry, screen, None, domain_context, context, [ledger])
            self.assertEqual(stale_context["status"], "INCOMPLETE_REVIEW")
            self.assertTrue(any("review_snapshot_id" in reason for reason in stale_context["reasons"]))

            domain_context = self.context(manifest)
            screen["results"][1]["evidence"][1]["reason"] = "changed screen evidence"
            stale_screen = validate_run(ROOT, manifest, registry, screen, None, domain_context, context, [ledger])
            self.assertEqual(stale_screen["status"], "INCOMPLETE_REVIEW")
            self.assertTrue(any("review_snapshot_id" in reason for reason in stale_screen["reasons"]))

    def test_review_snapshot_preserves_ordered_values_and_normalizes_set_like_results(self) -> None:
        _, _, _, manifest = build_manifest()
        domain_context = self.context(manifest)
        screen, _ = self.screen(manifest, candidate=False)
        domain = next(iter(domain_context["domains"]))
        key = next(iter(domain_context["domains"][domain]))
        domain_context["domains"][domain][key]["value"] = ["chainlink", "twap"]
        first = derive_review_snapshot_id(ROOT, manifest, None, domain_context, screen)

        reversed_context = json.loads(json.dumps(domain_context))
        reversed_context["domains"][domain][key]["value"] = ["twap", "chainlink"]
        self.assertNotEqual(
            first,
            derive_review_snapshot_id(ROOT, manifest, None, reversed_context, screen),
        )

        permuted_screen = json.loads(json.dumps(screen))
        permuted_screen["results"].reverse()
        for item in permuted_screen["results"]:
            item["evidence"].reverse()
        self.assertEqual(
            first,
            derive_review_snapshot_id(ROOT, manifest, None, domain_context, permuted_screen),
        )
        self.assertEqual(
            canonical_sha256({"a": 1, "b": 2}),
            canonical_sha256({"b": 2, "a": 1}),
        )

    def test_ordered_domain_context_mutation_stales_existing_review(self) -> None:
        registry, _, _, manifest = build_manifest()
        domain_context = self.context(manifest)
        screen, candidate_id = self.screen(manifest, candidate=True)
        domain = next(iter(domain_context["domains"]))
        key = next(iter(domain_context["domains"][domain]))
        domain_context["domains"][domain][key]["value"] = ["A", "B"]
        context = self.context_artifact(manifest)
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "review.jsonl"
            append(
                ledger,
                manifest,
                self.review_record(registry, manifest, candidate_id),
                registry,
                {candidate_id},
                domain_context=domain_context,
                screen_results=screen,
            )
            clean = validate_run(ROOT, manifest, registry, screen, None, domain_context, context, [ledger])
            self.assertEqual(clean["status"], "COMPLETE_CLEAN")

            domain_context["domains"][domain][key]["value"] = ["B", "A"]
            stale = validate_run(ROOT, manifest, registry, screen, None, domain_context, context, [ledger])
            self.assertNotEqual(clean["review_snapshot_id"], stale["review_snapshot_id"])
            self.assertEqual(stale["status"], "INCOMPLETE_REVIEW")
            self.assertTrue(any("review_snapshot_id" in reason for reason in stale["reasons"]))

    def test_domain_resolution_mutation_stales_existing_review(self) -> None:
        registry, _, _, manifest = build_manifest(domains=None)
        resolution = domain_resolution_template(manifest)
        for item in resolution["domains"].values():
            item.update(
                status="ABSENT_CONFIRMED",
                scope_complete=True,
                evidence=[
                    {"kind": "scope", "location": "fixture", "reason": "complete scope"},
                    {"kind": "inheritance", "location": "fixture", "reason": "domain surface absent"},
                ],
            )
        domain_context = self.context(manifest, resolution)
        screen, candidate_id = self.screen(manifest, resolution, candidate=True)
        context = self.context_artifact(manifest)
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "review.jsonl"
            append(
                ledger,
                manifest,
                self.review_record(registry, manifest, candidate_id),
                registry,
                {candidate_id},
                resolution,
                domain_context=domain_context,
                screen_results=screen,
            )
            self.assertEqual(
                validate_run(ROOT, manifest, registry, screen, resolution, domain_context, context, [ledger])["status"],
                "COMPLETE_CLEAN",
            )
            resolution["domains"][next(iter(resolution["domains"]))]["evidence"][0]["reason"] = "changed resolution evidence"
            stale = validate_run(ROOT, manifest, registry, screen, resolution, domain_context, context, [ledger])
            self.assertEqual(stale["status"], "INCOMPLETE_REVIEW")

    def test_required_context_not_applicable_requires_trusted_complete_scope(self) -> None:
        _, _, _, manifest = build_manifest()
        context = self.context(manifest)
        domain = next(iter(context["domains"]))
        key = next(iter(context["domains"][domain]))
        context["domains"][domain][key] = {
            "status": "NOT_APPLICABLE",
            "scope_complete": True,
            "evidence": [{"kind": "manual", "location": "fixture", "reason": "manual assertion"}],
        }
        from scripts.audit_artifacts import validate_domain_context

        with self.assertRaisesRegex(ValueError, "exclusion dimension"):
            validate_domain_context(ROOT, manifest, context)
        context["domains"][domain][key]["scope_complete"] = False
        with self.assertRaises(ValueError):
            validate_domain_context(ROOT, manifest, context)
        context["domains"][domain][key] = {
            "status": "NOT_APPLICABLE",
            "scope_complete": True,
            "evidence": [
                {"kind": "scope", "location": "fixture", "reason": "complete scope"},
                {"kind": "dependency", "location": "fixture", "reason": "required component absent"},
            ],
        }
        self.assertEqual(validate_domain_context(ROOT, manifest, context), set())
        context["domains"][domain][key] = {"status": "UNKNOWN", "evidence": []}
        with self.assertRaisesRegex(ValueError, "remains UNKNOWN"):
            validate_domain_context(ROOT, manifest, context, require_complete=True)

    def test_runtime_view_requires_matching_body_and_sidecar_hash(self) -> None:
        registry, _, _, manifest = build_manifest()
        candidate_ids = {manifest["selected"][0]["canonical_id"]}
        body = render(manifest, registry, "deep", candidate_ids)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "deep.md"
            metadata_path = output.with_suffix(".meta.json")
            output.write_bytes(body.encode("utf-8"))
            metadata = runtime_metadata(
                manifest,
                "deep",
                sorted(candidate_ids),
                None,
                None,
                hashlib.sha256(body.encode("utf-8")).hexdigest(),
            )
            write_json(metadata_path, metadata)
            expected = runtime_identity(manifest, "deep", sorted(candidate_ids), None, None)
            self.assertTrue(_runtime_view_current(output, expected))

            output.write_bytes(body[: len(body) // 2].encode("utf-8"))
            self.assertFalse(_runtime_view_current(output, expected))
            output.write_bytes(body.encode("utf-8"))

            metadata_path.write_text("{\n", encoding="utf-8")
            self.assertFalse(_runtime_view_current(output, expected))
            write_json(metadata_path, metadata)
            metadata["runtime_sha256"] = "0" * 64
            write_json(metadata_path, metadata)
            self.assertFalse(_runtime_view_current(output, expected))
            write_json(metadata_path, runtime_metadata(
                manifest,
                "deep",
                sorted(candidate_ids),
                None,
                None,
                hashlib.sha256(body.encode("utf-8")).hexdigest(),
            ))

            output.write_text(body + "interrupted", encoding="utf-8")
            self.assertFalse(_runtime_view_current(output, expected))
            output.write_bytes(body.encode("utf-8"))
            self.assertTrue(_runtime_view_current(output, expected))

    def test_single_file_compilation_scope_and_lib_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "src/Target.sol"
            dependency = root / "src/Dependency.sol"
            internal_lib = root / "src/lib/Foo.sol"
            external_lib = root / "lib/openzeppelin/Foo.sol"
            first_party_lib = root / "lib/MyProtocol.sol"
            for path in (target, dependency, internal_lib, external_lib, first_party_lib):
                path.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('pragma solidity ^0.8.24; import "./Dependency.sol"; contract Target is Dependency {}', encoding="utf-8")
            dependency.write_text("pragma solidity ^0.8.24; contract Dependency {}", encoding="utf-8")
            internal_lib.write_text("pragma solidity ^0.8.24; contract Foo {}", encoding="utf-8")
            external_lib.write_text("pragma solidity ^0.8.24; contract OpenZeppelinFoo {}", encoding="utf-8")
            first_party_lib.write_text("pragma solidity ^0.8.24; contract MyProtocol {}", encoding="utf-8")
            (root / "foundry.toml").write_text('[profile.default]\nsrc = "src"\n', encoding="utf-8")

            included, excluded = scope_inventory(root)
            self.assertIn("src/lib/Foo.sol", included)
            self.assertIn("lib/MyProtocol.sol", excluded)
            included, _ = scope_inventory(root, include_patterns=("lib/MyProtocol.sol",))
            self.assertIn("lib/MyProtocol.sol", included)
            self.assertNotIn("lib/openzeppelin/Foo.sol", included)

            files, _ = scope_inventory(target)
            before = compilation_digests(target, files, "0.8.24", build_root=root)
            target.write_text('pragma solidity ^0.8.24; import "./Dependency.sol"; contract Target is Dependency { uint256 changed; }', encoding="utf-8")
            after_target = compilation_digests(target, files, "0.8.24", build_root=root)
            self.assertNotEqual(before["audit_source_digest"], after_target["audit_source_digest"])
            self.assertNotEqual(before["compilation_input_digest"], after_target["compilation_input_digest"])
            target.write_text('pragma solidity ^0.8.24; import "./Dependency.sol"; contract Target is Dependency {}', encoding="utf-8")
            dependency.write_text("pragma solidity ^0.8.24; contract Dependency { uint256 changed; }", encoding="utf-8")
            after_dependency = compilation_digests(target, files, "0.8.24", build_root=root)
            self.assertEqual(before["audit_source_digest"], after_dependency["audit_source_digest"])
            self.assertNotEqual(before["compilation_input_digest"], after_dependency["compilation_input_digest"])
            (root / "foundry.toml").write_text('[profile.default]\nsrc = "contracts"\n', encoding="utf-8")
            after_config = compilation_digests(target, files, "0.8.24", build_root=root)
            self.assertNotEqual(after_dependency["compilation_input_digest"], after_config["compilation_input_digest"])

    def test_directory_scope_discovers_nearest_project_build_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            source = project / "src"
            dependency = project / "lib/Dependency.sol"
            for path in (source / "Vault.sol", source / "Helper.sol", dependency):
                path.parent.mkdir(parents=True, exist_ok=True)
            (project / "foundry.toml").write_text('[profile.default]\nsrc = "src"\n', encoding="utf-8")
            (project / "remappings.txt").write_text("dep/=lib/\n", encoding="utf-8")
            (source / "Vault.sol").write_text("pragma solidity ^0.8.24; contract Vault {}", encoding="utf-8")
            (source / "Helper.sol").write_text("pragma solidity ^0.8.24; contract Helper {}", encoding="utf-8")
            dependency.write_text("pragma solidity ^0.8.24; contract Dependency {}", encoding="utf-8")

            self.assertEqual(resolve_build_root(source, boundary=project), project.resolve())
            files, _ = scope_inventory(source)
            before = compilation_digests(source, files, "0.8.24", boundary=project)
            (project / "foundry.toml").write_text('[profile.default]\nsrc = "contracts"\n', encoding="utf-8")
            after_config = compilation_digests(source, files, "0.8.24", boundary=project)
            self.assertNotEqual(before["compilation_input_digest"], after_config["compilation_input_digest"])
            dependency.write_text("pragma solidity ^0.8.24; contract Dependency { uint256 changed; }", encoding="utf-8")
            after_dependency = compilation_digests(source, files, "0.8.24", boundary=project)
            self.assertNotEqual(after_config["compilation_input_digest"], after_dependency["compilation_input_digest"])

            repo = root / "repo"
            protocol = repo / "packages/protocol"
            (repo / "package.json").parent.mkdir(parents=True, exist_ok=True)
            (repo / "package.json").write_text("{}", encoding="utf-8")
            (protocol / "foundry.toml").parent.mkdir(parents=True, exist_ok=True)
            (protocol / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            nested_source = protocol / "src"
            nested_source.mkdir()
            self.assertEqual(resolve_build_root(nested_source, boundary=repo), protocol.resolve())

            override = root
            self.assertEqual(resolve_build_root(source, override), override.resolve())
            outside = root / "outside"
            outside.mkdir()
            with self.assertRaisesRegex(ValueError, "inside build root"):
                resolve_build_root(source, outside)

    def test_build_root_inference_does_not_escape_acquisition_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            acquisition = root / "acquisition"
            source = acquisition / "src"
            source.mkdir(parents=True)
            (source / "Target.sol").write_text("pragma solidity ^0.8.0; contract Target {}", encoding="utf-8")
            (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            self.assertEqual(resolve_build_root(source, boundary=acquisition), source.resolve())
            with self.assertRaisesRegex(ValueError, "acquisition boundary"):
                resolve_build_root(source, boundary=root / "missing")

    def test_reporting_templates_refresh_and_preserve_completed_artifacts(self) -> None:
        _, _, _, manifest = build_manifest()
        candidate_id = manifest["selected"][0]["canonical_id"]
        second_candidate_id = manifest["selected"][1]["canonical_id"]
        digest_one = "1" * 64
        digest_two = "2" * 64
        state_one = {"review_state_digest": digest_one, "coverage": {"confirmed": [candidate_id]}}
        state_two = {"review_state_digest": digest_two, "coverage": {"confirmed": [candidate_id]}}
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            first = _ensure_reporting_templates(manifest, state_one, run_dir)
            self.assertEqual(first["template_status"], {"severity": "GENERATED_TEMPLATE", "finding_details": "GENERATED_TEMPLATE"})
            severity_path = run_dir / "reviews/severity-decisions.json"
            details_path = run_dir / "reviews/finding-details.json"
            original = severity_path.read_text(encoding="utf-8")
            self.assertEqual(json.loads(original)["review_state_digest"], digest_one)
            self.assertEqual(json.loads(original)["artifact_state"], "TEMPLATE")

            unchanged = _ensure_reporting_templates(manifest, state_one, run_dir)
            self.assertEqual(unchanged["template_status"]["severity"], "CURRENT_TEMPLATE")
            self.assertEqual(severity_path.read_text(encoding="utf-8"), original)

            refreshed = _ensure_reporting_templates(manifest, state_two, run_dir)
            self.assertEqual(refreshed["template_status"]["severity"], "REGENERATED_STALE_TEMPLATE")
            self.assertEqual(json.loads(severity_path.read_text(encoding="utf-8"))["review_state_digest"], digest_two)

            changed_set = _ensure_reporting_templates(
                manifest,
                {"review_state_digest": digest_two, "coverage": {"confirmed": [candidate_id, second_candidate_id]}},
                run_dir,
            )
            self.assertEqual(changed_set["template_status"]["severity"], "REGENERATED_STALE_TEMPLATE")
            self.assertEqual(
                set(json.loads(severity_path.read_text(encoding="utf-8"))["decisions"]),
                {candidate_id, second_candidate_id},
            )
            _ensure_reporting_templates(manifest, state_two, run_dir)

            completed_severity = json.loads(severity_path.read_text(encoding="utf-8"))
            completed_severity["artifact_state"] = "COMPLETED"
            completed_severity["decisions"][candidate_id] = {
                "severity": "High",
                "rationale": "completed rationale",
                "dimensions": {
                    "impact": "none", "exploitability": "permissionless", "privileges": "none",
                    "capital_required": "none", "repeatability": "one_shot", "user_interaction": "none",
                    "loss_bound": "none", "protocol_exposure": "single_position", "recoverability": "irreversible",
                },
            }
            completed_severity["review_state_digest"] = digest_one
            severity_path.write_text(json.dumps(completed_severity) + "\n", encoding="utf-8")
            completed_details = json.loads(details_path.read_text(encoding="utf-8"))
            completed_details["artifact_state"] = "COMPLETED"
            completed_details["review_state_digest"] = digest_one
            completed_details["findings"][0].update(description="completed description", recommendation="completed fix")
            details_path.write_text(json.dumps(completed_details) + "\n", encoding="utf-8")

            archived = _ensure_reporting_templates(manifest, state_two, run_dir)
            self.assertEqual(archived["template_status"]["severity"], "ARCHIVED_STALE_ARTIFACT")
            self.assertEqual(archived["template_status"]["finding_details"], "ARCHIVED_STALE_ARTIFACT")
            self.assertIn("completed rationale", Path(archived["archived_templates"]["severity"]).read_text(encoding="utf-8"))
            self.assertEqual(json.loads(severity_path.read_text(encoding="utf-8"))["artifact_state"], "TEMPLATE")

    def test_review_state_digest_rejects_stale_reporting_inputs(self) -> None:
        registry, _, _, manifest = build_manifest()
        domain_context = self.context(manifest)
        screen, candidate_id = self.screen(manifest, candidate=True)
        context = self.context_artifact(manifest)
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "review.jsonl"
            self.append_confirmed_record(ledger, registry, manifest, candidate_id, domain_context, screen)
            state = validate_run(ROOT, manifest, registry, screen, None, domain_context, context, [ledger])
            digest = state["review_state_digest"]
            identity = {
                "schema_version": 2,
                "routing_snapshot_id": manifest["routing_snapshot_id"],
                "review_state_digest": digest,
                **{key: manifest["audit_context"][key] for key in ("registry_sha256", "source_digest", "compilation_input_digest")},
            }
            severity = {
                **identity,
                "decisions": {
                    candidate_id: {
                        "severity": "Medium",
                        "rationale": "proof-bound fixture impact",
                        "dimensions": {
                            "impact": "none", "exploitability": "permissionless", "privileges": "none",
                            "capital_required": "none", "repeatability": "one_shot", "user_interaction": "none",
                            "loss_bound": "none", "protocol_exposure": "single_position", "recoverability": "irreversible",
                        },
                    }
                },
            }
            details = {**identity, "findings": [{"canonical_id": candidate_id, "location": "Fixture.sol:1", "description": "fixture", "recommendation": "fix"}]}
            synthesize(ROOT, manifest, registry, state, [ledger], severity, finding_details=details, screen_results=screen, domain_context=domain_context, context=context)

            records = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines()]
            records[-1]["proof"] = "changed current proof"
            ledger.write_text("".join(json.dumps(record, sort_keys=True) + "\n" for record in records), encoding="utf-8")
            Path(f"{ledger}.commit.json").unlink()
            with self.assertRaisesRegex(ValueError, "mismatched review_state_digest"):
                synthesize(ROOT, manifest, registry, state, [ledger], severity, finding_details=details, screen_results=screen, domain_context=domain_context, context=context)

    def test_registry_mutation_invalidates_current_state(self) -> None:
        registry, _, _, manifest = build_manifest()
        domain_context = self.context(manifest)
        screen, _ = self.screen(manifest, candidate=False)
        changed_registry = json.loads(json.dumps(registry))
        changed_registry["checks"][0]["title"] += " changed"
        state = validate_run(
            ROOT,
            manifest,
            changed_registry,
            screen,
            None,
            domain_context,
            self.context_artifact(manifest),
            [],
        )
        self.assertEqual(state["status"], "INVALID_SNAPSHOT")
        self.assertTrue(any("registry" in reason for reason in state["reasons"]))

    def test_severity_and_details_mutation_rewrites_final_report(self) -> None:
        registry, _, _, manifest = build_manifest()
        domain_context = self.context(manifest)
        screen, candidate_id = self.screen(manifest, candidate=True)
        context = self.context_artifact(manifest)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, context_path = root / "manifest.json", root / "context.json"
            domain_context_path, screen_path = root / "domain-context.json", root / "screen-results.json"
            state_path, ledger = root / "audit-state.json", root / "review.jsonl"
            severity_path, details_path = root / "severity.json", root / "details.json"
            report_path, issues_path = root / "AUDIT-REPORT.md", root / "issue-candidates.json"
            bundle_path = root / "report-bundle.json"
            for path, value in ((manifest_path, manifest), (context_path, context), (domain_context_path, domain_context), (screen_path, screen)):
                write_json(path, value)
            self.append_confirmed_record(ledger, registry, manifest, candidate_id, domain_context, screen)
            state = validate_run(ROOT, manifest, registry, screen, None, domain_context, context, [ledger])
            write_json(state_path, state)
            identity = {
                "schema_version": 2,
                "routing_snapshot_id": manifest["routing_snapshot_id"],
                "review_state_digest": state["review_state_digest"],
                **{key: manifest["audit_context"][key] for key in ("registry_sha256", "source_digest", "compilation_input_digest")},
            }
            severity = {**identity, "decisions": {candidate_id: {"severity": "Low", "rationale": "first", "dimensions": {
                "impact": "none", "exploitability": "permissionless", "privileges": "none",
                "capital_required": "none", "repeatability": "one_shot", "user_interaction": "none",
                "loss_bound": "none", "protocol_exposure": "single_position", "recoverability": "irreversible",
            }}}}
            details = {**identity, "findings": [{"canonical_id": candidate_id, "location": "Fixture.sol:1", "description": "first description", "recommendation": "first fix"}]}
            write_json(severity_path, severity)
            write_json(details_path, details)
            command = [
                "--manifest", str(manifest_path), "--audit-state", str(state_path), "--context", str(context_path),
                "--domain-context", str(domain_context_path), "--screen-results", str(screen_path), "--ledger", str(ledger),
                "--severity-decisions", str(severity_path), "--finding-details", str(details_path),
                "--output", str(report_path), "--issue-candidates-out", str(issues_path),
                "--bundle-metadata-out", str(bundle_path),
            ]
            self.assertEqual(synthesize_main(command), 0)
            first_bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
            severity["decisions"][candidate_id]["severity"] = "Medium"
            details["findings"][0]["description"] = "updated description"
            write_json(severity_path, severity)
            write_json(details_path, details)
            write_json(state_path, {**state, "status": "INCOMPLETE_REVIEW", "complete": False, "review_state_digest": "0" * 64})
            self.assertEqual(synthesize_main(command), 0)
            second_bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
            report = report_path.read_text(encoding="utf-8")
            self.assertIn("**Severity:** Medium", report)
            self.assertIn("updated description", report)
            self.assertEqual(second_bundle["review_state_digest"], state["review_state_digest"])
            self.assertNotEqual(first_bundle["severity_decisions_sha256"], second_bundle["severity_decisions_sha256"])
            self.assertNotEqual(first_bundle["finding_details_sha256"], second_bundle["finding_details_sha256"])

    def test_report_bundle_rejects_tampered_bodies_and_stale_digest(self) -> None:
        registry, _, _, manifest = build_manifest()
        domain_context = self.context(manifest)
        screen, _ = self.screen(manifest, candidate=False)
        context = self.context_artifact(manifest)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, context_path = root / "manifest.json", root / "context.json"
            domain_context_path, screen_path = root / "domain-context.json", root / "screen-results.json"
            state_path = root / "audit-state.json"
            report_path, issues_path = root / "AUDIT-REPORT.md", root / "issue-candidates.json"
            bundle_path = root / "report-bundle.json"
            for path, value in ((manifest_path, manifest), (context_path, context), (domain_context_path, domain_context), (screen_path, screen)):
                write_json(path, value)
            state = validate_run(ROOT, manifest, registry, screen, None, domain_context, context, [])
            write_json(state_path, state)
            command = [
                "--manifest", str(manifest_path), "--audit-state", str(state_path), "--context", str(context_path),
                "--domain-context", str(domain_context_path), "--screen-results", str(screen_path),
                "--output", str(report_path), "--issue-candidates-out", str(issues_path),
                "--bundle-metadata-out", str(bundle_path),
            ]
            self.assertEqual(synthesize_main(command), 0)
            values = audit_paths(root)
            self.assertFalse(_report_bundle_status(ROOT, values, manifest, state)["current"])
            bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
            self.assertIsNone(bundle["severity_decisions_sha256"])
            self.assertIsNone(bundle["finding_details_sha256"])

            report = report_path.read_text(encoding="utf-8")
            report_path.write_text(report + "tampered\n", encoding="utf-8")
            self.assertEqual(_report_bundle_status(ROOT, values, manifest, state)["status"], "ABSENT")
            self.assertEqual(synthesize_main(command), 0)

            issues = json.loads(issues_path.read_text(encoding="utf-8"))
            issues_path.write_text(json.dumps(issues, separators=(",", ":")) + "\n", encoding="utf-8")
            self.assertEqual(_report_bundle_status(ROOT, values, manifest, state)["status"], "ABSENT")
            stale_state = {**state, "review_state_digest": "0" * 64}
            self.assertEqual(_report_bundle_status(ROOT, values, manifest, stale_state)["status"], "ABSENT")

            base_issues = json.loads(issues_path.read_text(encoding="utf-8"))
            mutations = {
                "wrong registry": lambda value: value.update(registry_sha256="0" * 64),
                "wrong source": lambda value: value.update(source_digest="0" * 64),
                "wrong compilation": lambda value: value.update(compilation_input_digest="0" * 64),
                "unknown ID": lambda value: value.update(findings=[{"canonical_id": "UNKNOWN-001", "severity": "High"}]),
                "non-confirmed ID": lambda value: value.update(findings=[{"canonical_id": manifest["selected"][0]["canonical_id"], "severity": "High"}]),
                "duplicate ID": lambda value: value.update(findings=[{"canonical_id": "UNKNOWN-001", "severity": "High"}, {"canonical_id": "UNKNOWN-001", "severity": "High"}]),
                "invalid schema": lambda value: value.pop("findings"),
            }
            for name, mutate in mutations.items():
                changed = json.loads(json.dumps(base_issues))
                mutate(changed)
                raw = (json.dumps(changed, separators=(",", ":")) + "\n").encode("utf-8")
                issues_path.write_bytes(raw)
                changed_bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
                changed_bundle["issue_candidates_sha256"] = hashlib.sha256(raw).hexdigest()
                bundle_path.write_text(json.dumps(changed_bundle) + "\n", encoding="utf-8")
                with self.subTest(case=name):
                    self.assertFalse(_report_bundle_status(ROOT, values, manifest, state)["current"])
                self.assertEqual(synthesize_main(command), 0)

    def test_failed_direct_synthesis_preserves_previous_final_outputs(self) -> None:
        registry, _, _, manifest = build_manifest()
        domain_context = self.context(manifest)
        screen, candidate_id = self.screen(manifest, candidate=False)
        context = self.context_artifact(manifest)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = root / "manifest.json"
            context_path = root / "context.json"
            domain_context_path = root / "domain-context.json"
            screen_path = root / "screen-results.json"
            state_path = root / "audit-state.json"
            report_path = root / "AUDIT-REPORT.md"
            issues_path = root / "issue-candidates.json"
            for path, value in ((manifest_path, manifest), (context_path, context), (domain_context_path, domain_context), (screen_path, screen)):
                write_json(path, value)
            write_json(state_path, validate_run(ROOT, manifest, registry, screen, None, domain_context, context, []))
            self.assertEqual(
                synthesize_main([
                    "--manifest", str(manifest_path), "--audit-state", str(state_path), "--context", str(context_path),
                    "--domain-context", str(domain_context_path), "--screen-results", str(screen_path),
                    "--output", str(report_path), "--issue-candidates-out", str(issues_path),
                ]),
                0,
            )
            self.assertIn("COMPLETE_CLEAN", report_path.read_text(encoding="utf-8"))
            previous_report = report_path.read_text(encoding="utf-8")
            previous_issues = issues_path.read_text(encoding="utf-8")

            screen, candidate_id = self.screen(manifest, candidate=True)
            write_json(screen_path, screen)
            ledger = root / "review.jsonl"
            self.append_confirmed_record(ledger, registry, manifest, candidate_id, domain_context, screen)
            self.assertEqual(
                synthesize_main([
                    "--manifest", str(manifest_path), "--audit-state", str(state_path), "--context", str(context_path),
                    "--domain-context", str(domain_context_path), "--screen-results", str(screen_path), "--ledger", str(ledger),
                    "--output", str(report_path), "--issue-candidates-out", str(issues_path),
                ]),
                1,
            )
            self.assertEqual(report_path.read_text(encoding="utf-8"), previous_report)
            self.assertEqual(issues_path.read_text(encoding="utf-8"), previous_issues)


if __name__ == "__main__":
    unittest.main()
