#!/usr/bin/env python3
"""Tests for runtime artifacts and audit completion safety."""

from __future__ import annotations

import json
import hashlib
import multiprocessing
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from scripts.audit_artifacts import (
    bind_routing_snapshot,
    resolved_routes,
    validate_context,
    validate_domain_context,
    validate_domain_resolution,
)
from scripts.render_runtime import domain_context_template, domain_resolution_template, render, screen_results_template, validate_manifest, validate_screen_results
from scripts import review_ledger
from scripts.review_ledger import _ledger_lock, append, check_body_hash, checkpoint, collect_review_history, collect_review_records, load, render_markdown, validate_record, validate_records, write_ledger
from scripts.scope_context import find_suite_root
from scripts.select_checks import audit_context, load_domains, normalize_feature_map, select
from scripts.validate_audit_run import validate_run

from helpers import EMPTY_TARGET, ROOT, build_manifest, load_json, review_inputs, suite_inputs, synthetic_feature_map


def _append_ledger_worker(path: str, manifest: dict, record: dict, registry: dict, expected_ids: set[str], domain_context: dict, screen_results: dict, result_queue: Any) -> None:
    try:
        append(Path(path), manifest, record, registry, expected_ids, domain_context=domain_context, screen_results=screen_results)
    except Exception as error:  # pragma: no cover - asserted through the result queue
        result_queue.put(("error", type(error).__name__, str(error)))
    else:
        result_queue.put(("ok", record["canonical_id"]))


def _read_ledger_worker(path: str, start_event: Any, result_queue: Any) -> None:
    try:
        start_event.wait()
        for _ in range(50):
            for record in load(Path(path)):
                json.dumps(record)
            time.sleep(0.001)
    except Exception as error:  # pragma: no cover - asserted through the result queue
        result_queue.put(("error", type(error).__name__, str(error)))
    else:
        result_queue.put(("ok", "reader"))


class RuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry, cls.feature_names, cls.feature_policies = suite_inputs()

    def test_suite_runtime_paths_resolve_shared_files(self) -> None:
        master = ROOT / "skills/evm-audit-master/SKILL.md"
        root = find_suite_root(master)
        self.assertEqual(root, ROOT)
        for name in ("data", "domains", "scripts"):
            with self.subTest(name=name):
                self.assertTrue((root / name).is_dir())
        master_text = master.read_text(encoding="utf-8")
        self.assertIn("<suite-root>/scripts/", master_text)
        self.assertNotIn("../scripts/", master_text)
        self.assertIn("docs/audit-runtime.md", master_text)
        self.assertNotIn("scripts/recon.py", master_text)
        self.assertNotIn("scripts/select_checks.py", master_text)
        self.assertNotIn("scripts/render_runtime.py", master_text)

        skill = ROOT / "skills/evm-audit-erc20/SKILL.md"
        self.assertEqual(find_suite_root(skill), ROOT)
        self.assertTrue((ROOT / "data/canonical-checks.json").exists())
        self.assertTrue((ROOT / "domains/erc20.json").exists())
        self.assertTrue((ROOT / "scripts/select_checks.py").exists())
        self.assertIn(
            "<suite-root>/skills/evm-audit-master/references/check-review-contract.runtime.md",
            skill.read_text(encoding="utf-8"),
        )

    def test_selector_single_snapshot_writes_manifest_and_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            feature_path = temp / "feature-map.json"
            feature_path.write_text(json.dumps(synthetic_feature_map()), encoding="utf-8")
            manifest_path, checks_path, context_path = temp / "manifest.json", temp / "screen.md", temp / "context.json"
            result = subprocess.run(
                [
                    sys.executable,
                    "scripts/select_checks.py",
                    "--feature-map",
                    str(feature_path),
                    "--target-root",
                    "tests/fixtures/recon/Empty.sol",
                    "--domain",
                    "evm-audit-erc20",
                    "--manifest-out",
                    str(manifest_path),
                    "--context-out",
                    str(context_path),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = load_json(manifest_path)
            self.assertTrue(manifest_path.exists() and context_path.exists())
            render_result = subprocess.run(
                [
                    sys.executable,
                    "scripts/render_runtime.py",
                    "--manifest",
                    str(manifest_path),
                    "--profile",
                    "screen",
                    "--output",
                    str(checks_path),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(render_result.returncode, 0, render_result.stderr)
            runtime = checks_path.read_text(encoding="utf-8")
            for entry in manifest["selected"]:
                self.assertIn(f"[{entry['canonical_id']}]", runtime)
            self.assertNotIn("LIKELY_SAFE", runtime)

    def test_routing_manifest_covers_scope_and_shared_owner(self) -> None:
        registry, _, _, manifest = build_manifest(
            ("evm-audit-general", "evm-audit-precision-math"),
            all_features=True,
        )
        self.assertEqual(manifest["schema_version"], 8)
        self.assertTrue(manifest["immutable"])
        self.assertIn("target_repo_commit", manifest["audit_context"])
        shared = next(
            entry
            for entry in manifest["selected"] + manifest["filtered"]
            if entry["canonical_id"] == "EVM-TIME-001"
        )
        self.assertEqual(shared["owner_domain"], "evm-audit-precision-math")
        validate_manifest(ROOT, manifest, registry)

    def deferred_shared_manifest(self) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
        raw = synthetic_feature_map()
        features = normalize_feature_map(raw, self.feature_names, self.feature_policies, EMPTY_TARGET)
        context = audit_context(
            ROOT,
            self.registry,
            raw["recon_context"],
            target_root=EMPTY_TARGET,
            audit_timestamp="test",
        )
        environment = {
            **{key: context[key] for key in (
                "chain_id", "chain_family", "execution_environment", "compiler_version",
                "evm_fork", "protocol_version",
            )},
            "environment_facts": context["environment_facts"],
        }
        configs = load_domains(ROOT)
        configs["evm-audit-general"] = {
            **configs["evm-audit-general"],
            "always_screen": False,
        }
        manifest, _ = select(
            self.registry,
            features,
            self.feature_names,
            None,
            context,
            configs,
            environment,
            raw["recon_context"],
        )
        return self.registry, raw, manifest, domain_resolution_template(manifest)

    def test_deferred_shared_owner_moves_to_present_domain(self) -> None:
        registry, _, manifest, resolution = (*self.deferred_shared_manifest(),)
        primary = "evm-audit-precision-math"
        fallback = "evm-audit-general"
        resolution["domains"][primary] = {
            "status": "ABSENT_CONFIRMED",
            "scope_complete": True,
            "evidence": [
                {"kind": "scope", "location": "fixture", "reason": "complete scope"},
                {"kind": "inheritance", "location": "fixture", "reason": "domain surface absent"},
            ],
        }
        resolution["domains"][fallback] = {
            "status": "PRESENT",
            "scope_complete": False,
            "evidence": [{"kind": "source", "location": "fixture", "reason": "surface exists"}],
        }
        for domain, item in resolution["domains"].items():
            if item["status"] == "UNKNOWN":
                resolution["domains"][domain] = {
                    "status": "ABSENT_CONFIRMED",
                    "scope_complete": True,
                    "evidence": [
                        {"kind": "scope", "location": "fixture", "reason": "complete scope"},
                        {"kind": "inheritance", "location": "fixture", "reason": "domain surface absent"},
                    ],
                }
        shared_id = "EVM-TIME-001"
        manifest_route = next(entry for entry in manifest["deferred"] if entry["canonical_id"] == shared_id)
        self.assertEqual(manifest_route["owner_domain"], primary)
        active = [entry for entry in resolved_routes(manifest, resolution) if entry["canonical_id"] == shared_id]
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["owner_domain"], fallback)
        self.assertIn(f"[{shared_id}]", render(manifest, registry, "screen", set(), fallback, resolution))
        self.assertNotIn(f"[{shared_id}]", render(manifest, registry, "screen", set(), primary, resolution))

        check = next(item for item in registry["checks"] if item["canonical_id"] == shared_id)
        record = {
            "record_type": "review",
            "schema_version": 7,
            "canonical_id": shared_id,
            "revision": 1,
            "owner_domain": fallback,
            "routing_snapshot_id": manifest["routing_snapshot_id"],
            "check_body_hash": check_body_hash(check),
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
        record.update({key: manifest["audit_context"][key] for key in (
            "registry_sha256", "source_digest", "compilation_input_digest",
        )})
        screen, domain_context, snapshot = review_inputs(manifest, resolution)
        record["review_snapshot_id"] = snapshot
        self.assertEqual(validate_record(record, manifest, registry, {shared_id}, resolution, snapshot), [])

    def test_deferred_shared_owner_prefers_active_manifest_owner(self) -> None:
        registry, _, manifest, resolution = (*self.deferred_shared_manifest(),)
        for domain in ("evm-audit-precision-math", "evm-audit-general"):
            resolution["domains"][domain] = {
                "status": "PRESENT",
                "scope_complete": False,
                "evidence": [{"kind": "source", "location": "fixture", "reason": "surface exists"}],
            }
        shared = [entry for entry in resolved_routes(manifest, resolution) if entry["canonical_id"] == "EVM-TIME-001"]
        self.assertEqual(len(shared), 1)
        self.assertEqual(shared[0]["owner_domain"], "evm-audit-precision-math")

    def test_deferred_shared_owner_disappears_when_all_domains_absent(self) -> None:
        _, _, manifest, resolution = (*self.deferred_shared_manifest(),)
        for domain, item in resolution["domains"].items():
            item.update(
                status="ABSENT_CONFIRMED",
                scope_complete=True,
                evidence=[
                    {"kind": "scope", "location": "fixture", "reason": "complete scope"},
                    {"kind": "inheritance", "location": "fixture", "reason": "domain surface absent"},
                ],
            )
        self.assertFalse(any(entry["canonical_id"] == "EVM-TIME-001" for entry in resolved_routes(manifest, resolution)))
        self.assertEqual(screen_results_template(manifest, resolution)["results"], [])

    def test_selected_primary_owner_does_not_change_after_resolution(self) -> None:
        _, _, _, manifest = build_manifest(
            ("evm-audit-general", "evm-audit-precision-math"),
            all_features=True,
        )
        shared = [entry for entry in resolved_routes(manifest) if entry["canonical_id"] == "EVM-TIME-001"]
        self.assertEqual(len(shared), 1)
        self.assertEqual(shared[0]["owner_domain"], "evm-audit-precision-math")

    def test_routing_manifest_rejects_invalid_shape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path = Path(directory) / "manifest.json"
            manifest_path.write_text(json.dumps({
                "schema_version": 1,
                "stage": "FAST_FILTER",
                "scope": {"domains": ["evm-audit-precision-math"], "candidate_count": 1},
                "feature_map": {"schema_version": 99, "features": {}},
                "selected_count": 0,
                "filtered_count": 0,
                "selected": [],
                "filtered": [],
            }), encoding="utf-8")
            with self.assertRaises(ValueError):
                validate_manifest(ROOT, load_json(manifest_path), self.registry)

    def test_context_exactly_matches_routing_snapshot(self) -> None:
        _, _, _, manifest = build_manifest()
        context = {**manifest["audit_context"], "routing_snapshot_id": manifest["routing_snapshot_id"]}
        self.assertEqual(validate_context(ROOT, manifest, context), [])
        changed_values = {
            "chain_id": 1,
            "environment_facts": {**context["environment_facts"], "changed": {"value": None, "trust": "UNKNOWN", "source": "test", "evidence": []}},
            "dependency_digest": "0" * 64,
            "build_config_digest": "1" * 64,
            "target_repo_commit": "changed",
        }
        for field, changed_value in changed_values.items():
            changed = {**context, field: changed_value}
            with self.subTest(field=field):
                self.assertTrue(any(f"context.{field}" in error for error in validate_context(ROOT, manifest, changed)))

    def test_routing_snapshot_id_ignores_run_timestamp(self) -> None:
        _, _, _, manifest = build_manifest()
        changed = {
            **manifest,
            "audit_context": {**manifest["audit_context"], "audit_timestamp": "later"},
        }
        self.assertEqual(manifest["routing_snapshot_id"], bind_routing_snapshot(changed)["routing_snapshot_id"])

    def test_domain_resolution_present_and_absent_are_valid(self) -> None:
        _, _, _, manifest = build_manifest(domains=None)
        resolution = domain_resolution_template(manifest)
        deferred = sorted(resolution["domains"])
        resolution["domains"][deferred[0]] = {
            "status": "PRESENT",
            "scope_complete": False,
            "evidence": [{"kind": "source", "location": "fixture", "reason": "surface exists"}],
        }
        resolution["domains"][deferred[1]] = {
            "status": "ABSENT_CONFIRMED",
            "scope_complete": True,
            "evidence": [
                {"kind": "scope", "location": "fixture", "reason": "complete scope"},
                {"kind": "inheritance", "location": "fixture", "reason": "domain surface absent"},
            ],
        }
        unresolved = validate_domain_resolution(ROOT, manifest, resolution)
        self.assertEqual(unresolved, set(deferred[2:]))

    def test_domain_resolution_unknown_blocks_deep(self) -> None:
        _, _, _, manifest = build_manifest(domains=None)
        resolution = domain_resolution_template(manifest)
        with self.assertRaisesRegex(ValueError, "resolve Domain screening before Deep"):
            validate_domain_resolution(ROOT, manifest, resolution, require_terminal=True)

    def test_domain_resolution_rejects_untrusted_absence_evidence(self) -> None:
        _, _, _, manifest = build_manifest(domains=None)
        resolution = domain_resolution_template(manifest)
        domain = next(iter(resolution["domains"]))
        resolution["domains"][domain] = {
            "status": "ABSENT_CONFIRMED",
            "scope_complete": True,
            "evidence": [{"kind": "manual", "location": "fixture", "reason": "not trusted"}],
        }
        with self.assertRaisesRegex(ValueError, "trusted_absence_policy"):
            validate_domain_resolution(ROOT, manifest, resolution)

    def test_domain_resolution_rejects_wrong_snapshot(self) -> None:
        _, _, _, manifest = build_manifest()
        resolution = domain_resolution_template(manifest)
        resolution["routing_snapshot_id"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "mismatched routing_snapshot_id"):
            validate_domain_resolution(ROOT, manifest, resolution)

    def test_domain_context_template_tracks_selected_and_present_domains(self) -> None:
        _, _, _, manifest = build_manifest(domains=None)
        resolution = domain_resolution_template(manifest)
        deferred = next(iter(resolution["domains"]))
        resolution["domains"][deferred] = {
            "status": "PRESENT",
            "scope_complete": False,
            "evidence": [{"kind": "source", "location": "fixture", "reason": "present"}],
        }
        context = domain_context_template(manifest, resolution)
        self.assertIn("evm-audit-general", context["domains"])
        self.assertIn(deferred, context["domains"])
        filtered = {entry["domain"] for entry in manifest["filtered_domains"]}
        self.assertTrue(filtered.isdisjoint(context["domains"]))

    def test_domain_context_known_requires_value_and_evidence(self) -> None:
        _, _, _, manifest = build_manifest()
        context = domain_context_template(manifest)
        item = next(iter(next(iter(context["domains"].values())).values()))
        item["status"] = "KNOWN"
        with self.assertRaisesRegex(ValueError, "value"):
            validate_domain_context(ROOT, manifest, context)

    def test_domain_context_not_applicable_requires_evidence(self) -> None:
        _, _, _, manifest = build_manifest()
        context = domain_context_template(manifest)
        item = next(iter(next(iter(context["domains"].values())).values()))
        item["status"] = "NOT_APPLICABLE"
        with self.assertRaises(ValueError):
            validate_domain_context(ROOT, manifest, context)

    def test_optional_unknown_context_does_not_block_completion(self) -> None:
        _, _, _, manifest = build_manifest()
        for requirement in manifest["required_context_requirements"]["evm-audit-general"].values():
            requirement["required"] = False
        manifest = bind_routing_snapshot(manifest)
        context = domain_context_template(manifest)
        self.assertEqual(validate_domain_context(ROOT, manifest, context), set())

    def test_domain_context_rejects_wrong_snapshot(self) -> None:
        _, _, _, manifest = build_manifest()
        context = domain_context_template(manifest)
        context["routing_snapshot_id"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "mismatched routing_snapshot_id"):
            validate_domain_context(ROOT, manifest, context)

    def test_screen_deep_uses_only_validated_candidates(self) -> None:
        registry, _, _, manifest = build_manifest(all_features=True)
        screen_results = screen_results_template(manifest)
        self.assertTrue(all(item["result"] == "CANDIDATE" for item in screen_results["results"]))
        candidate = screen_results["results"][0]["canonical_id"]
        not_applicable = screen_results["results"][1]
        for result in screen_results["results"][1:]:
            result["result"] = "NOT_APPLICABLE_CONFIRMED"
            result["scope_complete"] = True
            result["evidence"] = [
                {"kind": kind, "location": "fixture", "reason": "complete scope evidence"}
                for kind in ("scope", "inheritance", "interface", "deployment")
            ]
        candidates = validate_screen_results(ROOT, manifest, screen_results)
        self.assertEqual(candidates, {candidate})
        screen = render(manifest, registry, "screen", set())
        deep = render(manifest, registry, "deep", candidates)
        self.assertIn("**Screen gate:**", screen)
        self.assertNotIn("**Detection:**", screen)
        self.assertNotIn("**Risk:**", screen)
        self.assertIn(f"## [{candidate}]", deep)
        self.assertIn("**Risk:**", deep)
        self.assertNotIn(f"## [{not_applicable['canonical_id']}]", deep)
        self.assertNotIn("LIKELY_SAFE", screen + deep)

    def test_screen_na_uses_relevant_complete_evidence(self) -> None:
        _, _, _, manifest = build_manifest()
        screen = screen_results_template(manifest)
        screen["results"][0].update(
            result="NOT_APPLICABLE_CONFIRMED",
            scope_complete=True,
            evidence=[
                {"kind": "scope", "location": "fixture", "reason": "complete scope"},
                {"kind": "inheritance", "location": "fixture", "reason": "trigger absent from inheritance"},
            ],
        )
        validate_screen_results(ROOT, manifest, screen)

    def test_screen_na_does_not_require_irrelevant_deployment_evidence(self) -> None:
        _, _, _, manifest = build_manifest()
        screen = screen_results_template(manifest)
        screen["results"][0].update(
            result="NOT_APPLICABLE_CONFIRMED",
            scope_complete=True,
            evidence=[
                {"kind": "scope", "location": "fixture", "reason": "complete scope"},
                {"kind": "inheritance", "location": "fixture", "reason": "condition absent"},
            ],
        )
        validate_screen_results(ROOT, manifest, screen)

    def test_screen_na_insufficient_evidence_is_rejected(self) -> None:
        _, _, _, manifest = build_manifest()
        screen = screen_results_template(manifest)
        screen["results"][0].update(
            result="NOT_APPLICABLE_CONFIRMED",
            scope_complete=True,
            evidence=[{"kind": "scope", "location": "fixture", "reason": "scope only"}],
        )
        with self.assertRaisesRegex(ValueError, "exclusion dimension"):
            validate_screen_results(ROOT, manifest, screen)

    def test_deferred_present_expands_screen_and_coverage(self) -> None:
        _, _, _, manifest = build_manifest(domains=None)
        resolution = domain_resolution_template(manifest)
        domain = next(iter(resolution["domains"]))
        resolution["domains"][domain] = {
            "status": "PRESENT",
            "scope_complete": False,
            "evidence": [{"kind": "source", "location": "fixture", "reason": "surface exists"}],
        }
        screen = screen_results_template(manifest, resolution)
        selected_ids = {entry["canonical_id"] for entry in manifest["selected"]}
        expanded_ids = {entry["canonical_id"] for entry in manifest["deferred"] if domain in entry["domains"]}
        self.assertTrue(expanded_ids <= {entry["canonical_id"] for entry in screen["results"]})
        self.assertEqual(validate_screen_results(ROOT, manifest, screen, resolution), selected_ids | expanded_ids)

    def test_global_policies_do_not_enter_deep_cards(self) -> None:
        check = next(
            item
            for item in self.registry["checks"]
            if item["fp_policy"] == "global" and item["proof_policy"] == "global"
        )
        self.assertEqual(check["false_positive_gates"], [])
        self.assertEqual(check["proof"], [])

    def test_audit_state_is_derived_from_screen_coverage(self) -> None:
        _, _, _, manifest = build_manifest()
        screen = screen_results_template(manifest)
        evidence = [
            {"kind": kind, "location": "fixture", "reason": "complete evidence"}
            for kind in ("scope", "inheritance", "interface", "deployment")
        ]
        for result in screen["results"]:
            result["result"] = "NOT_APPLICABLE_CONFIRMED"
            result["scope_complete"] = True
            result["evidence"] = evidence
        context = {**manifest["audit_context"], "routing_snapshot_id": manifest["routing_snapshot_id"]}
        domain_context = domain_context_template(manifest)
        for values in domain_context["domains"].values():
            for item in values.values():
                item.update(
                    status="KNOWN",
                    value="fixture",
                    evidence=[{"kind": "scope", "location": "fixture", "reason": "complete scope"}],
                )
        state = validate_run(ROOT, manifest, self.registry, screen, None, domain_context, context, [])
        self.assertEqual(state["status"], "COMPLETE_CLEAN")
        self.assertTrue(state["complete"])
        self.assertTrue(state["clean"])
        screen["results"][0]["result"] = "CANDIDATE"
        screen["results"][0]["scope_complete"] = False
        screen["results"][0]["evidence"] = []
        state = validate_run(ROOT, manifest, self.registry, screen, None, domain_context, context, [])
        self.assertEqual(state["status"], "INCOMPLETE_REVIEW")
        self.assertFalse(state["complete"])

    def test_state_schema_failure_forces_incomplete_flags(self) -> None:
        _, _, _, manifest = build_manifest()
        screen = screen_results_template(manifest)
        evidence = [
            {"kind": kind, "location": "fixture", "reason": "complete evidence"}
            for kind in ("scope", "inheritance", "interface", "deployment")
        ]
        for result in screen["results"]:
            result.update(result="NOT_APPLICABLE_CONFIRMED", scope_complete=True, evidence=evidence)
        context = {**manifest["audit_context"], "routing_snapshot_id": manifest["routing_snapshot_id"]}
        domain_context = domain_context_template(manifest)
        for values in domain_context["domains"].values():
            for item in values.values():
                item.update(
                    status="KNOWN",
                    value="fixture",
                    evidence=[{"kind": "scope", "location": "fixture", "reason": "known context"}],
                )

        import scripts.validate_audit_run as audit_state

        original = audit_state.validate_schema

        def fail_only_for_state(root: Path, schema_name: str, value: Any) -> None:
            if schema_name == "audit-state.schema.json":
                raise ValueError("forced state schema failure")
            original(root, schema_name, value)

        with patch.object(audit_state, "validate_schema", side_effect=fail_only_for_state):
            state = validate_run(ROOT, manifest, self.registry, screen, None, domain_context, context, [])
        self.assertEqual(state["status"], "INVALID_SNAPSHOT")
        self.assertFalse(state["complete"])
        self.assertFalse(state["clean"])

    def test_unknown_deferred_domain_is_not_complete(self) -> None:
        raw = synthetic_feature_map()
        features = normalize_feature_map(raw, self.feature_names, self.feature_policies, EMPTY_TARGET)
        context = audit_context(
            ROOT,
            self.registry,
            raw["recon_context"],
            target_root=EMPTY_TARGET,
            audit_timestamp="test",
        )
        environment = {
            **{
                key: context[key]
                for key in (
                    "chain_id",
                    "chain_family",
                    "execution_environment",
                    "compiler_version",
                    "evm_fork",
                    "protocol_version",
                )
            },
            "environment_facts": context["environment_facts"],
        }
        configs = load_domains(ROOT)
        manifest, _ = select(
            self.registry,
            features,
            self.feature_names,
            None,
            context,
            configs,
            environment,
            raw["recon_context"],
        )
        screen = screen_results_template(manifest)
        for result in screen["results"]:
            result["result"] = "NOT_APPLICABLE_CONFIRMED"
            result["scope_complete"] = True
            result["evidence"] = [
                {"kind": kind, "location": "fixture", "reason": "complete evidence"}
                for kind in ("scope", "inheritance", "interface", "deployment")
            ]
        resolution = {
            "schema_version": 2,
            "routing_snapshot_id": manifest["routing_snapshot_id"],
            "registry_sha256": manifest["audit_context"]["registry_sha256"],
            "source_digest": manifest["audit_context"]["source_digest"],
            "compilation_input_digest": manifest["audit_context"]["compilation_input_digest"],
            "domains": {
                entry["domain"]: {"status": "UNKNOWN", "scope_complete": False, "evidence": []}
                for entry in manifest["deferred_domains"]
            },
        }
        context_artifact = {**manifest["audit_context"], "routing_snapshot_id": manifest["routing_snapshot_id"]}
        domain_context = domain_context_template(manifest, resolution)
        for values in domain_context["domains"].values():
            for item in values.values():
                item.update(
                    status="KNOWN",
                    value="fixture",
                    evidence=[{"kind": "scope", "location": "fixture", "reason": "complete scope"}],
                )
        state = validate_run(ROOT, manifest, self.registry, screen, resolution, domain_context, context_artifact, [])
        self.assertEqual(state["status"], "INCOMPLETE_DOMAIN_ROUTING")
        self.assertFalse(state["complete"])

    def test_jsonl_checkpoint_requires_same_snapshot_and_appends(self) -> None:
        registry, _, _, manifest = build_manifest()
        entry = manifest["selected"][0]
        check = next(item for item in registry["checks"] if item["canonical_id"] == entry["canonical_id"])
        screen, domain_context, snapshot = review_inputs(manifest)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "review.jsonl"
            record = {
                "record_type": "review",
                "schema_version": 7,
                "canonical_id": check["canonical_id"],
                "owner_domain": entry["owner_domain"],
                "routing_snapshot_id": manifest["routing_snapshot_id"],
                "check_body_hash": check_body_hash(check),
                "review_stage": "DEEP_REVIEW",
                "status": "REVIEWED_SAFE",
                "applicability": "APPLICABLE - fixture",
                "code_path": "fixture entry",
                "preconditions": "fixture state",
                "exploitability": "blocked by fixture guard",
                "impact": "N/A - invariant holds",
                "proof": "fixture invariant holds",
                "preserved_invariant": "fixture invariant",
                "evidence": [{"kind": "test", "location": "fixture", "reason": "test evidence"}],
            }
            record["review_snapshot_id"] = snapshot
            append(path, manifest, record, domain_context=domain_context, screen_results=screen)
            self.assertEqual(validate_records(load(path), manifest, registry, {check["canonical_id"]}, review_snapshot_id=snapshot), [])
            second_entry = manifest["selected"][1]
            second_check = next(item for item in registry["checks"] if item["canonical_id"] == second_entry["canonical_id"])
            second_record = {
                **record,
                "canonical_id": second_check["canonical_id"],
                "owner_domain": second_entry["owner_domain"],
                "check_body_hash": check_body_hash(second_check),
            }
            append(path, manifest, second_record, registry, {check["canonical_id"], second_check["canonical_id"]}, domain_context=domain_context, screen_results=screen)
            self.assertEqual(len(load(path)), 3)
            self.assertEqual(
                validate_records(load(path), manifest, registry, {check["canonical_id"], second_check["canonical_id"]}, review_snapshot_id=snapshot),
                [],
            )
            changed = {**manifest, "audit_context": {**manifest["audit_context"], "source_digest": "0" * 64}}
            self.assertTrue(validate_records(load(path), changed, registry, {check["canonical_id"]}))
            with self.assertRaisesRegex(ValueError, "record_type=review"):
                append(path, manifest, {key: value for key, value in record.items() if key != "record_type"}, domain_context=domain_context, screen_results=screen)

    def test_jsonl_append_publishes_a_committed_prefix(self) -> None:
        registry, _, _, manifest = build_manifest()
        entry = manifest["selected"][0]
        check = next(item for item in registry["checks"] if item["canonical_id"] == entry["canonical_id"])
        screen, domain_context, snapshot = review_inputs(manifest)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "review.jsonl"
            payload = "x" * 200_000
            record = {
                "record_type": "review",
                "schema_version": 7,
                "canonical_id": check["canonical_id"],
                "owner_domain": entry["owner_domain"],
                "routing_snapshot_id": manifest["routing_snapshot_id"],
                "check_body_hash": check_body_hash(check),
                "review_stage": "DEEP_REVIEW",
                "status": "REVIEWED_SAFE",
                "applicability": "APPLICABLE - fixture",
                "code_path": "fixture entry" + payload,
                "preconditions": "fixture state",
                "exploitability": "blocked by fixture guard",
                "impact": "N/A - invariant holds",
                "proof": "fixture invariant",
                "preserved_invariant": "fixture invariant",
                "evidence": [{"kind": "test", "location": "fixture", "reason": "test evidence"}],
            }
            record["review_snapshot_id"] = snapshot
            written_calls: list[bytes] = []
            original_write = os.write

            def recording_write(fd: int, data: bytes) -> int:
                written_calls.append(bytes(data))
                return original_write(fd, data)

            with patch.object(os, "write", side_effect=recording_write), patch.object(
                review_ledger, "fsync_parent_directory", wraps=review_ledger.fsync_parent_directory
            ) as fsync_dir:
                append(path, manifest, record, domain_context=domain_context, screen_results=screen)
            # A record larger than any internal buffer must still be written as whole JSON lines.
            lines = path.read_bytes().splitlines()
            self.assertEqual(len(lines), 2)
            values = [json.loads(line) for line in lines]
            self.assertEqual(values[1]["status"], "REVIEWED_SAFE")
            self.assertEqual(values[1]["code_path"], "fixture entry" + payload)
            self.assertEqual(
                validate_records(load(path), manifest, registry, {check["canonical_id"]}, review_snapshot_id=snapshot),
                [],
            )
            # The syscall count is an implementation check; the sidecar, not syscall size, is the crash boundary.
            self.assertEqual(len(written_calls), 1, "append payload should use one unbuffered syscall in this fixture")
            self.assertEqual(b"".join(written_calls), path.read_bytes())
            self.assertTrue(fsync_dir.called, "new ledger files must fsync their parent directory")
            metadata = json.loads(Path(f"{path}.commit.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["committed_bytes"], len(path.read_bytes()))
            self.assertEqual(metadata["prefix_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_review_revisions_preserve_history_and_derive_latest_state(self) -> None:
        registry, _, _, manifest = build_manifest()
        entry = manifest["selected"][0]
        check = next(item for item in registry["checks"] if item["canonical_id"] == entry["canonical_id"])
        screen, domain_context, snapshot = review_inputs(manifest)
        first = {
            "record_type": "review",
            "schema_version": 7,
            "canonical_id": entry["canonical_id"],
            "owner_domain": entry["owner_domain"],
            "routing_snapshot_id": manifest["routing_snapshot_id"],
            "check_body_hash": check_body_hash(check),
            "review_stage": "DEEP_REVIEW",
            "status": "SUSPICIOUS",
            "applicability": "APPLICABLE - fixture",
            "code_path": "fixture entry",
            "preconditions": "fixture state",
            "exploitability": "alternate path unresolved",
            "impact": "potential accounting issue",
            "proof": "proof pending",
            "unresolved_reason": "alternate path pending",
            "evidence": [{"kind": "manual", "location": "fixture", "reason": "deep review candidate"}],
        }
        first.update({key: manifest["audit_context"][key] for key in (
            "registry_sha256", "source_digest", "compilation_input_digest",
        )})
        first["review_snapshot_id"] = snapshot
        second = {
            **{key: value for key, value in first.items() if key != "unresolved_reason"},
            "review_stage": "PROOF",
            "status": "CONFIRMED",
            "exploitability": "attacker reaches the fixture path",
            "impact": "accounting is corrupted",
            "proof": "deterministic proof completed",
            "evidence": [{"kind": "trace", "location": "fixture", "reason": "deterministic proof trace"}],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "review.jsonl"
            append(path, manifest, first, registry, {entry["canonical_id"]}, domain_context=domain_context, screen_results=screen)
            append(path, manifest, second, registry, {entry["canonical_id"]}, domain_context=domain_context, screen_results=screen)
            values = load(path)
            self.assertEqual([record["revision"] for record in values[1:]], [1, 2])
            self.assertEqual(validate_records(values, manifest, registry, {entry["canonical_id"]}, review_snapshot_id=snapshot), [])
            latest, errors = collect_review_records([path], manifest, registry, {entry["canonical_id"]}, review_snapshot_id=snapshot)
            self.assertEqual(errors, [])
            self.assertEqual(latest[entry["canonical_id"]]["status"], "CONFIRMED")
            history, errors = collect_review_history([path], manifest, registry, {entry["canonical_id"]}, review_snapshot_id=snapshot)
            self.assertEqual(errors, [])
            markdown = render_markdown(history, manifest, registry)
            self.assertIn("- **Revision:** 1", markdown)
            self.assertIn("- **Revision:** 2", markdown)
            self.assertEqual(markdown.count(f"### {entry['canonical_id']}"), 2)

    def test_review_revision_order_and_transition_rules(self) -> None:
        registry, _, _, manifest = build_manifest()
        entry = manifest["selected"][0]
        check = next(item for item in registry["checks"] if item["canonical_id"] == entry["canonical_id"])
        screen, domain_context, snapshot = review_inputs(manifest)
        base = {
            "record_type": "review",
            "schema_version": 7,
            "canonical_id": entry["canonical_id"],
            "revision": 1,
            "owner_domain": entry["owner_domain"],
            "routing_snapshot_id": manifest["routing_snapshot_id"],
            "check_body_hash": check_body_hash(check),
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
        base.update({key: manifest["audit_context"][key] for key in (
            "registry_sha256", "source_digest", "compilation_input_digest",
        )})
        base["review_snapshot_id"] = snapshot
        without_first = {**base, "revision": 2}
        self.assertTrue(any("first review revision must be 1" in error for error in validate_records(
            [checkpoint(manifest, snapshot), without_first], manifest, registry, {entry["canonical_id"]}, review_snapshot_id=snapshot
        )))
        safe_first = {
            **base,
            "status": "REVIEWED_SAFE",
            "exploitability": "guard holds",
            "preserved_invariant": "fixture invariant",
        }
        safe_then_proof = {
            **safe_first,
            "revision": 2,
            "review_stage": "PROOF",
            "status": "CONFIRMED",
            "evidence": [{"kind": "trace", "location": "fixture", "reason": "proof trace"}],
        }
        errors = validate_records(
            [checkpoint(manifest, snapshot), safe_first, safe_then_proof],
            manifest,
            registry,
            {entry["canonical_id"]},
        )
        self.assertTrue(any("cannot follow REVIEWED_SAFE" in error for error in errors))
        proper_second = {
            **base,
            "revision": 2,
            "review_stage": "PROOF",
            "status": "SUSPICIOUS",
            "evidence": [{"kind": "trace", "location": "fixture", "reason": "proof trace"}],
        }
        duplicate = {**proper_second}
        errors = validate_records(
            [checkpoint(manifest, snapshot), base, proper_second, duplicate],
            manifest,
            registry,
            {entry["canonical_id"]},
        )
        self.assertTrue(any("revision must be 3" in error for error in errors))
        not_applicable = {
            **base,
            "revision": 2,
            "review_stage": "PROOF",
            "status": "NOT_APPLICABLE",
            "scope_complete": True,
            "applicability": "NOT_APPLICABLE - trigger absent",
            "code_path": "no trigger",
            "preconditions": "trigger absent",
            "exploitability": "not exploitable",
            "impact": "none",
            "proof": "scope proof",
            "evidence": [
                {"kind": "scope", "location": "fixture", "reason": "complete scope"},
                {"kind": "inheritance", "location": "fixture", "reason": "trigger absent"},
            ],
        }
        errors = validate_records(
            [checkpoint(manifest, snapshot), base, not_applicable],
            manifest,
            registry,
            {entry["canonical_id"]},
        )
        self.assertTrue(any("valid proof resolution" in error for error in errors))

    def test_deep_not_applicable_does_not_require_irrelevant_evidence(self) -> None:
        registry, _, _, manifest = build_manifest()
        entry = manifest["selected"][0]
        check = next(item for item in registry["checks"] if item["canonical_id"] == entry["canonical_id"])
        _, _, snapshot = review_inputs(manifest)
        record = {
            "record_type": "review",
            "schema_version": 7,
            "canonical_id": entry["canonical_id"],
            "revision": 1,
            "owner_domain": entry["owner_domain"],
            "routing_snapshot_id": manifest["routing_snapshot_id"],
            "check_body_hash": check_body_hash(check),
            "review_stage": "DEEP_REVIEW",
            "status": "NOT_APPLICABLE",
            "scope_complete": True,
            "applicability": "NOT_APPLICABLE — source trigger is absent",
            "code_path": "no reachable trigger path",
            "preconditions": "trigger precondition cannot be met",
            "exploitability": "not exploitable in scope",
            "impact": "none",
            "proof": "source evidence proves absence",
            "evidence": [
                {"kind": "scope", "location": "fixture", "reason": "complete scope"},
                {"kind": "inheritance", "location": "fixture", "reason": "trigger absent"},
            ],
        }
        record.update({key: manifest["audit_context"][key] for key in ("registry_sha256", "source_digest", "compilation_input_digest")})
        record["review_snapshot_id"] = snapshot
        self.assertEqual(validate_record(record, manifest, registry, {entry["canonical_id"]}, review_snapshot_id=snapshot), [])

    def test_confirmed_requires_proof_stage_and_strong_evidence(self) -> None:
        registry, _, _, manifest = build_manifest()
        entry = manifest["selected"][0]
        check = next(item for item in registry["checks"] if item["canonical_id"] == entry["canonical_id"])
        _, _, snapshot = review_inputs(manifest)
        record = {
            "record_type": "review",
            "schema_version": 7,
            "canonical_id": entry["canonical_id"],
            "revision": 1,
            "owner_domain": entry["owner_domain"],
            "routing_snapshot_id": manifest["routing_snapshot_id"],
            "check_body_hash": check_body_hash(check),
            "review_stage": "DEEP_REVIEW",
            "status": "CONFIRMED",
            "applicability": "APPLICABLE — path exists",
            "code_path": "entry() -> call()",
            "preconditions": "attacker controls input",
            "exploitability": "attacker invokes entry",
            "impact": "state is corrupted",
            "proof": "deterministic proof",
            "evidence": [{"kind": "manual", "location": "fixture", "reason": "manual only"}],
        }
        record.update({key: manifest["audit_context"][key] for key in ("registry_sha256", "source_digest", "compilation_input_digest")})
        record["review_snapshot_id"] = snapshot
        errors = validate_record(record, manifest, registry, {entry["canonical_id"]}, review_snapshot_id=snapshot)
        self.assertTrue(any("PROOF" in error or "strong proof" in error for error in errors))
        record["review_stage"] = "PROOF"
        errors = validate_record(record, manifest, registry, {entry["canonical_id"]}, review_snapshot_id=snapshot)
        self.assertTrue(any("strong proof" in error or "not valid" in error for error in errors))
        record["evidence"] = [{"kind": "trace", "location": "fixture", "reason": "deterministic trace"}]
        self.assertEqual(validate_record(record, manifest, registry, {entry["canonical_id"]}, review_snapshot_id=snapshot), [])

    def test_cross_ledger_duplicate_is_rejected(self) -> None:
        registry, _, _, manifest = build_manifest()
        entry = manifest["selected"][0]
        check = next(item for item in registry["checks"] if item["canonical_id"] == entry["canonical_id"])
        screen, domain_context, snapshot = review_inputs(manifest)
        record = {
            "record_type": "review",
            "schema_version": 7,
            "canonical_id": entry["canonical_id"],
            "revision": 1,
            "owner_domain": entry["owner_domain"],
            "routing_snapshot_id": manifest["routing_snapshot_id"],
            "check_body_hash": check_body_hash(check),
            "review_stage": "DEEP_REVIEW",
            "status": "REVIEWED_SAFE",
            "applicability": "APPLICABLE — fixture",
            "code_path": "fixture entry",
            "preconditions": "fixture state",
            "exploitability": "guard holds",
            "impact": "none",
            "proof": "fixture invariant",
            "preserved_invariant": "fixture invariant",
            "evidence": [{"kind": "test", "location": "fixture", "reason": "test evidence"}],
        }
        record.update({key: manifest["audit_context"][key] for key in ("registry_sha256", "source_digest", "compilation_input_digest")})
        record["review_snapshot_id"] = snapshot
        with tempfile.TemporaryDirectory() as directory:
            first, second = Path(directory) / "first.jsonl", Path(directory) / "second.jsonl"
            write_ledger(first, manifest, [record], registry, {entry["canonical_id"]}, domain_context=domain_context, screen_results=screen)
            write_ledger(second, manifest, [record], registry, {entry["canonical_id"]}, domain_context=domain_context, screen_results=screen)
            _, errors = collect_review_records([first, second], manifest, registry, {entry["canonical_id"]}, review_snapshot_id=snapshot)
        self.assertTrue(any("duplicate Deep record across ledgers" in error for error in errors))

    def test_multiprocess_ledger_writes_are_serialized_and_durable(self) -> None:
        registry, _, _, manifest = build_manifest()
        screen, domain_context, snapshot = review_inputs(manifest)
        canonical_ids = [item["canonical_id"] for item in screen["results"][:8]]
        expected_ids = set(canonical_ids)
        records = []
        for canonical_id in canonical_ids:
            route = next(item for item in manifest["selected"] if item["canonical_id"] == canonical_id)
            records.append(
                {
                    "record_type": "review",
                    "schema_version": 7,
                    "canonical_id": canonical_id,
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
                    "evidence": [{"kind": "test", "location": "fixture", "reason": "concurrent ledger test"}],
                }
            )

        context = multiprocessing.get_context("spawn")
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "review.jsonl")
            start_event = context.Event()
            result_queue = context.Queue()
            processes = [
                context.Process(
                    target=_append_ledger_worker,
                    args=(path, manifest, record, registry, expected_ids, domain_context, screen, result_queue),
                )
                for record in records
            ]
            reader = context.Process(target=_read_ledger_worker, args=(path, start_event, result_queue))
            processes.append(reader)
            for process in processes:
                process.start()
            start_event.set()
            outcomes = [result_queue.get(timeout=30) for _ in processes]
            for process in processes:
                process.join(30)
                self.assertEqual(process.exitcode, 0)
            self.assertEqual([outcome[0] for outcome in outcomes].count("ok"), len(processes))
            values = load(Path(path))
            self.assertEqual(len(values), len(records) + 1)
            self.assertEqual(
                validate_records(values, manifest, registry, expected_ids, review_snapshot_id=snapshot),
                [],
            )

            race_path = str(Path(directory) / "race.jsonl")
            race_event = context.Event()
            race_queue = context.Queue()
            race_processes = [
                context.Process(
                    target=_append_ledger_worker,
                    args=(race_path, manifest, records[0], registry, {canonical_ids[0]}, domain_context, screen, race_queue),
                )
                for _ in range(2)
            ]
            for process in race_processes:
                process.start()
            race_event.set()
            race_outcomes = [race_queue.get(timeout=30) for _ in race_processes]
            for process in race_processes:
                process.join(30)
                self.assertEqual(process.exitcode, 0)
            self.assertEqual([outcome[0] for outcome in race_outcomes].count("ok"), 1)
            self.assertEqual(len(load(Path(race_path))), 2)
            self.assertEqual(
                validate_records(load(Path(race_path)), manifest, registry, {canonical_ids[0]}, review_snapshot_id=snapshot),
                [],
            )

    def test_ledger_does_not_silently_disable_locking(self) -> None:
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "review.jsonl"
            with patch("scripts.review_ledger.fcntl", None), patch("scripts.review_ledger.msvcrt", None):
                with self.assertRaisesRegex(RuntimeError, "locking is unavailable"):
                    with _ledger_lock(path, shared=False):
                        pass

    def test_checkpoint_cli_has_no_cross_snapshot_option(self) -> None:
        result = subprocess.run(
            [sys.executable, "scripts/review_ledger.py", "--help"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("--" + "resume-from", result.stdout)

    def test_selector_has_no_domain_context_option(self) -> None:
        result = subprocess.run(
            [sys.executable, "scripts/select_checks.py", "--help"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("--domain-context", result.stdout)

    def test_domain_skills_embed_the_evidence_gate(self) -> None:
        for skill_path in sorted((ROOT / "skills").glob("evm-audit-*/SKILL.md")):
            if skill_path.parent.name == "evm-audit-master":
                continue
            text = skill_path.read_text(encoding="utf-8")
            with self.subTest(skill=skill_path.parent.name):
                self.assertIn("## Runtime Modes", text)
                self.assertIn("check-review-contract.runtime.md", text)
                self.assertIn("Never rerun Recon or Selector", text)
                self.assertIn("## Required Context", text)
                self.assertIn("Apply the Master contract", text)
                self.assertNotIn("Pattern matches are candidates, not findings", text)
                self.assertNotIn("The tri-state predicate router is conservative", text)

    def test_review_contract_keeps_suspicious_out_of_severity(self) -> None:
        text = (ROOT / "skills/evm-audit-master/references/check-review-contract.md").read_text(encoding="utf-8")
        self.assertIn("`SUSPICIOUS`", text)
        self.assertIn("Do not assign severity", text)
        self.assertIn("`CONFIRMED`", text)
        self.assertIn("runnable PoC", text)

    def test_review_ledger_enforces_status_evidence_gate(self) -> None:
        registry, _, _, manifest = build_manifest()
        entry = manifest["selected"][0]
        check = next(item for item in registry["checks"] if item["canonical_id"] == entry["canonical_id"])
        _, _, snapshot = review_inputs(manifest)
        base = {
                "schema_version": 7,
            "record_type": "review",
            "canonical_id": entry["canonical_id"],
            "revision": 1,
            "owner_domain": entry["owner_domain"],
            "routing_snapshot_id": manifest["routing_snapshot_id"],
            "check_body_hash": check_body_hash(check),
            "review_stage": "PROOF",
            "applicability": "APPLICABLE - path exists",
            "code_path": "entry() -> call()",
            "preconditions": "attacker controls target",
            "exploitability": "attacker invokes entry",
            "impact": "accounting accepts false success",
            "proof": "test demonstrates false success",
            "evidence": [{"kind": "test", "location": "fixture", "reason": "executable evidence"}],
        }
        base.update(
            {
                key: manifest["audit_context"][key]
                for key in ("registry_sha256", "source_digest", "compilation_input_digest")
            }
        )
        base["review_snapshot_id"] = snapshot
        suspicious = {
            **base,
            "status": "SUSPICIOUS",
            "unresolved_reason": "missing alternate path",
            "code_path": "UNRESOLVED - alternate path pending",
            "severity": "High",
        }
        self.assertTrue(
            any(
                "not valid" in error or "additional" in error
                for error in validate_record(suspicious, manifest, registry, {entry["canonical_id"]})
            )
        )
        confirmed = {**base, "status": "CONFIRMED"}
        self.assertEqual(validate_record(confirmed, manifest, registry, {entry["canonical_id"]}), [])
        old_schema = {**confirmed, "schema_version": 2}
        self.assertTrue(validate_record(old_schema, manifest, registry, {entry["canonical_id"]}))
        incomplete = {key: value for key, value in confirmed.items() if key != "proof"}
        self.assertTrue(
            any(
                "missing review fields" in error or "not valid" in error
                for error in validate_record(incomplete, manifest, registry, {entry["canonical_id"]})
            )
        )


if __name__ == "__main__":
    unittest.main()
