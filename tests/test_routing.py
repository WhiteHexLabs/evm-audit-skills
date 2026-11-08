#!/usr/bin/env python3
"""Focused routing safety and benchmark-runner behavior tests."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.audit_artifacts import validate_schema, validate_target_snapshot
from scripts.benchmark_routing import _assert_fixture, fixture_paths, run_profile, validate_fixture
from scripts.generate_checklists import load_domains
from scripts.select_checks import (
    audit_context,
    evaluate_check,
    evaluate_environment,
    evaluate_group,
    normalize_feature_map,
    select,
    validate_recon_context,
    validate_environment_context,
)

from helpers import EMPTY_TARGET, ROOT, load_json, suite_inputs, synthetic_feature_map


class RoutingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry, cls.feature_names, cls.feature_policies = suite_inputs()

    def test_predicates_are_explicit_and_domain_independent(self) -> None:
        for check in self.registry["checks"]:
            with self.subTest(canonical_id=check["canonical_id"]):
                self.assertEqual(set(check["predicate"]), {"all_of", "any_of", "none_of"})
                routed = {feature for group in check["predicate"].values() for feature in group}
                self.assertEqual(check["features"], sorted(routed))
                self.assertFalse(any(feature.startswith("evm-audit-") for feature in routed))
                if not routed:
                    self.assertTrue(check.get("always_screen"))

    def test_feature_filter_selects_relevant_checks(self) -> None:
        feature_map = synthetic_feature_map({"uses-erc4626": "PRESENT", "uses-oracle": "ABSENT_CONFIRMED"})
        with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8") as feature_file:
            json.dump(feature_map, feature_file)
            feature_file.flush()
            result = subprocess.run(
                [
                    sys.executable,
                    "scripts/select_checks.py",
                    "--feature-map",
                    feature_file.name,
                    "--target-root",
                    "tests/fixtures/recon/Empty.sol",
                    "--domain",
                    "evm-audit-erc4626",
                    "--format",
                    "json",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        selected = {entry["canonical_id"] for entry in json.loads(result.stdout)["selected"]}
        self.assertIn("ERC4626-ROUND-001", selected)
        self.assertIn("EVM-ERC4626-003", selected)
        self.assertNotIn("EVM-TIME-001", selected)

    def test_only_curated_false_predicates_can_filter(self) -> None:
        feature_map = {"a": {"status": "ABSENT_CONFIRMED", "evidence": ["fixture: absent"]}}
        registry = {
            "checks": [
                {
                    "canonical_id": "TEST-INFERRED-001",
                    "title": "inferred",
                    "domains": ["evm-audit-general"],
                    "primary_domain": "evm-audit-general",
                    "predicate": {"all_of": ["a"], "any_of": [], "none_of": []},
                    "predicate_source": "inferred",
                },
                {
                    "canonical_id": "TEST-CURATED-001",
                    "title": "curated",
                    "domains": ["evm-audit-general"],
                    "primary_domain": "evm-audit-general",
                    "predicate": {"all_of": ["a"], "any_of": [], "none_of": []},
                    "predicate_source": "curated",
                },
            ]
        }
        manifest, _ = select(registry, feature_map, {"a"}, ["evm-audit-general"])
        self.assertEqual([entry["canonical_id"] for entry in manifest["selected"]], ["TEST-INFERRED-001"])
        self.assertEqual([entry["canonical_id"] for entry in manifest["filtered"]], ["TEST-CURATED-001"])

    def test_check_predicates_inherit_domain_dependency_policy(self) -> None:
        """Dependency-only feature evidence must not prove first-party applicability at check level."""
        feature_map = {
            "feature-dep": {
                "status": "PRESENT",
                "evidence": [
                    {"kind": "slither-ast", "location": "lib/Dep.sol:1", "reason": "dependency match", "scope_origin": "DEPENDENCY"},
                ],
            },
        }
        registry = {
            "checks": [
                {
                    "canonical_id": "TEST-DEP-NONE-001",
                    "title": "dependency-only none_of",
                    "domains": ["evm-audit-general"],
                    "primary_domain": "evm-audit-general",
                    "predicate": {"all_of": [], "any_of": [], "none_of": ["feature-dep"]},
                    "predicate_source": "curated",
                },
                {
                    "canonical_id": "TEST-DEP-ANY-001",
                    "title": "dependency-only any_of",
                    "domains": ["evm-audit-general"],
                    "primary_domain": "evm-audit-general",
                    "predicate": {"all_of": [], "any_of": ["feature-dep"], "none_of": []},
                    "predicate_source": "curated",
                },
            ]
        }
        manifest, _ = select(registry, feature_map, {"feature-dep"}, None, None, load_domains(ROOT), {}, None)
        selected = {entry["canonical_id"] for entry in manifest["selected"]}
        self.assertIn("TEST-DEP-NONE-001", selected, "dependency-only evidence must never filter a curated check")
        self.assertIn("TEST-DEP-ANY-001", selected)
        self.assertEqual(manifest["filtered"], [])
        any_entry = next(item for item in manifest["selected"] if item["canonical_id"] == "TEST-DEP-ANY-001")
        self.assertEqual(any_entry["matched_features"], [], "dependency-only features must not be reported as matched")
        self.assertEqual(any_entry["unknown_features"], ["feature-dep"])
        self.assertEqual(any_entry["feature_evaluation"], "UNKNOWN")

    def test_evaluate_check_honors_scope_origin_policy(self) -> None:
        feature_map = {
            "dep-only": {
                "status": "PRESENT",
                "evidence": [{"kind": "source", "location": "lib:1", "reason": "dependency", "scope_origin": "DEPENDENCY"}],
            },
            "own-only": {
                "status": "PRESENT",
                "evidence": [{"kind": "source", "location": "src:1", "reason": "first party", "scope_origin": "AUDIT_SCOPE"}],
            },
        }
        names = set(feature_map)
        any_check = {"canonical_id": "T1", "predicate": {"all_of": [], "any_of": ["dep-only"], "none_of": []}, "predicate_source": "curated"}
        self.assertEqual(evaluate_check(any_check, feature_map, names)["result"], "UNKNOWN")
        self.assertEqual(evaluate_check(any_check, feature_map, names)["matched_features"], [])
        self.assertEqual(evaluate_check(any_check, feature_map, names)["unknown_features"], ["dep-only"])
        none_check = {"canonical_id": "T2", "predicate": {"all_of": [], "any_of": [], "none_of": ["dep-only"]}, "predicate_source": "curated"}
        self.assertEqual(evaluate_check(none_check, feature_map, names)["result"], "UNKNOWN")
        allowed = evaluate_check(any_check, feature_map, names, dependency_presence_sufficient=True)
        self.assertEqual(allowed["result"], "TRUE")
        own_check = {"canonical_id": "T3", "predicate": {"all_of": ["own-only"], "any_of": [], "none_of": []}, "predicate_source": "curated"}
        self.assertEqual(evaluate_check(own_check, feature_map, names)["result"], "TRUE")

    def test_predicate_truth_table_is_conservative_for_unknown(self) -> None:
        feature_map = {
            "a": {"status": "PRESENT", "evidence": []},
            "b": {"status": "ABSENT_CONFIRMED", "evidence": []},
            "c": {"status": "UNKNOWN", "evidence": []},
        }
        self.assertEqual(evaluate_group(["a"], "all_of", feature_map), "TRUE")
        self.assertEqual(evaluate_group(["a", "b"], "all_of", feature_map), "FALSE")
        self.assertEqual(evaluate_group(["b", "c"], "any_of", feature_map), "UNKNOWN")
        self.assertEqual(evaluate_group(["b"], "none_of", feature_map), "TRUE")
        self.assertEqual(evaluate_group(["a", "c"], "none_of", feature_map), "FALSE")
        unknown_check = {
            "canonical_id": "TEST-UNKNOWN-001",
            "predicate": {"all_of": ["c"], "any_of": [], "none_of": []},
            "predicate_source": "curated",
        }
        self.assertEqual(evaluate_check(unknown_check, feature_map, {"a", "b", "c"})["result"], "UNKNOWN")

    def test_feature_map_requires_evidence_for_confirmed_states(self) -> None:
        feature_map = synthetic_feature_map({"uses-erc20": "PRESENT"})
        feature_map["features"]["uses-erc20"]["evidence"] = []
        with self.assertRaises(ValueError):
            normalize_feature_map(feature_map, self.feature_names, self.feature_policies, EMPTY_TARGET)
        with self.assertRaises(ValueError):
            normalize_feature_map({"schema_version": 2, "features": {}}, self.feature_names, self.feature_policies, EMPTY_TARGET)

    def test_incomplete_recon_downgrades_absence_but_keeps_presence(self) -> None:
        feature_map = synthetic_feature_map({
            "uses-assembly": "ABSENT_CONFIRMED",
            "uses-erc20": "PRESENT",
        })
        context = feature_map["recon_context"]
        context["files_analyzed"] = []
        context["compilation_complete"] = False
        context["uncompiled_paths"] = ["Empty.sol"]
        context["recon_quality"] = {
            "compilation_complete": False,
            "absence_filtering_complete": False,
            "mode": "CONSERVATIVE_DEGRADED",
            "uncompiled_paths": ["Empty.sol"],
            "compilation_provenance": "CONSERVATIVE_BUILD_ROOT_FALLBACK",
        }
        normalized = normalize_feature_map(feature_map, self.feature_names, self.feature_policies, EMPTY_TARGET)
        self.assertEqual(normalized["uses-assembly"]["status"], "UNKNOWN")
        self.assertEqual(normalized["uses-erc20"]["status"], "PRESENT")
        self.assertIn("incomplete", normalized["uses-assembly"]["reason"])
        manifest, _ = select(
            {
                "checks": [{
                    "canonical_id": "TEST-DEGRADED-001",
                    "title": "degraded",
                    "domains": ["evm-audit-general"],
                    "primary_domain": "evm-audit-general",
                    "predicate": {"all_of": ["uses-assembly"], "any_of": [], "none_of": []},
                    "predicate_source": "curated",
                }]
            },
            normalized,
            self.feature_names,
            ["evm-audit-general"],
        )
        self.assertEqual([entry["canonical_id"] for entry in manifest["selected"]], ["TEST-DEGRADED-001"])

    def test_recon_coverage_fields_are_derived_from_scope(self) -> None:
        feature_map = synthetic_feature_map()
        with self.assertRaisesRegex(ValueError, "outside the current audit scope"):
            feature_map["recon_context"]["files_analyzed"] = ["outside.sol"]
            validate_recon_context(feature_map["recon_context"], EMPTY_TARGET, ())

        legacy = synthetic_feature_map()
        legacy["recon_context"]["recon_quality"].pop("compilation_provenance")
        normalized_legacy = validate_recon_context(legacy["recon_context"], EMPTY_TARGET, ())
        self.assertEqual(
            normalized_legacy["recon_quality"]["compilation_provenance"],
            "CONSERVATIVE_BUILD_ROOT_FALLBACK",
        )

        feature_map = synthetic_feature_map()
        with self.assertRaisesRegex(ValueError, "scope_files minus files_analyzed"):
            feature_map["recon_context"]["compilation_complete"] = False
            feature_map["recon_context"]["uncompiled_paths"] = ["Empty.sol"]
            feature_map["recon_context"]["recon_quality"] = {
                "compilation_complete": False,
                "absence_filtering_complete": False,
                "mode": "CONSERVATIVE_DEGRADED",
                "uncompiled_paths": ["Empty.sol"],
                "compilation_provenance": "CONSERVATIVE_BUILD_ROOT_FALLBACK",
            }
            validate_recon_context(feature_map["recon_context"], EMPTY_TARGET, ())

        feature_map = synthetic_feature_map()
        with self.assertRaisesRegex(ValueError, "compilation_complete"):
            feature_map["recon_context"]["compilation_complete"] = False
            feature_map["recon_context"]["recon_quality"] = {
                "compilation_complete": False,
                "absence_filtering_complete": False,
                "mode": "CONSERVATIVE_DEGRADED",
                "uncompiled_paths": [],
                "compilation_provenance": "CONSERVATIVE_BUILD_ROOT_FALLBACK",
            }
            validate_recon_context(feature_map["recon_context"], EMPTY_TARGET, ())

    def test_feature_map_v5_rejects_unsupported_cli_and_formats(self) -> None:
        help_result = subprocess.run(
            [sys.executable, "scripts/select_checks.py", "--help"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertNotIn("--features", help_result.stdout)
        for version in (1, 2):
            with self.assertRaises(ValueError):
                normalize_feature_map(
                    {"schema_version": version, "features": {}},
                    self.feature_names,
                    self.feature_policies,
                    EMPTY_TARGET,
                )

    def test_feature_map_has_single_schema_source(self) -> None:
        self.assertTrue((ROOT / "schemas/feature-map.schema.json").exists())
        self.assertFalse((ROOT / "data" / ("feature-map" + ".schema.json")).exists())
        result = subprocess.run(
            [sys.executable, "scripts/recon.py", str(EMPTY_TARGET)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        validate_schema(ROOT, "feature-map.schema.json", json.loads(result.stdout))

    def test_absence_policy_downgrades_dynamic_loop(self) -> None:
        normalized = normalize_feature_map(
            synthetic_feature_map({"uses-dynamic-loop": "ABSENT_CONFIRMED"}),
            self.feature_names,
            self.feature_policies,
            EMPTY_TARGET,
        )
        self.assertEqual(normalized["uses-dynamic-loop"]["status"], "UNKNOWN")
        self.assertIn("never-confirm-absence", normalized["uses-dynamic-loop"]["reason"])

    def test_scope_digest_mismatch_rejects_selector(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8") as feature_file:
            json.dump(synthetic_feature_map(), feature_file)
            feature_file.flush()
            result = subprocess.run(
                [
                    sys.executable,
                    "scripts/select_checks.py",
                    "--feature-map",
                    feature_file.name,
                    "--target-root",
                    str(ROOT),
                    "--domain",
                    "evm-audit-general",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source_digest", result.stderr)

    def test_dependency_source_change_invalidates_compilation_input_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir)
            (target / "contracts").mkdir()
            dependency = target / "lib/foo/src/Foo.sol"
            dependency.parent.mkdir(parents=True)
            (target / "contracts/Main.sol").write_text("pragma solidity ^0.8.24; contract Main {}", encoding="utf-8")
            dependency.write_text("pragma solidity ^0.8.24; contract Foo {}", encoding="utf-8")
            raw = synthetic_feature_map(target=target)
            normalized = normalize_feature_map(raw, self.feature_names, self.feature_policies, target)
            context = audit_context(ROOT, self.registry, raw["recon_context"], target_root=target, audit_timestamp="test")
            environment = {
                **{key: context[key] for key in ("chain_id", "chain_family", "execution_environment", "compiler_version", "evm_fork", "protocol_version")},
                "environment_facts": context["environment_facts"],
            }
            manifest, _ = select(
                self.registry,
                normalized,
                self.feature_names,
                ["evm-audit-general"],
                context,
                load_domains(ROOT),
                environment,
                raw["recon_context"],
            )
            validate_target_snapshot(manifest)
            dependency.write_text("pragma solidity ^0.8.24; contract Foo { uint256 value; }", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Target source/build inputs changed"):
                validate_target_snapshot(manifest)

    def test_domain_gate_does_not_expand_related_domains(self) -> None:
        all_absent = synthetic_feature_map({name: "ABSENT_CONFIRMED" for name in self.feature_names})
        selected, _ = select(
            self.registry,
            all_absent["features"],
            self.feature_names,
            None,
            {"source_digest": "benchmark"},
            load_domains(ROOT),
            {},
            None,
        )
        self.assertEqual([entry["domain"] for entry in selected["selected_domains"]], ["evm-audit-general"])
        self.assertIn("evm-audit-erc20", {entry["domain"] for entry in selected["filtered_domains"]})

    def test_environment_gate_filters_only_confirmed_mismatch(self) -> None:
        check = {
            "canonical_id": "TEST-ENV-001",
            "title": "environment",
            "domains": ["evm-audit-general"],
            "primary_domain": "evm-audit-general",
            "predicate": {"all_of": [], "any_of": [], "none_of": []},
            "predicate_source": "curated",
            "always_screen": True,
            "applicability": {
                "chain_ids": [],
                "chain_families": ["op-stack"],
                "execution_environments": ["ethereum-evm"],
                "compiler": ">=0.8.20",
                "evm_fork_from": "cancun",
                "evm_fork_until": None,
                "protocol_versions": [],
            },
        }
        values = {
            "chain_family": "arbitrum",
            "execution_environment": "ethereum-evm",
            "compiler_version": "0.8.24",
            "evm_fork": "cancun",
        }
        confirmed = {
            **values,
            "chain_id": None,
            "protocol_version": None,
            "environment_facts": {
                key: {"trust": "CONFIRMED", "value": value, "source": "fixture", "evidence": ["fixture"]}
                for key, value in values.items()
            },
        }
        self.assertEqual(evaluate_environment(check, confirmed)[0], "FALSE")
        declared = {
            **confirmed,
            "environment_facts": {
                key: {**fact, "trust": "DECLARED"}
                for key, fact in confirmed["environment_facts"].items()
            },
        }
        self.assertEqual(evaluate_environment(check, declared)[0], "UNKNOWN")
        self.assertEqual(evaluate_environment(check, {"environment_facts": {}})[0], "UNKNOWN")

    def test_zksync_environment_gate_keeps_native_and_interpreter_distinct(self) -> None:
        check = next(item for item in self.registry["checks"] if item["canonical_id"] == "EVM-CHAIN-013")
        native = {
            "chain_family": "zksync-era",
            "execution_environment": "eravm-native",
            "compiler_version": None,
            "evm_fork": None,
            "chain_id": None,
            "protocol_version": None,
            "environment_facts": {
                "chain_family": {"trust": "CONFIRMED", "value": "zksync-era", "source": "fixture", "evidence": ["fixture"]},
                "execution_environment": {"trust": "CONFIRMED", "value": "eravm-native", "source": "fixture", "evidence": ["fixture"]},
            },
        }
        interpreter = {
            **native,
            "execution_environment": "zksync-evm-interpreter",
            "environment_facts": {
                **native["environment_facts"],
                "execution_environment": {"trust": "CONFIRMED", "value": "zksync-evm-interpreter", "source": "fixture", "evidence": ["fixture"]},
            },
        }
        other = {
            **native,
            "execution_environment": "ethereum-evm",
            "environment_facts": {
                **native["environment_facts"],
                "execution_environment": {"trust": "CONFIRMED", "value": "ethereum-evm", "source": "fixture", "evidence": ["fixture"]},
            },
        }
        self.assertEqual(evaluate_environment(check, native)[0], "TRUE")
        self.assertEqual(evaluate_environment(check, interpreter)[0], "TRUE")
        self.assertEqual(evaluate_environment(check, other)[0], "FALSE")

    def test_chain_id_populates_known_chain_family(self) -> None:
        context = audit_context(
            ROOT,
            self.registry,
            synthetic_feature_map()["recon_context"],
            target_root=EMPTY_TARGET,
            chain_id=8453,
        )
        self.assertEqual(context["chain_family"], "op-stack")

    def test_environment_context_rejects_conflicts(self) -> None:
        recon = synthetic_feature_map()["recon_context"]
        with self.assertRaises(ValueError):
            validate_environment_context(recon, chain_id=8453, chain_family="arbitrum")
        with self.assertRaises(ValueError):
            validate_environment_context(recon, chain_id=324, execution_environment="ethereum-evm")
        with self.assertRaises(ValueError):
            validate_environment_context(recon, compiler_version="0.8.20")

    def test_unknown_domain_is_deferred_and_blocks_clean_completion(self) -> None:
        raw = synthetic_feature_map()
        manifest, _ = select(
            self.registry,
            raw["features"],
            self.feature_names,
            None,
            {"source_digest": raw["recon_context"]["source_digest"]},
            load_domains(ROOT),
            {},
            raw["recon_context"],
        )
        self.assertTrue(manifest["deferred_domains"])
        self.assertNotIn("completion_gate", manifest)
        self.assertIn("required_context_requirements", manifest)
        self.assertNotIn("unresolved_" + "required_context", manifest)

    def test_curated_predicates_have_select_and_filter_fixtures(self) -> None:
        fixtures = {
            item["canonical_id"]: item
            for item in load_json(ROOT / "tests/routing/curated-predicates.json")["fixtures"]
        }
        for canonical_id, check in (
            (key, value) for key, value in {item["canonical_id"]: item for item in self.registry["checks"]}.items()
            if value.get("predicate_source") == "curated"
        ):
            fixture = fixtures[canonical_id]
            with self.subTest(canonical_id=canonical_id):
                selected_map = {
                    feature: {"status": "PRESENT", "evidence": []}
                    for feature in fixture["select_present"]
                }
                filtered_map = dict(selected_map)
                for feature in fixture["filter_absent"]:
                    filtered_map[feature] = {"status": "ABSENT_CONFIRMED", "evidence": []}
                self.assertNotEqual(evaluate_check(check, selected_map, self.feature_names)["result"], "FALSE")
                self.assertEqual(evaluate_check(check, filtered_map, self.feature_names)["result"], "FALSE")

    def test_benchmark_runner_rejects_malformed_fixture(self) -> None:
        with self.assertRaisesRegex(ValueError, "Additional properties"):
            run_profile(ROOT, {"schema_version": 1, "name": "malformed", "present_features": [], "absent_features": [], "detected_features": ["uses-erc20"]})

    def test_benchmark_fixtures_use_current_schema_and_layout(self) -> None:
        self.assertFalse((ROOT / "development" / "migrations").exists())
        paths = fixture_paths(ROOT)
        self.assertTrue(paths)
        self.assertTrue({path.stem for path in paths} >= {"access-control", "chain-specific", "dependency-only", "external-calls", "incomplete-compilation", "precision-math"})
        for path in paths:
            with self.subTest(path=path):
                self.assertIn(path.parent.name, {"automatic", "explicit"})
                fixture = load_json(path)
                validate_fixture(ROOT, fixture)
                for key in ("expected_selected_domains", "expected_deferred_domains", "expected_filtered_domains"):
                    self.assertIn(key, fixture)
                self.assertNotIn("detected_features", fixture)
                self.assertNotIn("must_select_ids", fixture)
                self.assertNotIn("must_not_filter_ids", fixture)

        dependency = load_json(ROOT / "development/benchmarks/routing/automatic/dependency-only.json")
        self.assertEqual(dependency["feature_scope_origins"]["uses-access-control"], "DEPENDENCY")
        incomplete = load_json(ROOT / "development/benchmarks/routing/automatic/incomplete-compilation.json")
        self.assertFalse(incomplete["compilation_complete"])

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "suite"
            routing = root / "development/benchmarks/routing"
            routing.mkdir(parents=True)
            (routing / "legacy.json").write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "automatic/ or explicit/"):
                fixture_paths(root)

    def test_benchmark_runner_rejects_must_not_filter_violation(self) -> None:
        fixture = {
            "schema_version": 1,
            "name": "must-not-filter",
            "present_features": [],
            "absent_features": ["uses-erc4626"],
            "domain_scope": ["evm-audit-erc4626"],
            "must_not_filter_checks": ["EVM-ERC4626-043"],
        }
        with self.assertRaisesRegex(ValueError, "must-not-filter"):
            run_profile(ROOT, fixture)

    def test_must_not_filter_domain_may_be_selected(self) -> None:
        run_profile(ROOT, {
            "schema_version": 1,
            "name": "must-not-filter-domain",
            "present_features": ["uses-erc20"],
            "absent_features": [],
            "must_not_filter_domains": ["evm-audit-erc20"],
        })

    def test_must_not_select_domain_may_be_filtered(self) -> None:
        run_profile(ROOT, {
            "schema_version": 1,
            "name": "must-not-select-domain",
            "present_features": [],
            "absent_features": ["uses-erc20"],
            "must_not_select_domains": ["evm-audit-erc20"],
        })

    def test_deferred_only_expectation_is_explicit(self) -> None:
        fixture = {
            "name": "deferred-domain",
            "must_not_filter_domains": ["evm-audit-erc20"],
            "must_not_select_domains": ["evm-audit-erc20"],
        }
        manifest = {
            "selected_domains": [],
            "deferred_domains": [{"domain": "evm-audit-erc20"}],
            "filtered_domains": [],
            "selected": [],
            "filtered": [],
        }
        _assert_fixture(fixture, {}, manifest)
        with self.assertRaisesRegex(ValueError, "expected_deferred_domains"):
            _assert_fixture(
                {**fixture, "expected_deferred_domains": ["evm-audit-erc20"]},
                {},
                {**manifest, "selected_domains": [{"domain": "evm-audit-erc20"}], "deferred_domains": []},
            )

    def test_benchmark_runner_rejects_runtime_budget_violation(self) -> None:
        with self.assertRaisesRegex(ValueError, "exceeds hard budget"):
            run_profile(
                ROOT,
                {
                    "schema_version": 1,
                    "name": "budget",
                    "present_features": [],
                    "absent_features": [],
                    "max_runtime_bytes": 0,
                },
            )

    def test_benchmark_budgets_are_upper_bounds(self) -> None:
        result = run_profile(
            ROOT,
            {
                "schema_version": 1,
                "name": "upper-bound",
                "present_features": [],
                "absent_features": [],
                "max_selected_checks": 10_000,
                "max_runtime_bytes": 10_000_000,
                "max_total_context_bytes": 10_000_000,
            },
        )
        self.assertGreater(result["screen_runtime_bytes"], 0)
        self.assertEqual(result["routing_recall"], 1.0)
        self.assertEqual(result["false_negative_cases"], 0)
        self.assertGreater(result["aggregate_domain_skill_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
