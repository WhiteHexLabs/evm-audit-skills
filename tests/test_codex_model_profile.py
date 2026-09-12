"""Tests for the Codex-only stage execution policy."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from helpers import EMPTY_TARGET, ROOT, build_manifest, load_json, review_inputs
from scripts.audit_artifacts import review_state_digest
from scripts.audit_run import main as audit_run_main, recommended_execution
from scripts.codex_model_profile import (
    DEFAULT_CODEX_MODEL_PROFILE,
    DEFAULT_ZCODE_MODEL_PROFILE,
    STAGES,
    ZCODE_CONTROLLER_STAGES,
    ZCODE_WORKER_AGENTS,
    ZCODE_WORKER_STAGES,
    compact_summary,
    default_profile,
    load_global_profile,
    load_profile,
    validate_profile,
    write_profile,
)

class CodexModelProfileTests(unittest.TestCase):
    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, *arguments],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    @staticmethod
    def run_audit_run(arguments: list[str], home: Path) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("scripts.codex_model_profile.Path.home", return_value=home):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = audit_run_main(arguments)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_default_profile_is_exact_and_schema_valid(self) -> None:
        expected = {
            "RECON": ("gpt-5.6-luna", "max"),
            "ROUTING": ("gpt-5.6-luna", "max"),
            "DOMAIN_RESOLUTION": ("gpt-5.6-terra", "medium"),
            "DOMAIN_CONTEXT": ("gpt-5.6-terra", "medium"),
            "SCREEN": ("gpt-5.6-terra", "high"),
            "DEEP_REVIEW": ("gpt-5.6-sol", "high"),
            "PROOF": ("gpt-5.6-sol", "max"),
            "REPORT": ("gpt-5.6-terra", "medium"),
        }
        self.assertEqual(DEFAULT_CODEX_MODEL_PROFILE, default_profile())
        self.assertEqual(
            {stage: (default_profile()["stages"][stage]["model"], default_profile()["stages"][stage]["reasoning_effort"]) for stage in STAGES},
            expected,
        )
        validate_profile(default_profile())

    def test_compact_summary_uses_public_phases_and_preserves_distinct_substages(self) -> None:
        self.assertEqual(
            compact_summary(default_profile()).splitlines(),
            [
                "Project Analysis: gpt-5.6-luna max",
                "Context Analysis: gpt-5.6-terra medium",
                "Initial Review: gpt-5.6-terra high",
                "Deep Audit: gpt-5.6-sol high",
                "Vulnerability Validation: gpt-5.6-sol max",
                "Final Report: gpt-5.6-terra medium",
            ],
        )
        custom = default_profile()
        custom["stages"]["ROUTING"] = {"model": "gpt-5.6-terra", "reasoning_effort": "high"}
        summary = compact_summary(custom)
        self.assertIn("Project Analysis · Recon: gpt-5.6-luna max", summary)
        self.assertIn("Project Analysis · Routing: gpt-5.6-terra high", summary)

    def test_invalid_model_and_effort_are_rejected(self) -> None:
        invalid = default_profile()
        invalid["stages"]["SCREEN"]["model"] = "gpt-5.5"
        with self.assertRaisesRegex(ValueError, "unsupported Codex model"):
            validate_profile(invalid)
        invalid = default_profile()
        invalid["stages"]["SCREEN"]["reasoning_effort"] = "turbo"
        with self.assertRaisesRegex(ValueError, "invalid reasoning effort"):
            validate_profile(invalid)

    def test_init_persists_default_profile_and_next_recommendation(self) -> None:
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
                "--accept-default-models",
                "--quiet",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            profile_path = run_dir / "config/codex-model-profile.json"
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
            self.assertEqual(profile, default_profile())
            from scripts.audit_artifacts import validate_schema

            validate_schema(ROOT, "codex-model-profile.schema.json", profile)
            payload = json.loads(result.stdout)
            self.assertEqual(
                payload["next"]["recommended_execution"],
                {"provider": "codex", "model": "gpt-5.6-terra", "reasoning_effort": "medium"},
            )

    def test_global_profile_is_explicitly_initialized_and_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            code, _, stderr = self.run_audit_run(["models", "--init-global", "--quiet"], home)
            self.assertEqual(code, 0, stderr)
            global_path = home / ".codex/evm-audit-model-profile.json"
            self.assertEqual(json.loads(global_path.read_text(encoding="utf-8")), default_profile())
            self.assertEqual(load_global_profile(global_path), default_profile())
            from scripts.audit_artifacts import validate_schema

            validate_schema(ROOT, "codex-model-profile.schema.json", load_global_profile(global_path))
            code, _, stderr = self.run_audit_run(["models", "--init-global", "--quiet"], home)
            self.assertNotEqual(code, 0)
            self.assertIn("refusing to overwrite", stderr)

    def test_init_copies_global_profile_and_later_global_edits_do_not_change_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            global_path = home / ".codex/evm-audit-model-profile.json"
            custom = default_profile()
            custom["profile_name"] = "user-default"
            custom["stages"]["SCREEN"] = {"model": "gpt-5.6-sol", "reasoning_effort": "xhigh"}
            write_profile(global_path, custom)
            run_dir = root / "run"
            code, _, stderr = self.run_audit_run(
                [
                    "init", str(EMPTY_TARGET), "--run-dir", str(run_dir),
                    "--audit-root", str(EMPTY_TARGET), "--domain", "evm-audit-general", "--quiet",
                ],
                home,
            )
            self.assertEqual(code, 0, stderr)
            run_profile = run_dir / "config/codex-model-profile.json"
            self.assertEqual(json.loads(run_profile.read_text(encoding="utf-8")), custom)
            changed = default_profile()
            changed["stages"]["SCREEN"] = {"model": "gpt-5.6-luna", "reasoning_effort": "low"}
            write_profile(global_path, changed)
            self.assertEqual(
                recommended_execution(run_dir, "SCREEN"),
                {"provider": "codex", "model": "gpt-5.6-sol", "reasoning_effort": "xhigh"},
            )

    def test_explicit_init_sources_override_global_profile(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            global_profile = default_profile()
            global_profile["stages"]["PROOF"] = {"model": "gpt-5.6-sol", "reasoning_effort": "high"}
            write_profile(home / ".codex/evm-audit-model-profile.json", global_profile)
            explicit = default_profile()
            explicit["stages"]["PROOF"] = {"model": "gpt-5.6-luna", "reasoning_effort": "max"}
            source = root / "explicit.json"
            write_profile(source, explicit)
            for run_dir, option in ((root / "explicit-run", "--model-profile"), (root / "default-run", "--accept-default-models")):
                arguments = [
                    "init", str(EMPTY_TARGET), "--run-dir", str(run_dir),
                    "--audit-root", str(EMPTY_TARGET), "--domain", "evm-audit-general", option,
                ]
                if option == "--model-profile":
                    arguments.append(str(source))
                arguments.append("--quiet")
                code, _, stderr = self.run_audit_run(arguments, home)
                self.assertEqual(code, 0, stderr)
            self.assertEqual(json.loads((root / "explicit-run/config/codex-model-profile.json").read_text())["stages"]["PROOF"], explicit["stages"]["PROOF"])
            self.assertEqual(json.loads((root / "default-run/config/codex-model-profile.json").read_text())["stages"]["PROOF"], default_profile()["stages"]["PROOF"])

    def test_invalid_global_profile_is_rejected_without_creating_run_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            invalid = default_profile()
            invalid["stages"]["SCREEN"]["model"] = "gpt-5.5"
            write_profile_path = home / ".codex/evm-audit-model-profile.json"
            write_profile_path.parent.mkdir(parents=True)
            write_profile_path.write_text(json.dumps(invalid) + "\n", encoding="utf-8")
            run_dir = root / "run"
            code, _, stderr = self.run_audit_run(
                [
                    "init", str(EMPTY_TARGET), "--run-dir", str(run_dir),
                    "--audit-root", str(EMPTY_TARGET), "--domain", "evm-audit-general", "--quiet",
                ],
                home,
            )
            self.assertNotEqual(code, 0)
            self.assertIn("unsupported Codex model", stderr)
            self.assertFalse((run_dir / "config/codex-model-profile.json").exists())

    def test_custom_profile_is_copied_and_models_reset_restores_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = root / "run"
            custom = default_profile()
            custom["profile_name"] = "custom-audit"
            custom["stages"]["SCREEN"] = {"model": "gpt-5.6-sol", "reasoning_effort": "xhigh"}
            source = root / "custom.json"
            source.write_text(json.dumps(custom) + "\n", encoding="utf-8")
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
                "--model-profile",
                str(source),
                "--quiet",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads((run_dir / "config/codex-model-profile.json").read_text()), custom)
            result = self.run_cli(
                "scripts/audit_run.py",
                "models",
                "--run-dir",
                str(run_dir),
                "--reset-defaults",
                "--quiet",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["profile"], default_profile())
            self.assertEqual(
                json.loads((run_dir / "config/codex-model-profile.json").read_text()),
                default_profile(),
            )

    def test_all_stage_recommendations_and_identity_independence(self) -> None:
        expected = {
            "RECON": ("gpt-5.6-luna", "max"),
            "ROUTING": ("gpt-5.6-luna", "max"),
            "DOMAIN_RESOLUTION": ("gpt-5.6-terra", "medium"),
            "DOMAIN_CONTEXT": ("gpt-5.6-terra", "medium"),
            "SCREEN": ("gpt-5.6-terra", "high"),
            "DEEP_REVIEW": ("gpt-5.6-sol", "high"),
            "PROOF": ("gpt-5.6-sol", "max"),
            "REPORT": ("gpt-5.6-terra", "medium"),
        }
        _, _, _, manifest = build_manifest()
        screen, context, review_snapshot = review_inputs(manifest)
        before = (
            manifest["routing_snapshot_id"],
            review_snapshot,
            review_state_digest({}, set()),
            manifest["audit_context"]["compilation_input_digest"],
        )
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            write_profile(run_dir / "config/codex-model-profile.json", default_profile())
            for stage, (model, effort) in expected.items():
                recommendation = recommended_execution(run_dir, stage)
                self.assertEqual(recommendation, {"provider": "codex", "model": model, "reasoning_effort": effort})
            custom = default_profile()
            custom["stages"]["DEEP_REVIEW"] = {"model": "gpt-5.6-sol", "reasoning_effort": "max"}
            write_profile(run_dir / "config/codex-model-profile.json", custom)
            self.assertEqual(
                recommended_execution(run_dir, "DEEP_REVIEW"),
                {"provider": "codex", "model": "gpt-5.6-sol", "reasoning_effort": "max"},
            )
            custom["stages"]["PROOF"] = {"model": "gpt-5.6-luna", "reasoning_effort": "max"}
            write_profile(run_dir / "config/codex-model-profile.json", custom)
            after = (
                manifest["routing_snapshot_id"],
                review_snapshot,
                review_state_digest({}, set()),
                manifest["audit_context"]["compilation_input_digest"],
            )
        self.assertEqual(before, after)

    def test_legacy_run_without_profile_stays_valid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            run_dir = root / "run"
            code, _, stderr = self.run_audit_run(
                [
                    "init", str(EMPTY_TARGET), "--run-dir", str(run_dir),
                    "--audit-root", str(EMPTY_TARGET), "--domain", "evm-audit-general", "--quiet",
                ],
                home,
            )
            self.assertEqual(code, 0, stderr)
            profile_path = run_dir / "config/codex-model-profile.json"
            self.assertTrue(profile_path.exists())
            self.assertEqual(json.loads(profile_path.read_text(encoding="utf-8")), default_profile())
            profile_path.unlink()
            global_profile = default_profile()
            global_profile["stages"]["DOMAIN_CONTEXT"] = {"model": "gpt-5.6-sol", "reasoning_effort": "xhigh"}
            write_profile(home / ".codex/evm-audit-model-profile.json", global_profile)
            code, stdout, stderr = self.run_audit_run(
                ["status", "--run-dir", str(run_dir), "--quiet"], home
            )
            self.assertEqual(code, 0, stderr)
            payload = json.loads(stdout)
            self.assertEqual(payload["recommended_execution"]["model"], "gpt-5.6-terra")
            code, _, _ = self.run_audit_run(
                ["report", "--run-dir", str(run_dir), "--quiet"], home
            )
            self.assertNotEqual(code, 0)
            state = json.loads((run_dir / "audit-state.json").read_text(encoding="utf-8"))
            self.assertNotEqual(state["status"], "INVALID_SNAPSHOT")

    def test_zcode_default_profile_is_exact_and_schema_valid(self) -> None:
        expected = {
            "RECON": ("GLM-5.3", "max", None),
            "ROUTING": ("GLM-5.3", "max", None),
            "DOMAIN_RESOLUTION": ("GLM-5.3", "high", None),
            "DOMAIN_CONTEXT": ("GLM-5.3-Flash", "default", "evm-audit-worker-flash"),
            "SCREEN": ("GLM-5.3", "high", "evm-audit-worker-deep"),
            "DEEP_REVIEW": ("GLM-5.3", "high", "evm-audit-worker-deep"),
            "PROOF": ("GLM-5.3", "max", "evm-audit-worker-proof"),
            "REPORT": ("GLM-5.3", "high", None),
        }
        zcode = default_profile("zcode")
        self.assertEqual(DEFAULT_ZCODE_MODEL_PROFILE, zcode)
        self.assertEqual(
            {
                stage: (zcode["stages"][stage]["model"], zcode["stages"][stage]["thought_level"], zcode["stages"][stage]["agent"])
                for stage in STAGES
            },
            expected,
        )
        validate_profile(zcode)
        from scripts.audit_artifacts import validate_schema

        validate_schema(ROOT, "codex-model-profile.schema.json", zcode)
        self.assertIn("Initial Review: GLM-5.3 high · evm-audit-worker-deep", compact_summary(zcode))

    def test_zcode_thought_levels_are_model_specific(self) -> None:
        invalid = default_profile("zcode")
        invalid["stages"]["DOMAIN_RESOLUTION"]["thought_level"] = "medium"
        with self.assertRaisesRegex(ValueError, "invalid GLM-5.3 thought level 'medium'"):
            validate_profile(invalid)
        invalid = default_profile("zcode")
        invalid["stages"]["DOMAIN_CONTEXT"]["thought_level"] = "high"
        with self.assertRaisesRegex(ValueError, "invalid GLM-5.3-Flash thought level 'high'"):
            validate_profile(invalid)
        for level in ("low", "high", "max"):
            valid = default_profile("zcode")
            valid["stages"]["DOMAIN_RESOLUTION"]["thought_level"] = level
            validate_profile(valid)

    def test_zcode_worker_contracts_are_enforced(self) -> None:
        lying_model = default_profile("zcode")
        lying_model["stages"]["DOMAIN_CONTEXT"] = {
            "model": "GLM-5.3",
            "thought_level": "high",
            "agent": "evm-audit-worker-flash",
        }
        with self.assertRaisesRegex(ValueError, "runs GLM-5.3-Flash, not 'GLM-5.3'"):
            validate_profile(lying_model)
        lying_level = default_profile("zcode")
        lying_level["stages"]["SCREEN"]["thought_level"] = "max"
        with self.assertRaisesRegex(ValueError, "pins thought level 'high', not 'max'"):
            validate_profile(lying_level)
        wrong_stage = default_profile("zcode")
        wrong_stage["stages"]["DEEP_REVIEW"]["agent"] = "evm-audit-worker-proof"
        wrong_stage["stages"]["DEEP_REVIEW"]["thought_level"] = "max"
        with self.assertRaisesRegex(ValueError, "may not execute this stage"):
            validate_profile(wrong_stage)
        unknown_agent = default_profile("zcode")
        unknown_agent["stages"]["SCREEN"]["agent"] = "audit-deep"
        with self.assertRaisesRegex(ValueError, "invalid zcode agent"):
            validate_profile(unknown_agent)
        wrong_vocab = default_profile("zcode")
        wrong_vocab["stages"]["REPORT"]["model"] = "gpt-5.6-terra"
        with self.assertRaisesRegex(ValueError, "unsupported ZCode model"):
            validate_profile(wrong_vocab)
        codex_with_agent = default_profile()
        codex_with_agent["stages"]["SCREEN"] = {
            "model": "gpt-5.6-terra",
            "reasoning_effort": "high",
            "agent": "evm-audit-worker-deep",
        }
        with self.assertRaisesRegex(ValueError, "must contain exactly agent, model|for provider codex"):
            validate_profile(codex_with_agent)

    def test_zcode_worker_stage_rejects_null_agent(self) -> None:
        for stage in ZCODE_WORKER_STAGES:
            invalid = default_profile("zcode")
            invalid["stages"][stage]["agent"] = None
            with self.assertRaisesRegex(ValueError, "zcode worker stage requires a configured worker agent", msg=stage):
                validate_profile(invalid)

    def test_zcode_controller_stage_rejects_worker_agent(self) -> None:
        for stage in ZCODE_CONTROLLER_STAGES:
            invalid = default_profile("zcode")
            invalid["stages"][stage]["agent"] = "evm-audit-worker-deep"
            with self.assertRaisesRegex(ValueError, "zcode controller stage must use agent null", msg=stage):
                validate_profile(invalid)

    def test_zcode_stage_role_sets_partition_stages(self) -> None:
        self.assertEqual(ZCODE_CONTROLLER_STAGES | ZCODE_WORKER_STAGES, set(STAGES))
        self.assertEqual(ZCODE_CONTROLLER_STAGES & ZCODE_WORKER_STAGES, set())

    def test_zcode_schema_pins_worker_execution_triplets(self) -> None:
        from scripts.audit_artifacts import validate_schema

        expected_triplets = {
            "DOMAIN_CONTEXT": ("DOMAIN_CONTEXT", "evm-audit-worker-flash"),
            "SCREEN": ("SCREEN", "evm-audit-worker-deep"),
            "DEEP_REVIEW": ("DEEP_REVIEW", "evm-audit-worker-deep"),
            "PROOF": ("PROOF", "evm-audit-worker-proof"),
        }
        schema = load_json(ROOT / "schemas" / "codex-model-profile.schema.json")
        for stage, (stage_name, agent) in expected_triplets.items():
            contract = ZCODE_WORKER_AGENTS[agent]
            triplet = {
                "model": contract["model"],
                "thought_level": contract["thought_level"],
                "agent": agent,
            }
            self.assertEqual(
                schema["$defs"][f"zcode_{stage_name.lower()}_stage"],
                {"const": triplet},
                stage,
            )
        # The canonical default is schema-valid and every shipped worker stage
        # matches its exact executable triplet.
        zcode = default_profile("zcode")
        validate_schema(ROOT, "codex-model-profile.schema.json", zcode)
        for stage, (_, agent) in expected_triplets.items():
            self.assertEqual(zcode["stages"][stage]["agent"], agent, stage)
        # A worker stage that drops its agent fails the schema exactly as it
        # fails semantic validation.
        invalid = default_profile("zcode")
        invalid["stages"]["SCREEN"]["agent"] = None
        with self.assertRaisesRegex(ValueError, "codex-model-profile.schema.json:stages.SCREEN"):
            validate_schema(ROOT, "codex-model-profile.schema.json", invalid)
        # A controller stage that names a worker agent fails the schema.
        invalid = default_profile("zcode")
        invalid["stages"]["REPORT"]["agent"] = "evm-audit-worker-deep"
        with self.assertRaisesRegex(ValueError, "codex-model-profile.schema.json:stages.REPORT"):
            validate_schema(ROOT, "codex-model-profile.schema.json", invalid)


    def test_zcode_worker_frontmatter_matches_execution_contracts(self) -> None:
        for name, contract in ZCODE_WORKER_AGENTS.items():
            template = ROOT / "skills" / "evm-audit-master" / "agents" / f"{name}.md"
            self.assertTrue(template.is_file(), template)
            frontmatter: dict[str, str] = {}
            for line in template.read_text(encoding="utf-8").splitlines():
                if line == "---":
                    if frontmatter:
                        break
                    continue
                if ": " in line and not line.startswith(" "):
                    key, value = line.split(": ", 1)
                    frontmatter[key] = value
            self.assertEqual(frontmatter.get("name"), name, template)
            self.assertEqual(frontmatter.get("model"), contract["model"], template)
            pinned = frontmatter.get("thoughtLevel")
            if contract["thought_level"] == "default":
                self.assertIsNone(pinned, f"{name} must not pin an unverified Flash thought level")
            else:
                self.assertEqual(pinned, contract["thought_level"], template)

    def test_outdated_profile_schema_versions_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for version in (1, 2):
                stale = default_profile()
                stale["schema_version"] = version
                path = Path(directory) / f"v{version}.json"
                path.write_text(json.dumps(stale) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "schema_version must be 3"):
                    load_profile(path)

    def test_zcode_global_profile_and_init_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            code, _, stderr = self.run_audit_run(["models", "--init-global", "--provider", "zcode", "--quiet"], home)
            self.assertEqual(code, 0, stderr)
            global_path = home / ".zcode/evm-audit-model-profile.json"
            self.assertEqual(load_global_profile(global_path), default_profile("zcode"))
            self.assertFalse((home / ".codex/evm-audit-model-profile.json").exists())
            run_dir = root / "run"
            code, stdout, stderr = self.run_audit_run(
                [
                    "init", str(EMPTY_TARGET), "--run-dir", str(run_dir),
                    "--audit-root", str(EMPTY_TARGET), "--domain", "evm-audit-general",
                    "--provider", "zcode", "--accept-default-models", "--quiet",
                ],
                home,
            )
            self.assertEqual(code, 0, stderr)
            profile_path = run_dir / "config/codex-model-profile.json"
            self.assertEqual(json.loads(profile_path.read_text(encoding="utf-8")), default_profile("zcode"))
            payload = json.loads(stdout)
            # Single-domain init skips deferred resolution, so the next stage
            # is DOMAIN_CONTEXT: the flash worker with its agent assignment.
            self.assertEqual(
                payload["next"]["recommended_execution"],
                {
                    "provider": "zcode",
                    "model": "GLM-5.3-Flash",
                    "thought_level": "default",
                    "agent": "evm-audit-worker-flash",
                },
            )
            # Every stage handoff names exactly the worker contract that will
            # be dispatched for it (controller stages carry agent null).
            expected_handoffs = {
                "RECON": ("GLM-5.3", "max", None),
                "ROUTING": ("GLM-5.3", "max", None),
                "DOMAIN_RESOLUTION": ("GLM-5.3", "high", None),
                "DOMAIN_CONTEXT": ("GLM-5.3-Flash", "default", "evm-audit-worker-flash"),
                "SCREEN": ("GLM-5.3", "high", "evm-audit-worker-deep"),
                "DEEP_REVIEW": ("GLM-5.3", "high", "evm-audit-worker-deep"),
                "PROOF": ("GLM-5.3", "max", "evm-audit-worker-proof"),
                "REPORT": ("GLM-5.3", "high", None),
            }
            for stage, (model, level, agent) in expected_handoffs.items():
                self.assertEqual(
                    recommended_execution(run_dir, stage),
                    {"provider": "zcode", "model": model, "thought_level": level, "agent": agent},
                    stage,
                )
            code, stdout, stderr = self.run_audit_run(
                ["models", "--run-dir", str(run_dir), "--reset-defaults", "--quiet"], home
            )
            self.assertEqual(code, 0, stderr)
            self.assertEqual(json.loads(stdout)["profile"], default_profile("zcode"))


if __name__ == "__main__":
    unittest.main()
