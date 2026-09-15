from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import scripts.audit_run as controller
from scripts.audit_run import CurrentReportingInputs
from helpers import ROOT


HASH = "a" * 64


def _finding(command: str = "forge test --match-test testExploit") -> dict:
    return {
        "canonical_id": "FINDING-1",
        "severity": "High",
        "runner": "foundry",
        "command": command,
        "sources": [{"path": "poc/Exploit.t.sol", "sha256": HASH}],
        "entrypoint": "testExploit",
        "expected_result": "the test passes",
        "result_summary": "the test passes",
    }


class PocVerificationTests(unittest.TestCase):
    def test_attacker_selected_runners_and_installing_npx_forms_are_rejected(self) -> None:
        cases = (
            ("foundry", "/tmp/attacker/forge test", "bare trusted runner"),
            ("hardhat", "/tmp/attacker/hardhat test test/Exploit.js", "bare trusted runner"),
            ("hardhat", "npx -p attacker hardhat test test/Exploit.js", "--no-install"),
            ("hardhat", "npx --package attacker hardhat test test/Exploit.js", "--no-install"),
            ("hardhat", "npx --yes hardhat test test/Exploit.js", "--no-install"),
        )
        for runner, command, message in cases:
            with self.subTest(command=command):
                with self.assertRaisesRegex(ValueError, message):
                    controller._poc_command_argv(runner, command)

    def test_foundry_command_is_bound_to_exact_entrypoint_and_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            finding = _finding()
            staged = [{"path": "poc/Exploit.t.sol", "staged_path": "poc-evidence/Exploit.t.sol", "sha256": HASH}]
            forge = workspace / "forge"
            forge.write_bytes(b"forge")
            forge.chmod(forge.stat().st_mode | stat.S_IXUSR)
            with patch.object(controller, "_trusted_executable", return_value=forge):
                resolved = controller._resolve_poc_command(finding, workspace, staged)
            self.assertEqual(resolved.runner, "foundry")
            self.assertIn("--match-test", resolved.argv)
            self.assertIn("testExploit", resolved.argv)
            self.assertEqual(resolved.argv[-2:], ("--match-path", "poc-evidence/Exploit.t.sol"))
            self.assertEqual(resolved.entrypoint, "poc-evidence/Exploit.t.sol::testExploit")

    def test_hardhat_npx_requires_local_copied_executable_and_exact_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            executable = workspace / "node_modules/.bin/hardhat"
            executable.parent.mkdir(parents=True)
            executable.write_text("#!/bin/sh\n", encoding="utf-8")
            executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
            finding = {
                "canonical_id": "FINDING-1",
                "severity": "High",
                "runner": "hardhat",
                "command": "npx --no-install hardhat test test/Exploit.js",
                "sources": [{"path": "poc/test/Exploit.js", "sha256": HASH}],
                "entrypoint": "test/Exploit.js",
            }
            staged = [{"path": "poc/test/Exploit.js", "staged_path": "poc-evidence/test/Exploit.js", "sha256": HASH}]
            npx = workspace / "npx"
            npx.write_bytes(b"npx")
            npx.chmod(npx.stat().st_mode | stat.S_IXUSR)
            with patch.object(controller, "_trusted_executable", return_value=npx):
                resolved = controller._resolve_poc_command(finding, workspace, staged)
            self.assertEqual(resolved.argv[1:3], ("--no-install", "hardhat"))
            self.assertIn("poc-evidence/test/Exploit.js", resolved.argv)
            self.assertEqual(resolved.entrypoint, "poc-evidence/test/Exploit.js")

    def test_workspace_copy_rejects_external_symlink_and_keeps_dependencies_local(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            build = base / "build"
            build.mkdir()
            (build / "lib").mkdir()
            (build / "lib/marker").write_text("original", encoding="utf-8")
            (build / "node_modules").mkdir()
            (build / "node_modules/marker").write_text("original", encoding="utf-8")
            workspace = controller._isolated_poc_workspace(build, base / "run")
            try:
                self.assertNotEqual(workspace / "lib", build / "lib")
                (workspace / "lib/marker").write_text("changed", encoding="utf-8")
                (workspace / "node_modules/marker").write_text("changed", encoding="utf-8")
            finally:
                shutil.rmtree(workspace.parent, ignore_errors=True)
            self.assertEqual((build / "lib/marker").read_text(encoding="utf-8"), "original")
            self.assertEqual((build / "node_modules/marker").read_text(encoding="utf-8"), "original")

            external = base / "external"
            external.write_text("secret", encoding="utf-8")
            (build / "escape").symlink_to(external)
            with self.assertRaisesRegex(ValueError, "symlink"):
                controller._isolated_poc_workspace(build, base / "run")

    def test_project_local_run_tree_is_excluded_from_the_workspace_copy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            build = base / "build"
            (build / "src").mkdir(parents=True)
            (build / "src/Protocol.sol").write_text("contract Protocol {}", encoding="utf-8")
            run_dir = build / ".evm-auditor-work"
            (run_dir / "poc").mkdir(parents=True)
            (run_dir / "poc/Exploit.t.sol").write_text("contract Exploit {}", encoding="utf-8")
            (run_dir / "AUDIT-REPORT.md").write_text("# report", encoding="utf-8")
            workspace = controller._isolated_poc_workspace(build, run_dir)
            try:
                self.assertFalse((workspace / ".evm-auditor-work").exists())
                self.assertTrue((workspace / "src/Protocol.sol").is_file())
                # The disposable copy never lands inside the audited project.
                self.assertNotEqual(workspace.parent, build)
                self.assertEqual(list(build.glob(".verify-poc-*")), [])
            finally:
                shutil.rmtree(workspace.parent, ignore_errors=True)

            # A custom-named managed root is excluded by exact path, while an
            # unrelated directory sharing its basename is still copied.
            custom = build / "security" / "audit-001"
            custom.mkdir(parents=True)
            (custom / "poc").mkdir()
            (custom / "poc/Exploit.t.sol").write_text("contract Exploit {}", encoding="utf-8")
            (build / "src" / "audit-001").mkdir()
            (build / "src" / "audit-001" / "Real.sol").write_text(
                "contract Real {}", encoding="utf-8"
            )
            workspace = controller._isolated_poc_workspace(build, custom)
            try:
                self.assertFalse((workspace / "security" / "audit-001").exists())
                self.assertTrue((workspace / "src/audit-001/Real.sol").is_file())
            finally:
                shutil.rmtree(workspace.parent, ignore_errors=True)

    def test_external_run_keeps_its_workspace_beside_the_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            build = base / "build"
            build.mkdir()
            run_dir = base / "run"
            workspace = controller._isolated_poc_workspace(build, run_dir)
            try:
                self.assertEqual(workspace.parent.parent, base)
            finally:
                shutil.rmtree(workspace.parent, ignore_errors=True)

    def test_changed_source_cannot_be_staged_against_old_evidence_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            run_dir = base / "run"
            workspace = base / "workspace"
            run_dir.mkdir()
            workspace.mkdir()
            source = run_dir / "poc/Exploit.t.sol"
            source.parent.mkdir()
            source.write_bytes(b"changed")
            finding = _finding()
            finding["sources"][0]["sha256"] = hashlib.sha256(b"original").hexdigest()
            with self.assertRaisesRegex(ValueError, "changed while staging"):
                controller._stage_poc_sources(workspace, finding, run_dir)
            self.assertFalse((workspace / "poc-evidence").exists())

    def test_verify_poc_stages_exact_bytes_scrubs_environment_and_cleans_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            build = base / "build"
            run_dir = base / "run"
            build.mkdir()
            run_dir.mkdir()
            (build / "lib").mkdir()
            (build / "lib/marker").write_text("original", encoding="utf-8")
            (build / "node_modules").mkdir()
            (build / "node_modules/marker").write_text("original", encoding="utf-8")
            source = run_dir / "poc/Exploit.t.sol"
            source.parent.mkdir()
            source_bytes = b"contract ExploitTest { function testExploit() public {} }\n"
            source.write_bytes(source_bytes)
            source_hash = hashlib.sha256(source_bytes).hexdigest()
            finding = _finding()
            finding["sources"][0]["sha256"] = source_hash
            manifest = {
                "routing_snapshot_id": HASH,
                "feature_map": {"recon_context": {"build_root": str(build)}},
            }
            state = {"status": "COMPLETE_WITH_FINDINGS", "review_snapshot_id": HASH, "review_state_digest": HASH}
            severity = {"decisions": {"FINDING-1": {"severity": "High"}}}
            poc = {"findings": [finding]}
            inputs = CurrentReportingInputs(
                severity, b"severity", {}, b"details", poc, b"poc", ("FINDING-1",), HASH
            )
            executable = base / "forge"
            executable.write_bytes(b"trusted forge")
            executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
            seen: dict[str, object] = {}

            def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
                cwd = Path(str(kwargs["cwd"]))
                seen["command"] = command
                seen["cwd"] = kwargs["cwd"]
                seen["env"] = kwargs["env"]
                self.assertEqual(
                    (cwd / "poc-evidence/Exploit.t.sol").read_bytes(), source_bytes
                )
                (cwd / "lib/marker").write_text("changed", encoding="utf-8")
                (cwd / "node_modules/marker").write_text("changed", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, stdout=b"ok", stderr=b"")

            with patch.object(controller, "_load_run", return_value=(controller.paths(run_dir), manifest, {})), \
                    patch.object(controller, "status_run", return_value=state), \
                    patch.object(controller, "load_current_reporting_inputs", return_value=inputs), \
                    patch.object(controller, "_trusted_executable", return_value=executable), \
                    patch.object(controller.subprocess, "run", side_effect=fake_run):
                os.environ["EVM_AUDIT_SECRET_SHOULD_NOT_LEAK"] = "secret"
                try:
                    result = controller.verify_poc(ROOT, run_dir)
                finally:
                    os.environ.pop("EVM_AUDIT_SECRET_SHOULD_NOT_LEAK", None)
            self.assertEqual(result["state"], "PASSED")
            command = seen["command"]
            self.assertIn("--match-path", command)
            self.assertIn("poc-evidence/Exploit.t.sol", command)
            environment = seen["env"]
            self.assertNotIn("EVM_AUDIT_SECRET_SHOULD_NOT_LEAK", environment)
            self.assertNotEqual(environment["HOME"], str(Path.home()))
            self.assertFalse(Path(str(seen["cwd"])).exists())
            self.assertEqual((build / "lib/marker").read_text(encoding="utf-8"), "original")
            self.assertEqual((build / "node_modules/marker").read_text(encoding="utf-8"), "original")
            receipt = json.loads((run_dir / "reviews/poc-verification.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["schema_version"], 2)
            self.assertEqual(receipt["results"][0]["staged_sources"][0]["sha256"], source_hash)

    def test_custom_runner_result_is_recorded_not_dropped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            build = base / "build"
            run_dir = base / "run"
            build.mkdir()
            run_dir.mkdir()
            exploit_bytes = b"contract ExploitTest { function testExploit() public {} }\n"
            custom_bytes = b"contract CustomPoC { function reproduce() public {} }\n"
            exploit = run_dir / "poc/Exploit.t.sol"
            exploit.parent.mkdir()
            exploit.write_bytes(exploit_bytes)
            custom = run_dir / "poc/Custom.t.sol"
            custom.write_bytes(custom_bytes)
            foundry = _finding()
            foundry["sources"][0]["sha256"] = hashlib.sha256(exploit_bytes).hexdigest()
            manual = {
                "canonical_id": "FINDING-2",
                "severity": "High",
                "runner": "custom",
                "command": "manual reproduction against a local fork",
                "sources": [
                    {"path": "poc/Custom.t.sol", "sha256": hashlib.sha256(custom_bytes).hexdigest()}
                ],
                "entrypoint": "reproduce",
                "expected_result": "manual reproduction drains funds",
                "result_summary": "manual reproduction drains funds",
            }
            manifest = {
                "routing_snapshot_id": HASH,
                "feature_map": {"recon_context": {"build_root": str(build)}},
            }
            state = {"status": "COMPLETE_WITH_FINDINGS", "review_snapshot_id": HASH, "review_state_digest": HASH}
            inputs = CurrentReportingInputs(
                {"decisions": {"FINDING-1": {"severity": "High"}, "FINDING-2": {"severity": "High"}}},
                b"severity",
                {},
                b"details",
                {"findings": [foundry, manual]},
                b"poc",
                ("FINDING-1", "FINDING-2"),
                HASH,
            )
            executable = base / "forge"
            executable.write_bytes(b"trusted forge")
            executable.chmod(executable.stat().st_mode | stat.S_IXUSR)

            def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
                return subprocess.CompletedProcess(command, 0, stdout=b"ok", stderr=b"")

            with patch.object(controller, "_load_run", return_value=(controller.paths(run_dir), manifest, {})), \
                    patch.object(controller, "status_run", return_value=state), \
                    patch.object(controller, "load_current_reporting_inputs", return_value=inputs), \
                    patch.object(controller, "_trusted_executable", return_value=executable), \
                    patch.object(controller.subprocess, "run", side_effect=fake_run):
                result = controller.verify_poc(ROOT, run_dir)
            by_id = {entry["canonical_id"]: entry for entry in result["results"]}
            self.assertEqual(set(by_id), {"FINDING-1", "FINDING-2"})
            self.assertEqual(by_id["FINDING-1"]["state"], "PASSED")
            self.assertEqual(by_id["FINDING-2"]["state"], "UNVERIFIED")
            self.assertEqual(by_id["FINDING-2"]["runner"], "custom")
            self.assertEqual(
                by_id["FINDING-2"]["reason"], "custom PoC runners are not executed automatically"
            )
            self.assertEqual(by_id["FINDING-2"]["error_code"], "POC_VERIFICATION_FAILED")
            self.assertNotEqual(result["state"], "PASSED")
            self.assertEqual(result["state"], "UNVERIFIED")
            receipt = json.loads((run_dir / "reviews/poc-verification.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["state"], "UNVERIFIED")
            self.assertEqual(len(receipt["results"]), 2)

    def test_custom_only_poc_evidence_produces_unverified_receipt_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            build = base / "build"
            run_dir = base / "run"
            build.mkdir()
            run_dir.mkdir()
            custom_bytes = b"contract CustomPoC { function reproduce() public {} }\n"
            custom_source = run_dir / "poc/Custom.t.sol"
            custom_source.parent.mkdir()
            custom_source.write_bytes(custom_bytes)
            manual = {
                "canonical_id": "FINDING-2",
                "severity": "Critical",
                "runner": "custom",
                "command": "manual reproduction against a local fork",
                "sources": [
                    {"path": "poc/Custom.t.sol", "sha256": hashlib.sha256(custom_bytes).hexdigest()}
                ],
                "entrypoint": "reproduce",
                "expected_result": "manual reproduction drains funds",
                "result_summary": "manual reproduction drains funds",
            }
            manifest = {
                "routing_snapshot_id": HASH,
                "feature_map": {"recon_context": {"build_root": str(build)}},
            }
            state = {"status": "COMPLETE_WITH_FINDINGS", "review_snapshot_id": HASH, "review_state_digest": HASH}
            inputs = CurrentReportingInputs(
                {"decisions": {"FINDING-2": {"severity": "Critical"}}},
                b"severity",
                {},
                b"details",
                {"findings": [manual]},
                b"poc",
                ("FINDING-2",),
                HASH,
            )
            with patch.object(controller, "_load_run", return_value=(controller.paths(run_dir), manifest, {})), \
                    patch.object(controller, "status_run", return_value=state), \
                    patch.object(controller, "load_current_reporting_inputs", return_value=inputs), \
                    patch.object(controller.subprocess, "run") as mock_run:
                result = controller.verify_poc(ROOT, run_dir)
            self.assertFalse(mock_run.called)
            self.assertEqual(result["state"], "UNVERIFIED")
            self.assertEqual(len(result["results"]), 1)
            self.assertEqual(result["results"][0]["state"], "UNVERIFIED")
            receipt = json.loads((run_dir / "reviews/poc-verification.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["state"], "UNVERIFIED")
            self.assertEqual(receipt["runner"], "custom")
            self.assertEqual(len(receipt["results"]), 1)

    @unittest.skipUnless(shutil.which("forge"), "Foundry is not installed")
    def test_real_foundry_executes_the_staged_poc_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            build = base / "build"
            run_dir = base / "run"
            build.mkdir()
            run_dir.mkdir()
            (build / "foundry.toml").write_text(
                '[profile.default]\ntest = "poc-evidence"\nsolc = "/usr/local/bin/solc"\n',
                encoding="utf-8",
            )
            source = run_dir / "poc/Exploit.t.sol"
            source.parent.mkdir()
            content = b"pragma solidity ^0.8.0; contract ExploitTest { function testExploit() public {} }\n"
            source.write_bytes(content)
            finding = _finding()
            finding["sources"][0]["sha256"] = hashlib.sha256(content).hexdigest()
            manifest = {"routing_snapshot_id": HASH, "feature_map": {"recon_context": {"build_root": str(build), "solc_version": "0.8.16"}}}
            state = {"status": "COMPLETE_WITH_FINDINGS", "review_snapshot_id": HASH, "review_state_digest": HASH}
            inputs = CurrentReportingInputs(
                {"decisions": {"FINDING-1": {"severity": "High"}}},
                b"severity",
                {},
                b"details",
                {"findings": [finding]},
                b"poc",
                ("FINDING-1",),
                HASH,
            )
            with patch.object(controller, "_load_run", return_value=(controller.paths(run_dir), manifest, {})), \
                    patch.object(controller, "status_run", return_value=state), \
                    patch.object(controller, "load_current_reporting_inputs", return_value=inputs):
                result = controller.verify_poc(ROOT, run_dir, timeout=60)
            self.assertEqual(result["state"], "PASSED", result)
            self.assertEqual(result["results"][0]["state"], "PASSED")
            self.assertEqual(result["results"][0]["entrypoint"], "poc-evidence/Exploit.t.sol::testExploit")


if __name__ == "__main__":
    unittest.main()
