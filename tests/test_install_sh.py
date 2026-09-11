"""Tests for the managed installer (skills + ZCode worker agents)."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_AGENTS = ("evm-audit-worker-flash", "evm-audit-worker-deep", "evm-audit-worker-proof")


def _run_install(home: Path, agent: str) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment["HOME"] = str(home)
    return subprocess.run(
        ["bash", str(ROOT / "install.sh"), agent],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=environment,
    )


def _skills(home: Path) -> list[Path]:
    return sorted((home / ".zcode/skills" if (home / ".zcode").exists() else home / ".codex/skills").glob("evm-audit-*"))


class InstallShTests(unittest.TestCase):
    def test_fresh_codex_install(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            result = _run_install(home, "codex")
            self.assertEqual(result.returncode, 0, result.stderr)
            links = _skills(home)
            self.assertEqual(len(links), 20)
            for link in links:
                self.assertTrue((link / "SKILL.md").is_file(), link)
            self.assertFalse((home / ".codex/agents").exists())
            self.assertFalse((home / ".zcode").exists())

    def test_fresh_zcode_install_includes_worker_agents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            result = _run_install(home, "zcode")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(_skills(home)), 20)
            for name in REQUIRED_AGENTS:
                link = home / ".zcode/agents" / f"{name}.md"
                self.assertTrue(link.is_symlink(), link)
                self.assertIn("new ZCode session is required", result.stdout)
                text = link.read_text(encoding="utf-8")
                self.assertIn(f"name: {name}", text)
                self.assertIn("model:", text)

    def test_idempotent_rerun(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            self.assertEqual(_run_install(home, "zcode").returncode, 0)
            again = _run_install(home, "zcode")
            self.assertEqual(again.returncode, 0, again.stderr)
            self.assertEqual(len(_skills(home)), 20)
            for name in REQUIRED_AGENTS:
                self.assertTrue((home / ".zcode/agents" / f"{name}.md").is_symlink())

    def test_conflicting_skill_entry_blocks_all_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            conflict = home / ".zcode/skills/evm-audit-general"
            conflict.parent.mkdir(parents=True)
            conflict.mkdir()
            result = _run_install(home, "zcode")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("no entries were modified", result.stderr)
            self.assertFalse((home / ".zcode/agents").exists())
            created = [link for link in (home / ".zcode/skills").glob("evm-audit-*") if link != conflict]
            self.assertEqual(created, [], "preflight conflict must block every link")

    def test_conflicting_agent_entry_blocks_all_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            agents = home / ".zcode/agents"
            agents.mkdir(parents=True)
            (agents / "evm-audit-worker-deep.md").write_text("---\nname: evm-audit-worker-deep\n---\nuser-owned\n")
            result = _run_install(home, "zcode")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("no entries were modified", result.stderr)
            created = list((home / ".zcode/skills").glob("evm-audit-*")) if (home / ".zcode/skills").exists() else []
            self.assertEqual(created, [], "preflight conflict must block skill links too")
            self.assertIn("user-owned", (agents / "evm-audit-worker-deep.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
