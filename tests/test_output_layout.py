"""Managed audit-output path model regressions."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from evm_audit_runtime.output_layout import (
    DEFAULT_OUTPUT_DIR_NAME,
    default_output_dir,
    location_mode,
    resolve_output_dir,
    run_layout_metadata,
    validate_managed_output_root,
)
from scripts.audit_artifacts import validate_target_snapshot
from scripts.scope_context import (
    compilation_digests,
    conservative_input_snapshot,
    resolve_build_root,
    scope_inventory,
)
from helpers import synthetic_feature_map


def _foundry_project(parent: Path) -> Path:
    project = (parent / "protocol").resolve()
    (project / "src").mkdir(parents=True, exist_ok=True)
    (project / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    (project / "src" / "Protocol.sol").write_text("contract Protocol {}\n", encoding="utf-8")
    return project


class OutputDirResolutionTests(unittest.TestCase):
    def test_directory_target_defaults_to_build_root_subtree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = _foundry_project(Path(directory))
            resolved = resolve_output_dir(project)
            self.assertEqual(resolved, project / DEFAULT_OUTPUT_DIR_NAME)
            self.assertEqual(default_output_dir(project), resolved)

    def test_nested_audit_root_defaults_to_project_build_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = _foundry_project(Path(directory))
            build_root = resolve_build_root(project / "src", project)
            self.assertEqual(
                resolve_output_dir(build_root),
                project / DEFAULT_OUTPUT_DIR_NAME,
            )

    def test_standalone_sol_defaults_to_file_parent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            target = parent / "Standalone.sol"
            target.write_text("contract Standalone {}\n", encoding="utf-8")
            build_root = resolve_build_root(target)
            self.assertEqual(
                resolve_output_dir(build_root),
                parent / DEFAULT_OUTPUT_DIR_NAME,
            )

    def test_relative_output_dir_resolves_against_build_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = _foundry_project(Path(directory))
            self.assertEqual(
                resolve_output_dir(project, output_dir=Path("audit-results/run-001")),
                project / "audit-results" / "run-001",
            )

    def test_absolute_output_dir_is_used_canonically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            project = _foundry_project(parent)
            requested = parent / "elsewhere" / ".." / "elsewhere" / "audit"
            self.assertEqual(
                resolve_output_dir(project, output_dir=requested),
                parent / "elsewhere" / "audit",
            )

    def test_legacy_run_dir_alias_still_works(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = _foundry_project(Path(directory))
            legacy = Path(directory).resolve() / "legacy-run"
            self.assertEqual(resolve_output_dir(project, legacy_run_dir=legacy), legacy)

    def test_output_dir_and_run_dir_are_mutually_exclusive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = _foundry_project(Path(directory))
            with self.assertRaisesRegex(ValueError, "only one of --output-dir or --run-dir"):
                resolve_output_dir(project, output_dir=Path("a"), legacy_run_dir=Path("b"))

    def test_output_dir_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            project = _foundry_project(parent)
            real = parent / "real"
            real.mkdir()
            link = project / "linked-output"
            link.symlink_to(real)
            with self.assertRaisesRegex(ValueError, "symlink"):
                resolve_output_dir(project, output_dir=link)


class ManagedOutputLayoutTests(unittest.TestCase):
    def test_default_managed_subtree_is_accepted_as_project_local(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = _foundry_project(Path(directory))
            output = project / DEFAULT_OUTPUT_DIR_NAME
            self.assertEqual(
                validate_managed_output_root(output, audit_root=project, build_root=project),
                "PROJECT_LOCAL",
            )
            self.assertEqual(location_mode(output, project), "PROJECT_LOCAL")

    def test_custom_project_local_subtree_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = _foundry_project(Path(directory))
            output = project / "audit-results" / "run-1"
            self.assertEqual(
                validate_managed_output_root(output, audit_root=project, build_root=project),
                "PROJECT_LOCAL",
            )

    def test_external_output_directories_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            project = _foundry_project(parent)
            for candidate in (parent / "sibling-audit", project / ".." / "tmp-audit"):
                self.assertEqual(
                    validate_managed_output_root(
                        candidate, audit_root=project, build_root=project
                    ),
                    "EXTERNAL",
                )

    def test_output_equal_to_build_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = _foundry_project(Path(directory))
            with self.assertRaisesRegex(ValueError, "build root"):
                validate_managed_output_root(project, audit_root=project, build_root=project)

    def test_output_equal_to_audit_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = _foundry_project(Path(directory))
            audit = project / "src"
            with self.assertRaisesRegex(ValueError, "audit root"):
                validate_managed_output_root(audit, audit_root=audit, build_root=project)

    def test_output_path_that_is_a_regular_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = _foundry_project(Path(directory))
            victim = project / "audit-output"
            victim.write_text("not a directory\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "regular file"):
                validate_managed_output_root(victim, audit_root=project, build_root=project)

    def test_output_root_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            project = _foundry_project(parent)
            real = parent / "real"
            real.mkdir()
            link = project / "linked"
            link.symlink_to(real)
            with self.assertRaisesRegex(ValueError, "symlink"):
                validate_managed_output_root(link, audit_root=project, build_root=project)

    def test_output_below_forbidden_project_subtrees_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = _foundry_project(Path(directory))
            for part in (".git", "lib", "node_modules", "out", "cache", "artifacts", "build"):
                with self.subTest(part=part):
                    with self.assertRaisesRegex(ValueError, "dependency/build/cache"):
                        validate_managed_output_root(
                            project / part / "audit",
                            audit_root=project,
                            build_root=project,
                        )

    def test_output_nested_inside_narrower_audit_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = _foundry_project(Path(directory))
            audit = project / "src"
            with self.assertRaisesRegex(ValueError, "narrower audit root"):
                validate_managed_output_root(
                    audit / "audit-output", audit_root=audit, build_root=project
                )

    def test_run_layout_metadata_reports_operational_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            project = _foundry_project(parent)
            output = project / DEFAULT_OUTPUT_DIR_NAME
            self.assertEqual(
                run_layout_metadata(project, output),
                {
                    "artifact_type": "run-layout",
                    "schema_version": 1,
                    "workspace_root": str(project),
                    "output_root": str(output),
                    "location_mode": "PROJECT_LOCAL",
                },
            )
            external = parent / "external-run"
            self.assertEqual(
                run_layout_metadata(project, external)["location_mode"],
                "EXTERNAL",
            )


class ManagedOutputExclusionTests(unittest.TestCase):
    """Generated artifacts under the managed root stay outside audit identity."""

    def _project_with_poc(self, directory: Path, output: Path) -> Path:
        project = _foundry_project(directory)
        (output / "poc").mkdir(parents=True, exist_ok=True)
        (output / "poc" / "Exploit.t.sol").write_text(
            "contract ExploitTest {}\n", encoding="utf-8"
        )
        (output / "AUDIT-REPORT.md").write_text("# report\n", encoding="utf-8")
        return project

    def test_poc_sources_neither_included_nor_excluded_in_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            project = self._project_with_poc(parent, parent / "protocol" / DEFAULT_OUTPUT_DIR_NAME)
            included, excluded = scope_inventory(
                project,
                excluded_roots=(project / DEFAULT_OUTPUT_DIR_NAME,),
            )
            self.assertEqual(included, ["src/Protocol.sol"])
            self.assertEqual(excluded, [])
            # Without the exact root the generated source would be inventoried.
            unmanaged_included, _ = scope_inventory(project)
            self.assertEqual(unmanaged_included, ["src/Protocol.sol"])

    def test_custom_output_root_exclusion_is_path_based(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            output = parent / "protocol" / "security" / "audit-001"
            project = self._project_with_poc(parent, output)
            # An unrelated directory sharing the basename is not excluded.
            (project / "src" / "audit-001").mkdir(parents=True, exist_ok=True)
            (project / "src" / "audit-001" / "Real.sol").write_text(
                "contract Real {}\n", encoding="utf-8"
            )
            included, _ = scope_inventory(project, excluded_roots=(output,))
            self.assertEqual(included, ["src/Protocol.sol", "src/audit-001/Real.sol"])

    def test_managed_output_never_changes_digests_or_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            output = parent / "protocol" / DEFAULT_OUTPUT_DIR_NAME
            project = self._project_with_poc(parent, output)
            files, _ = scope_inventory(project, excluded_roots=(output,))
            snapshot_kwargs = {
                "build_root": project,
                "boundary": project,
                "excluded_roots": (output,),
            }
            before = conservative_input_snapshot(project, **snapshot_kwargs)
            digests_before = compilation_digests(
                project, files, None, build_root=project, boundary=project, excluded_roots=(output,)
            )
            (output / "poc" / "Second.t.sol").write_text(
                "contract Second {}\n", encoding="utf-8"
            )
            (output / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            self.assertEqual(
                conservative_input_snapshot(project, **snapshot_kwargs),
                before,
            )
            self.assertEqual(
                compilation_digests(
                    project, files, None, build_root=project, boundary=project, excluded_roots=(output,)
                ),
                digests_before,
            )

    def test_validate_target_snapshot_ignores_only_the_managed_subtree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            project = _foundry_project(parent)
            output = project / DEFAULT_OUTPUT_DIR_NAME
            # Routing binds digests while the managed output root is empty.
            manifest = {"feature_map": synthetic_feature_map(target=project)}
            self._project_with_poc(parent, output)
            validate_target_snapshot(manifest, managed_output_root=output)
            (output / "poc" / "More.t.sol").write_text("contract More {}\n", encoding="utf-8")
            validate_target_snapshot(manifest, managed_output_root=output)
            (project / "src" / "Protocol.sol").write_text(
                "contract Protocol { uint256 changed; }\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "changed after routing"):
                validate_target_snapshot(manifest, managed_output_root=output)


if __name__ == "__main__":
    unittest.main()
