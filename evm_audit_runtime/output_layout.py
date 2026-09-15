"""Managed audit-output path model.

The controller owns exactly one explicitly managed output subtree. Generated
artifacts may exist inside it, but they may not overwrite or become part of
authoritative audit inputs: scope discovery, compilation fingerprints, source
snapshots, and PoC build-tree copies all exclude the managed output root.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


DEFAULT_OUTPUT_DIR_NAME = ".evm-auditor-work"
RUN_LAYOUT_SCHEMA_VERSION = 1
RUN_LAYOUT_ARTIFACT_TYPE = "run-layout"
LOCATION_MODES = ("PROJECT_LOCAL", "EXTERNAL")

# Managed output roots never overlap these project subtrees: they hold
# authoritative source, dependency metadata, or volatile build state.
FORBIDDEN_OUTPUT_PARTS = frozenset(
    {".git", "lib", "node_modules", "out", "cache", "artifacts", "build"}
)


def default_output_dir(original_build_root: Path) -> Path:
    """Return the canonical project-local output root for a build root."""
    return original_build_root.resolve() / DEFAULT_OUTPUT_DIR_NAME


def _canonical(path: Path) -> Path:
    # Non-strict: existing symlinked components are resolved and the remaining
    # tail is normalized lexically, so '..' cannot hide from comparisons.
    return path.resolve()


def _relative_or_none(path: Path, root: Path) -> Path | None:
    try:
        return path.relative_to(root)
    except ValueError:
        return None


def resolve_output_dir(
    original_build_root: Path,
    *,
    output_dir: Path | None = None,
    legacy_run_dir: Path | None = None,
) -> Path:
    """Resolve the controller-owned output root for one audit run.

    ``--output-dir`` and the legacy ``--run-dir`` alias are mutually exclusive.
    Relative paths resolve against the audited project's original build root,
    never against the suite root or the process CWD.
    """
    if output_dir is not None and legacy_run_dir is not None:
        raise ValueError("specify only one of --output-dir or --run-dir, not both")
    build_root = original_build_root.resolve()
    if output_dir is None and legacy_run_dir is None:
        return default_output_dir(build_root)
    chosen = Path(output_dir if output_dir is not None else legacy_run_dir).expanduser()
    if not chosen.is_absolute():
        chosen = build_root / chosen
    if chosen.is_symlink():
        raise ValueError(f"output directory must not be a symlink: {chosen}")
    return _canonical(chosen)


def validate_managed_output_root(
    output_root: Path,
    *,
    audit_root: Path,
    build_root: Path,
) -> str:
    """Validate the managed output boundary and return its location mode.

    Supported layouts are (A) one managed output subtree inside the project
    and (B) an arbitrary external output directory. Everything else — the
    project/build root itself, ``.git``, dependency/build/cache trees, or a
    narrower audit scope — stays authoritative input and must not host run
    artifacts.
    """
    resolved = _canonical(output_root)
    audit = _canonical(audit_root)
    build = _canonical(build_root)
    if resolved == build:
        raise ValueError(f"output directory must not be the build root itself: {resolved}")
    if resolved == audit:
        raise ValueError(f"output directory must not be the audit root itself: {resolved}")
    if output_root.is_symlink() or resolved.is_symlink():
        raise ValueError(f"output directory must not be a symlink: {resolved}")
    if os.path.lexists(resolved) and not resolved.is_dir():
        raise ValueError(f"output directory must not be an existing regular file: {resolved}")
    build_relative = _relative_or_none(resolved, build)
    if build_relative is None:
        return "EXTERNAL"
    if any(part in FORBIDDEN_OUTPUT_PARTS for part in build_relative.parts):
        raise ValueError(
            "output directory must not live under dependency/build/cache trees: " + str(resolved)
        )
    if audit.is_dir():
        audit_relative = _relative_or_none(audit, build)
        if audit_relative is not None and audit_relative.parts and _relative_or_none(resolved, audit) is not None:
            raise ValueError(
                f"output directory must not be nested inside the narrower audit root {audit}: {resolved}"
            )
    return "PROJECT_LOCAL"


def location_mode(output_root: Path, workspace_root: Path) -> str:
    resolved = _canonical(output_root)
    workspace = _canonical(workspace_root)
    return "PROJECT_LOCAL" if workspace in resolved.parents else "EXTERNAL"


def run_layout_metadata(workspace_root: Path, output_root: Path) -> dict[str, Any]:
    """Operational sidecar payload describing where the run bundle lives."""
    workspace = _canonical(workspace_root)
    return {
        "artifact_type": RUN_LAYOUT_ARTIFACT_TYPE,
        "schema_version": RUN_LAYOUT_SCHEMA_VERSION,
        "workspace_root": str(workspace),
        "output_root": str(_canonical(output_root)),
        "location_mode": location_mode(output_root, workspace),
    }
