"""Filesystem-only repository trust checks and safe source snapshots."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


SOURCE_TRUSTS = frozenset({"TRUSTED", "UNTRUSTED", "UNKNOWN"})


@dataclass(frozen=True)
class PreparedRepository:
    original_target: Path
    original_audit_root: Path
    original_build_root: Path
    target: Path
    audit_root: Path
    build_root: Path
    trust: dict[str, Any]


def normalize_source_trust(value: str | None) -> str:
    normalized = (value or "UNKNOWN").upper()
    if normalized not in SOURCE_TRUSTS:
        raise ValueError(f"source trust must be one of {sorted(SOURCE_TRUSTS)}")
    return normalized


def git_metadata_kind(root: Path) -> str:
    marker = root / ".git"
    if not os.path.lexists(marker):
        return "ABSENT"
    mode = os.lstat(marker).st_mode
    if stat.S_ISLNK(mode):
        return "SYMLINK"
    if stat.S_ISDIR(mode):
        return "DIRECTORY"
    if stat.S_ISREG(mode):
        return "FILE"
    return "OTHER"


def inspect_repository(root: Path, source_trust: str | None = None) -> dict[str, Any]:
    """Inspect only the source root and its ``.git`` entry; never invoke Git."""
    resolved = root.resolve()
    if not resolved.is_dir():
        raise ValueError(f"repository source root must be a directory: {resolved}")
    trust = normalize_source_trust(source_trust)
    marker_kind = git_metadata_kind(resolved)
    present = marker_kind != "ABSENT"
    blocked = trust != "TRUSTED" and present
    return {
        "source_trust": trust,
        "git_metadata": "PRESENT" if present else "ABSENT",
        "git_metadata_kind": marker_kind,
        "direct_agent_open_allowed": not blocked,
        "required_action": "SANITIZE" if blocked else "OPEN",
    }


def _read_regular_file(path: Path) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError(f"snapshot input is not a regular file: {path}")
        with os.fdopen(descriptor, "rb") as source:
            descriptor = -1
            return source.read()
    finally:
        if descriptor != -1:
            os.close(descriptor)


def _digest_update(digest: "hashlib._Hash", relative: str, data: bytes) -> None:
    digest.update(relative.encode("utf-8"))
    digest.update(b"\0")
    digest.update(str(len(data)).encode("ascii"))
    digest.update(b"\0")
    digest.update(data)
    digest.update(b"\0")


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()

    def visit(directory: Path, prefix: Path) -> None:
        for entry in sorted(os.scandir(directory), key=lambda item: item.name):
            if entry.name == ".git":
                continue
            path = Path(entry.path)
            mode = os.lstat(path).st_mode
            relative = (prefix / entry.name).as_posix()
            if stat.S_ISDIR(mode):
                visit(path, prefix / entry.name)
            elif stat.S_ISREG(mode):
                _digest_update(digest, relative, _read_regular_file(path))
            elif stat.S_ISLNK(mode):
                raise ValueError(f"repository snapshot rejects symlink: {path}")
            else:
                raise ValueError(f"repository snapshot rejects special file: {path}")

    visit(root, Path())
    return digest.hexdigest()


def copy_tree(
    source: Path,
    destination: Path,
    *,
    excluded_names: set[str] | frozenset[str] = frozenset(),
    excluded_relative_paths: Iterable[Path] = (),
    allow_internal_symlinks: bool = False,
    allow_existing_empty: bool = False,
) -> None:
    """Copy regular files without following external links or special files.

    ``excluded_relative_paths`` skips exact source-relative subtrees (for
    example the managed audit output root inside a copied build tree) without
    globally excluding any directory basename.
    """
    source = source.resolve()
    requested_destination = Path(destination)
    if requested_destination.is_symlink():
        raise ValueError(f"copy destination must not be a symlink: {requested_destination}")
    destination = requested_destination.resolve(strict=False)
    if not source.is_dir():
        raise ValueError(f"copy source must be a directory: {source}")
    if destination == source or source in destination.parents:
        raise ValueError("copy destination must be outside the source")
    excluded = {".git", *excluded_names}
    excluded_roots = tuple(path if path.is_absolute() else source / path for path in excluded_relative_paths)
    if destination.exists():
        if not allow_existing_empty or not destination.is_dir() or any(destination.iterdir()):
            raise ValueError(f"copy destination must be a missing directory: {destination}")
    else:
        destination.mkdir(parents=True, exist_ok=False)

    def visit(current: Path, output: Path) -> None:
        for entry in sorted(os.scandir(current), key=lambda item: item.name):
            if entry.name in excluded:
                continue
            path = Path(entry.path)
            if any(path == root or root in path.parents for root in excluded_roots):
                continue
            target = output / entry.name
            mode = os.lstat(path).st_mode
            if stat.S_ISDIR(mode):
                target.mkdir()
                visit(path, target)
            elif stat.S_ISREG(mode):
                target.write_bytes(_read_regular_file(path))
                os.chmod(target, stat.S_IMODE(mode))
            elif stat.S_ISLNK(mode):
                if not allow_internal_symlinks:
                    raise ValueError(f"repository snapshot rejects symlink: {path}")
                try:
                    resolved = path.resolve(strict=True)
                    relative = resolved.relative_to(source)
                except (OSError, RuntimeError, ValueError) as error:
                    raise ValueError(f"repository snapshot rejects escaping or looping symlink: {path}") from error
                link_target = os.path.relpath(destination / relative, target.parent)
                os.symlink(link_target, target, target_is_directory=resolved.is_dir())
            else:
                raise ValueError(f"repository snapshot rejects special file: {path}")

    visit(source, destination)


def sanitize_snapshot(source: Path, destination: Path) -> dict[str, str]:
    """Copy a source tree without Git metadata, symlinks, or special files."""
    source = source.resolve()
    requested_destination = Path(destination)
    if requested_destination.is_symlink():
        raise ValueError(f"sanitized source destination must not be a symlink: {requested_destination}")
    destination = requested_destination.resolve(strict=False)
    if not source.is_dir():
        raise ValueError(f"sanitized source must be a directory: {source}")
    if destination == source or source in destination.parents:
        raise ValueError("sanitized source must be outside the original source")
    if os.path.lexists(destination):
        raise ValueError(f"sanitized source destination already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    before = _tree_digest(source)
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.", dir=str(destination.parent)))
    try:
        copy_tree(source, temporary, allow_existing_empty=True)
        after = _tree_digest(source)
        if before != after:
            raise ValueError("source changed while creating sanitized snapshot")
        if _tree_digest(temporary) != after:
            raise ValueError("sanitized snapshot verification failed")
        temporary.replace(destination)
        temporary = Path()
    finally:
        if temporary != Path() and temporary.exists():
            shutil.rmtree(temporary, ignore_errors=True)
    return {"source_root": str(source), "snapshot_root": str(destination), "snapshot_sha256": after}


def prepare_repository(
    target: Path,
    audit_root: Path,
    build_root: Path,
    *,
    source_trust: str | None = None,
    acquisition_root: Path | None = None,
    snapshot_destination: Path | None = None,
) -> PreparedRepository:
    """Return original paths or paths rooted in a verified sanitized snapshot."""
    original_target = target.resolve()
    original_audit_root = audit_root.resolve()
    original_build_root = build_root.resolve()
    original_source_root = (acquisition_root or original_build_root).resolve()
    if original_source_root.is_file():
        original_source_root = original_source_root.parent
    for label, path in (
        ("target", original_target),
        ("audit root", original_audit_root),
        ("build root", original_build_root),
    ):
        try:
            path.relative_to(original_source_root)
        except ValueError as error:
            raise ValueError(f"{label} must be inside acquisition root before sanitization") from error
    trust = inspect_repository(original_source_root, source_trust)
    if trust["direct_agent_open_allowed"]:
        return PreparedRepository(
            original_target, original_audit_root, original_build_root,
            original_target, original_audit_root, original_build_root,
            {**trust, "original_root": str(original_source_root), "effective_root": str(original_build_root), "sanitized": False, "snapshot_sha256": None},
        )
    if snapshot_destination is None:
        raise ValueError("repository trust gate requires an explicit sanitized snapshot destination")
    snapshot = sanitize_snapshot(original_source_root, snapshot_destination)
    sanitized_root = Path(snapshot["snapshot_root"])

    def relocate(path: Path) -> Path:
        return sanitized_root / path.relative_to(original_source_root)

    trust_artifact = {
        **trust,
        "original_root": str(original_build_root),
        "effective_root": str(sanitized_root),
        "sanitized": True,
        "snapshot_sha256": snapshot["snapshot_sha256"],
    }
    return PreparedRepository(
        original_target, original_audit_root, original_build_root,
        relocate(original_target), relocate(original_audit_root), sanitized_root,
        trust_artifact,
    )
