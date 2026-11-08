"""Small shared inputs for Python tests; no test framework or runner lives here."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from scripts.scope_context import DEFAULT_DEPENDENCY_ROOTS, compilation_digests, resolve_build_root, scope_inventory
from scripts.select_checks import audit_context, load_domains, normalize_feature_map, select, vocabulary
from scripts.audit_artifacts import derive_review_snapshot_id
from scripts.render_runtime import domain_context_template, screen_results_template


ROOT = Path(__file__).resolve().parents[1]
EMPTY_TARGET = ROOT / "tests/fixtures/recon/Empty.sol"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def suite_inputs() -> tuple[dict[str, Any], set[str], dict[str, dict[str, Any]]]:
    registry = load_json(ROOT / "data/canonical-checks.json")
    feature_names, policies = vocabulary(load_json(ROOT / "data/features.json"))
    return registry, feature_names, policies


def synthetic_feature_map(
    statuses: Mapping[str, str] | None = None,
    target: Path = EMPTY_TARGET,
) -> dict[str, Any]:
    _, feature_names, policies = suite_inputs()
    build_root = resolve_build_root(target)
    files, excluded = scope_inventory(target)
    digests = compilation_digests(
        target,
        files,
        "0.8.24",
        build_root=build_root,
        dependency_roots=DEFAULT_DEPENDENCY_ROOTS,
    )
    requested = dict(statuses or {})
    features: dict[str, dict[str, Any]] = {}
    for feature in sorted(feature_names):
        status = requested.get(feature, "UNKNOWN")
        if status == "UNKNOWN":
            evidence: list[dict[str, str]] = []
        elif status == "ABSENT_CONFIRMED":
            kind = (policies[feature].get("allowed_absence_evidence") or ["manual"])[0]
            evidence = [{"kind": kind, "location": "fixture", "reason": "explicit fixture evidence", "scope_origin": "AUDIT_SCOPE"}]
        else:
            evidence = [{"kind": "manual", "location": "fixture", "reason": "explicit fixture evidence", "scope_origin": "AUDIT_SCOPE"}]
        features[feature] = {"status": status, "evidence": evidence}
    return {
        "schema_version": 5,
        "recon_context": {
            "target_root": str(target.resolve()),
            "build_root": str(build_root.resolve()),
            "files_analyzed": files,
            "excluded_paths": excluded,
            "exclusion_patterns": [],
            "include_patterns": [],
            "dependency_roots": sorted(DEFAULT_DEPENDENCY_ROOTS),
            "uncompiled_paths": [],
            "source_digest": digests["audit_source_digest"],
            **digests,
            "compilation_complete": True,
            "recon_quality": {
                "compilation_complete": True,
                "absence_filtering_complete": True,
                "mode": "COMPLETE",
                "uncompiled_paths": [],
                "compilation_provenance": "CONSERVATIVE_BUILD_ROOT_FALLBACK",
            },
            "slither_version": "synthetic",
            "solc_version": "0.8.24",
            "navigation_artifacts": {"code_index": None},
        },
        "features": features,
    }


def build_manifest(
    domains: Sequence[str] | None = ("evm-audit-general",),
    statuses: Mapping[str, str] | None = None,
    *,
    all_features: bool = False,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    registry, feature_names, policies = suite_inputs()
    requested = {name: "PRESENT" for name in feature_names} if all_features else {}
    requested.update(statuses or {})
    raw = synthetic_feature_map(requested)
    normalized = normalize_feature_map(raw, feature_names, policies, EMPTY_TARGET)
    context = audit_context(
        ROOT,
        registry,
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
        registry,
        normalized,
        feature_names,
        list(domains) if domains is not None else None,
        context,
        configs,
        environment,
        raw["recon_context"],
    )
    return registry, raw, normalized, manifest


def review_inputs(
    manifest: dict[str, Any],
    domain_resolution: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    screen = screen_results_template(manifest, domain_resolution)
    domain_context = domain_context_template(manifest, domain_resolution)
    evidence = [{"kind": "scope", "location": "fixture", "reason": "complete scope"}]
    for requirements in domain_context["domains"].values():
        for item in requirements.values():
            item.update(status="KNOWN", value="fixture", evidence=evidence)
    return screen, domain_context, derive_review_snapshot_id(
        ROOT, manifest, domain_resolution, domain_context, screen
    )
