"""Stage execution policy for audit runs across supported agent providers.

The artifact keeps its machine name ``codex-model-profile`` for lineage
compatibility; as of schema version 2 it carries a ``provider`` field that
selects the stage vocabulary: ``codex`` (Codex CLI stages) or ``zcode``
(ZCode main agent plus custom worker agent types).
"""

from __future__ import annotations

from copy import deepcopy
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from evm_audit_runtime.controller_state import STAGE_PROGRESS, progress_metadata
from evm_audit_runtime.versions import CODEX_MODEL_PROFILE_VERSION

try:
    from audit_artifacts import atomic_write_json
except ImportError:  # pragma: no cover
    from scripts.audit_artifacts import atomic_write_json


STAGES = (
    "RECON",
    "ROUTING",
    "DOMAIN_RESOLUTION",
    "DOMAIN_CONTEXT",
    "SCREEN",
    "DEEP_REVIEW",
    "PROOF",
    "REPORT",
)
PROVIDERS = ("codex", "zcode")
PROVIDER_LABELS = {"codex": "Codex", "zcode": "ZCode"}
CODEX_MODELS = ("gpt-5.6-luna", "gpt-5.6-terra", "gpt-5.6-sol")
ZCODE_MODELS = ("GLM-5.3", "GLM-5.3-Flash")
REASONING_EFFORTS = ("none", "low", "medium", "high", "xhigh", "max")

# ZCode dispatch: the worker agent type pins the model that runs it. The
# profile must not claim a model the agent type does not use.
ZCODE_AGENTS = ("evm-audit-worker-deep", "evm-audit-worker-flash")
ZCODE_AGENT_MODELS = {
    "evm-audit-worker-deep": "GLM-5.3",
    "evm-audit-worker-flash": "GLM-5.3-Flash",
}
PROVIDER_MODELS = {"codex": CODEX_MODELS, "zcode": ZCODE_MODELS}
# zcode stage entries additionally carry an `agent` key (worker agent type or
# null for controller-run stages); codex entries keep the v1 shape.
PROVIDER_STAGE_KEYS = {
    "codex": {"model", "reasoning_effort"},
    "zcode": {"model", "reasoning_effort", "agent"},
}


DEFAULT_CODEX_MODEL_PROFILE: dict[str, Any] = {
    "schema_version": CODEX_MODEL_PROFILE_VERSION,
    "provider": "codex",
    "profile_name": "default-balanced-audit",
    "stages": {
        "RECON": {"model": "gpt-5.6-luna", "reasoning_effort": "max"},
        "ROUTING": {"model": "gpt-5.6-luna", "reasoning_effort": "max"},
        "DOMAIN_RESOLUTION": {"model": "gpt-5.6-terra", "reasoning_effort": "medium"},
        "DOMAIN_CONTEXT": {"model": "gpt-5.6-terra", "reasoning_effort": "medium"},
        "SCREEN": {"model": "gpt-5.6-terra", "reasoning_effort": "high"},
        "DEEP_REVIEW": {"model": "gpt-5.6-sol", "reasoning_effort": "high"},
        "PROOF": {"model": "gpt-5.6-sol", "reasoning_effort": "max"},
        "REPORT": {"model": "gpt-5.6-terra", "reasoning_effort": "medium"},
    },
}

# SCREEN intentionally runs the flagship model: NOT_APPLICABLE_CONFIRMED is a
# trusted-absence decision, so triage quality is security-relevant.
DEFAULT_ZCODE_MODEL_PROFILE: dict[str, Any] = {
    "schema_version": CODEX_MODEL_PROFILE_VERSION,
    "provider": "zcode",
    "profile_name": "default-balanced-audit",
    "stages": {
        "RECON": {"model": "GLM-5.3", "reasoning_effort": "max", "agent": None},
        "ROUTING": {"model": "GLM-5.3", "reasoning_effort": "max", "agent": None},
        "DOMAIN_RESOLUTION": {"model": "GLM-5.3", "reasoning_effort": "medium", "agent": None},
        "DOMAIN_CONTEXT": {"model": "GLM-5.3-Flash", "reasoning_effort": "medium", "agent": "evm-audit-worker-flash"},
        "SCREEN": {"model": "GLM-5.3", "reasoning_effort": "high", "agent": "evm-audit-worker-deep"},
        "DEEP_REVIEW": {"model": "GLM-5.3", "reasoning_effort": "high", "agent": "evm-audit-worker-deep"},
        "PROOF": {"model": "GLM-5.3", "reasoning_effort": "max", "agent": "evm-audit-worker-deep"},
        "REPORT": {"model": "GLM-5.3", "reasoning_effort": "medium", "agent": None},
    },
}

DEFAULT_PROFILES: dict[str, dict[str, Any]] = {
    "codex": DEFAULT_CODEX_MODEL_PROFILE,
    "zcode": DEFAULT_ZCODE_MODEL_PROFILE,
}


def default_profile(provider: str = "codex") -> dict[str, Any]:
    if provider not in PROVIDERS:
        raise ValueError(f"unsupported provider {provider!r}; expected one of {', '.join(PROVIDERS)}")
    return deepcopy(DEFAULT_PROFILES[provider])


def validate_profile(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("Codex model profile must be an object")
    if set(value) != {"schema_version", "provider", "profile_name", "stages"}:
        raise ValueError("Codex model profile has unexpected or missing fields")
    if isinstance(value["schema_version"], bool) or value["schema_version"] != CODEX_MODEL_PROFILE_VERSION:
        raise ValueError(f"Codex model profile schema_version must be {CODEX_MODEL_PROFILE_VERSION}")
    provider = value["provider"]
    if provider not in PROVIDERS:
        raise ValueError(f"Codex model profile provider must be one of {', '.join(PROVIDERS)}")
    label = PROVIDER_LABELS[provider]
    if not isinstance(value["profile_name"], str) or not value["profile_name"].strip():
        raise ValueError("Codex model profile profile_name must be non-empty")
    stages = value["stages"]
    if not isinstance(stages, dict) or set(stages) != set(STAGES):
        raise ValueError(f"Codex model profile stages must be exactly {', '.join(STAGES)}")
    expected_keys = PROVIDER_STAGE_KEYS[provider]
    for stage in STAGES:
        entry = stages[stage]
        if not isinstance(entry, dict) or set(entry) != expected_keys:
            raise ValueError(
                f"Codex model profile {stage} must contain exactly {', '.join(sorted(expected_keys))} for provider {provider}"
            )
        if entry["model"] not in PROVIDER_MODELS[provider]:
            raise ValueError(f"{stage}: unsupported {label} model {entry['model']!r}")
        if entry["reasoning_effort"] not in REASONING_EFFORTS:
            raise ValueError(f"{stage}: invalid reasoning effort {entry['reasoning_effort']!r}")
        if provider == "zcode":
            agent = entry["agent"]
            if agent is not None and agent not in ZCODE_AGENTS:
                raise ValueError(f"{stage}: invalid zcode agent {agent!r}")
            if agent is not None and entry["model"] != ZCODE_AGENT_MODELS[agent]:
                raise ValueError(
                    f"{stage}: zcode agent {agent!r} runs {ZCODE_AGENT_MODELS[agent]}, not {entry['model']!r}"
                )


def load_profile(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc.msg}") from exc
    validate_profile(value)
    return value


def write_profile(path: Path, profile: dict[str, Any]) -> dict[str, Any]:
    validate_profile(profile)
    atomic_write_json(path, profile)
    return profile


def write_default_profile(path: Path) -> dict[str, Any]:
    return write_profile(path, default_profile())


def global_profile_path(provider: str = "codex") -> Path:
    if provider not in PROVIDERS:
        raise ValueError(f"unsupported provider {provider!r}; expected one of {', '.join(PROVIDERS)}")
    return Path.home() / f".{provider}" / "evm-audit-model-profile.json"


def load_global_profile(path: Path | None = None) -> dict[str, Any] | None:
    path = path or global_profile_path()
    return load_profile(path) if path.exists() else None


def init_global_profile(path: Path | None = None, provider: str = "codex") -> dict[str, Any]:
    path = path or global_profile_path(provider)
    if path.exists():
        raise ValueError(f"refusing to overwrite existing global model profile: {path}")
    return write_profile(path, default_profile(provider))


def stage_model(profile: dict[str, Any], stage: str) -> dict[str, str]:
    validate_profile(profile)
    if stage not in STAGES:
        raise ValueError(f"unknown audit stage: {stage}")
    return dict(profile["stages"][stage])


def compact_summary(profile: dict[str, Any]) -> str:
    validate_profile(profile)
    groups: dict[tuple[int, str], list[str]] = {}
    for stage in STAGES:
        metadata = progress_metadata(stage)
        groups.setdefault((metadata["step"], metadata["label"]), []).append(stage)

    def _entry_text(entry: dict[str, Any]) -> str:
        text = f"{entry['model']} {entry['reasoning_effort']}"
        agent = entry.get("agent")
        return f"{text} · {agent}" if agent is not None else text

    lines: list[str] = []
    for _, stages in sorted(groups.items()):
        label = progress_metadata(stages[0])["label"]
        executions = {_entry_text(profile["stages"][stage]) for stage in stages}
        if len(executions) == 1:
            lines.append(f"{label}: {next(iter(executions))}")
            continue
        for stage in stages:
            metadata = progress_metadata(stage)
            entry = profile["stages"][stage]
            lines.append(
                f"{metadata['label']} · {STAGE_PROGRESS[stage].get('substage', stage)}: "
                f"{_entry_text(entry)}"
            )
    return "\n".join(lines)
