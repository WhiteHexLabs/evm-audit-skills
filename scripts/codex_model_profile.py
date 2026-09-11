"""Stage execution policy for audit runs across supported agent providers.

The artifact keeps its machine name ``codex-model-profile`` for lineage
compatibility. It carries a ``provider`` field that selects the stage
vocabulary: ``codex`` (Codex CLI reasoning efforts) or ``zcode`` (ZCode
main agent plus custom worker agent types with ``thoughtLevel`` contracts).

ZCode worker execution contracts are pinned per custom-agent definition:
one agent type = one {model, thought_level} pair = a fixed set of allowed
stages. The validator enforces that a profile stage entry never claims a
contract its dispatched agent cannot execute.
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
CODEX_REASONING_EFFORTS = ("none", "low", "medium", "high", "xhigh", "max")
ZCODE_MODELS = ("GLM-5.3", "GLM-5.3-Flash")

# ZCode thinking vocabulary is model-specific: GLM-5.3 documents
# low/high/max; GLM-5.3-Flash has no verified explicit level, so "default"
# is the only representable value (the worker definition pins no thoughtLevel).
ZCODE_MODEL_THOUGHT_LEVELS = {
    "GLM-5.3": ("low", "high", "max"),
    "GLM-5.3-Flash": ("default",),
}

# Single source of truth for the shipped worker execution contracts. It must
# match the frontmatter of skills/evm-audit-master/agents/<name>.md; the
# profile tests parse those files and reject drift.
ZCODE_WORKER_AGENTS: dict[str, dict[str, Any]] = {
    "evm-audit-worker-flash": {
        "model": "GLM-5.3-Flash",
        "thought_level": "default",
        "allowed_stages": ("DOMAIN_CONTEXT",),
    },
    "evm-audit-worker-deep": {
        "model": "GLM-5.3",
        "thought_level": "high",
        "allowed_stages": ("SCREEN", "DEEP_REVIEW"),
    },
    "evm-audit-worker-proof": {
        "model": "GLM-5.3",
        "thought_level": "max",
        "allowed_stages": ("PROOF",),
    },
}
ZCODE_AGENTS = tuple(ZCODE_WORKER_AGENTS)
PROVIDER_MODELS = {"codex": CODEX_MODELS, "zcode": ZCODE_MODELS}
# codex stages carry {model, reasoning_effort}; zcode stages carry
# {model, thought_level, agent} (agent = worker type, null on controller stages).
PROVIDER_STAGE_KEYS = {
    "codex": {"model", "reasoning_effort"},
    "zcode": {"model", "thought_level", "agent"},
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

# Controller stages (agent null) are main-session handoff recommendations.
# Worker stages must name an agent whose pinned contract can execute them.
# SCREEN deliberately runs the flagship model at high: NOT_APPLICABLE_CONFIRMED
# is a trusted-absence decision, so triage quality is security-relevant.
DEFAULT_ZCODE_MODEL_PROFILE: dict[str, Any] = {
    "schema_version": CODEX_MODEL_PROFILE_VERSION,
    "provider": "zcode",
    "profile_name": "default-balanced-audit",
    "stages": {
        "RECON": {"model": "GLM-5.3", "thought_level": "max", "agent": None},
        "ROUTING": {"model": "GLM-5.3", "thought_level": "max", "agent": None},
        "DOMAIN_RESOLUTION": {"model": "GLM-5.3", "thought_level": "high", "agent": None},
        "DOMAIN_CONTEXT": {"model": "GLM-5.3-Flash", "thought_level": "default", "agent": "evm-audit-worker-flash"},
        "SCREEN": {"model": "GLM-5.3", "thought_level": "high", "agent": "evm-audit-worker-deep"},
        "DEEP_REVIEW": {"model": "GLM-5.3", "thought_level": "high", "agent": "evm-audit-worker-deep"},
        "PROOF": {"model": "GLM-5.3", "thought_level": "max", "agent": "evm-audit-worker-proof"},
        "REPORT": {"model": "GLM-5.3", "thought_level": "high", "agent": None},
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


def _validate_zcode_stage(stage: str, entry: dict[str, Any]) -> None:
    model = entry["model"]
    level = entry["thought_level"]
    if level not in ZCODE_MODEL_THOUGHT_LEVELS[model]:
        raise ValueError(
            f"{stage}: invalid {model} thought level {level!r}; "
            f"supported levels are {', '.join(ZCODE_MODEL_THOUGHT_LEVELS[model])}"
        )
    agent = entry["agent"]
    if agent is None:
        return
    if agent not in ZCODE_WORKER_AGENTS:
        raise ValueError(f"{stage}: invalid zcode agent {agent!r}")
    contract = ZCODE_WORKER_AGENTS[agent]
    if model != contract["model"]:
        raise ValueError(f"{stage}: zcode agent {agent!r} runs {contract['model']}, not {model!r}")
    if level != contract["thought_level"]:
        raise ValueError(
            f"{stage}: zcode agent {agent!r} pins thought level {contract['thought_level']!r}, not {level!r}"
        )
    if stage not in contract["allowed_stages"]:
        raise ValueError(
            f"{stage}: zcode agent {agent!r} may not execute this stage "
            f"(allowed: {', '.join(contract['allowed_stages'])})"
        )


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
        if provider == "codex":
            if entry["reasoning_effort"] not in CODEX_REASONING_EFFORTS:
                raise ValueError(f"{stage}: invalid reasoning effort {entry['reasoning_effort']!r}")
        else:
            _validate_zcode_stage(stage, entry)


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


def _entry_text(entry: dict[str, Any]) -> str:
    effort = entry.get("thought_level", entry.get("reasoning_effort"))
    text = f"{entry['model']} {effort}"
    agent = entry.get("agent")
    return f"{text} · {agent}" if agent is not None else text


def compact_summary(profile: dict[str, Any]) -> str:
    validate_profile(profile)
    groups: dict[tuple[int, str], list[str]] = {}
    for stage in STAGES:
        metadata = progress_metadata(stage)
        groups.setdefault((metadata["step"], metadata["label"]), []).append(stage)

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
