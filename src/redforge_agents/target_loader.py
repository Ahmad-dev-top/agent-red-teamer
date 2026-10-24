"""Load a target agent description from a YAML config file."""

from __future__ import annotations

from pathlib import Path

import yaml

from redforge_agents.schemas import Target


def load_target(path: Path | str) -> Target:
    path = Path(path)
    raw = yaml.safe_load(path.read_text())
    if not isinstance(raw, dict):
        raise TypeError(f"{path}: target config must be a mapping")
    try:
        return Target.model_validate(raw)
    except Exception as exc:
        raise ValueError(f"{path}: invalid target config: {exc}") from exc
