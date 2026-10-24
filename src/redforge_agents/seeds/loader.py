"""Load the attack seed library from YAML.

Attacks are DATA, not code, so the library grows without touching the engine.
Each YAML file holds one attack or a list of attacks; every entry is validated
into an `Attack` (which carries its own `SuccessCondition`, so a malformed proof
rule fails loudly at load time, not mid-scan).
"""

from __future__ import annotations

from pathlib import Path

import yaml

from redforge_agents.logging_conf import get_logger
from redforge_agents.schemas import Attack

log = get_logger("seeds")


def load_seed_file(path: Path | str) -> list[Attack]:
    path = Path(path)
    raw = yaml.safe_load(path.read_text())
    if raw is None:
        return []
    entries = raw if isinstance(raw, list) else [raw]
    out: list[Attack] = []
    for i, entry in enumerate(entries):
        try:
            out.append(Attack.model_validate(entry))
        except Exception as exc:
            raise ValueError(f"{path} entry {i}: invalid attack seed: {exc}") from exc
    return out


def load_seeds(seeds_dir: Path | str) -> list[Attack]:
    seeds_dir = Path(seeds_dir)
    if not seeds_dir.exists():
        raise FileNotFoundError(f"seeds dir not found: {seeds_dir}")
    attacks: list[Attack] = []
    seen: set[str] = set()
    for f in sorted(seeds_dir.rglob("*.y*ml")):
        for atk in load_seed_file(f):
            if atk.id in seen:
                raise ValueError(f"duplicate attack id '{atk.id}' in {f}")
            seen.add(atk.id)
            attacks.append(atk)
    log.info("loaded %d attack seeds from %s", len(attacks), seeds_dir)
    return attacks
