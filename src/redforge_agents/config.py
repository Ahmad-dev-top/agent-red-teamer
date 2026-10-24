"""Central configuration. The only module that reads the environment."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="RFA_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- LLM (attacker + judge second opinion) -----------------------------
    anthropic_api_key: str = Field(default="")
    attacker_model: str = Field(default="claude-opus-4-8")   # strong multi-turn reasoning
    judge_model: str = Field(default="claude-haiku-4-5-20251001")  # cheap second opinion
    target_model: str = Field(default="claude-haiku-4-5-20251001")  # inbox agent brain
    max_tokens: int = Field(default=4096)

    # --- Target model via any OpenAI-compatible endpoint -------------------
    openai_base_url: str = Field(default="https://api.openai.com/v1")
    openai_api_key: str = Field(default="")
    openai_model: str = Field(default="gpt-4o-mini")

    # --- Attack loop -------------------------------------------------------
    max_turns: int = Field(default=6)          # multi-turn attack depth
    mutations_per_seed: int = Field(default=3)  # attacker variations on a failed seed

    # --- Sandbox -----------------------------------------------------------
    sandbox_image: str = Field(default="rfa-sandbox:latest")
    sandbox_memory: str = Field(default="1g")
    sandbox_cpus: float = Field(default=1.0)
    sandbox_timeout_s: int = Field(default=120)

    # --- HTTP adapter ------------------------------------------------------
    http_timeout_s: float = Field(default=60.0)

    # --- Paths -------------------------------------------------------------
    seeds_dir: Path = Field(default=Path("seeds"))
    reports_dir: Path = Field(default=Path("reports"))
    work_dir: Path = Field(default=Path(".rfa_work"))
    db_path: Path = Field(default=Path("reports/redforge.sqlite"))

    def ensure_dirs(self) -> None:
        for p in (self.reports_dir, self.work_dir):
            p.mkdir(parents=True, exist_ok=True)


settings = Settings()
