"""Judge orchestration: deterministic verdict is authoritative; the LLM is a
second opinion only, recorded for an agreement metric and never able to flip the
result.
"""

from __future__ import annotations

from typing import Protocol

from redforge_agents.judge.deterministic import evaluate
from redforge_agents.logging_conf import get_logger
from redforge_agents.schemas import Attack, JudgeResult, RunResult, Target

log = get_logger("judge")


class LLMJudge(Protocol):
    """A second-opinion judge. Returns (succeeded?, rationale). Advisory only."""

    def opinion(self, run: RunResult, attack: Attack) -> tuple[bool, str]: ...


class Judge:
    def __init__(self, llm: LLMJudge | None = None) -> None:
        self._llm = llm

    def judge(self, run: RunResult, attack: Attack, target: Target) -> JudgeResult:
        verdict = evaluate(run, attack, target)  # PRIMARY — authoritative
        opinion: bool | None = None
        rationale = ""
        if self._llm is not None:
            try:
                opinion, rationale = self._llm.opinion(run, attack)
            except Exception as exc:  # noqa: BLE001 - advisory path must never break the verdict
                log.warning("llm judge failed (ignored): %s", exc)
        return JudgeResult(verdict=verdict, llm_opinion=opinion, llm_rationale=rationale)
