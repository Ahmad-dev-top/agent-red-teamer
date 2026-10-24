"""Stub adapter — scripted RunResults for tests and offline dry runs.

Supports both the single-shot path (`run_attack`, keyed by attack id) and the
multi-turn path (`run_turns`): pass `turn_results` to return a different
RunResult on each successive `run_turns` call, so a test can model an agent that
resists early turns and gives in later — exactly what the attacker loop must
handle.
"""

from __future__ import annotations

from collections.abc import Callable

from redforge_agents.schemas import Attack, RunResult, Target, Turn


class StubAdapter:
    def __init__(
        self,
        by_attack: dict[str, RunResult] | None = None,
        default: Callable[[Target, Attack], RunResult] | None = None,
        turn_results: list[RunResult] | None = None,
    ) -> None:
        self._by_attack = by_attack or {}
        self._default = default
        self._turn_results = list(turn_results or [])
        self.calls: list[str] = []
        self.turn_calls: int = 0

    def run_attack(self, target: Target, attack: Attack) -> RunResult:
        self.calls.append(attack.id)
        if attack.id in self._by_attack:
            return self._by_attack[attack.id]
        if self._default is not None:
            return self._default(target, attack)
        return RunResult(final_output="(stub: agent declined)")

    def run_turns(
        self, target: Target, messages: list[Turn], injected: str | None = None
    ) -> RunResult:
        i = self.turn_calls
        self.turn_calls += 1
        if i < len(self._turn_results):
            return self._turn_results[i]
        return RunResult(final_output="(stub: agent declined)")
