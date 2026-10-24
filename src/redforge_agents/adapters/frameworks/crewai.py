"""CrewAI adapter. One process-wide POST_TOOL_CALL hook; the collector is per run.

CrewAI registers hooks globally. A ContextVar selects the collector for the
run that is in progress, so overlapping logical runs do not share evidence.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from contextvars import ContextVar
from typing import Any

from redforge_agents.adapters.frameworks.collector import CallCollector
from redforge_agents.schemas import Attack, RunResult, Target, Turn

RunFn = Callable[[str], str]

_active: ContextVar[CallCollector | None] = ContextVar("rfa_crewai_collector", default=None)
_installed = False


def record_crewai_call(tool_name: str, tool_input: Any, tool_result: Any) -> None:
    collector = _active.get()
    if collector is None:
        return
    args = dict(tool_input) if isinstance(tool_input, dict) else {"input": tool_input}
    collector.record(tool_name or "tool", args, tool_result)


def _install_hook() -> None:
    global _installed
    if _installed:
        return
    try:
        from crewai.hooks import after_tool_call
    except ImportError:
        return

    def _hook(context: Any) -> None:
        record_crewai_call(
            str(getattr(context, "tool_name", "") or ""),
            getattr(context, "tool_input", {}) or {},
            getattr(context, "tool_result", None),
        )

    try:
        after_tool_call(_hook)
    except TypeError:
        return
    _installed = True


def _prompt(messages: list[Turn]) -> str:
    users = [m.content for m in messages if m.role == "user"]
    if users:
        return users[-1]
    return messages[-1].content if messages else ""


class CrewAIAdapter:
    def __init__(self, run: RunFn) -> None:
        self._run = run

    def run_attack(self, target: Target, attack: Attack) -> RunResult:
        turns = [Turn(role="user", content=t) for t in attack.turns]
        if not turns:
            turns = [Turn(role="user", content=attack.description or attack.title)]
        return self.run_turns(target, turns, attack.injected_content)

    def run_turns(
        self, target: Target, messages: list[Turn], injected: str | None = None
    ) -> RunResult:
        del injected
        collector = CallCollector(target)
        _install_hook()
        token = _active.set(collector)
        t0 = time.perf_counter()
        try:
            final = str(self._run(_prompt(messages)))
        finally:
            _active.reset(token)
        return collector.to_result(messages, final, time.perf_counter() - t0)
