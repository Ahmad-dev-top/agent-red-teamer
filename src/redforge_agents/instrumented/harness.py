"""The object a user's agent calls instead of its real tools."""

from __future__ import annotations

import time
from typing import Any

from redforge_agents.instrumented.tools import ToolRegistry
from redforge_agents.schemas import RunResult, Target, Turn


class ToolHarness:
    """Records every tools.call. Builds the RunResult the deterministic judge reads."""

    def __init__(self, target: Target) -> None:
        self.registry = ToolRegistry(target)
        self._t0 = time.perf_counter()

    def call(self, name: str, **arguments: Any) -> Any:
        return self.registry.call(name, **arguments)

    def to_result(self, messages: list[Turn], final: str) -> RunResult:
        calls = list(self.registry.calls)
        return RunResult(
            transcript=[*messages, Turn(role="assistant", content=final, tool_calls=calls)],
            tool_calls=calls,
            outbound_payloads=list(self.registry.outbound),
            final_output=final,
            steps=len(calls),
            seconds=time.perf_counter() - self._t0,
        )
