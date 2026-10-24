"""MCP adapter. A recording proxy around a client session's call_tool.

Works for both sync and async call_tool. Other session attributes pass through.
"""

from __future__ import annotations

import inspect
import time
from collections.abc import Callable
from typing import Any

from redforge_agents.adapters.frameworks.collector import CallCollector
from redforge_agents.schemas import Attack, RunResult, Target, Turn

RunFn = Callable[[str, Any], Any]


def _prompt(messages: list[Turn]) -> str:
    users = [m.content for m in messages if m.role == "user"]
    if users:
        return users[-1]
    return messages[-1].content if messages else ""


class RecordingSession:
    def __init__(self, real: Any, collector: CallCollector) -> None:
        self._real = real
        self._collector = collector

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        args = dict(arguments or {})
        result = self._real.call_tool(name, args, **kwargs)
        if inspect.iscoroutine(result):
            collector = self._collector

            async def _capture() -> Any:
                value = await result
                collector.record(name, args, value)
                return value

            return _capture()
        self._collector.record(name, args, result)
        return result

    def __getattr__(self, item: str) -> Any:
        return getattr(self._real, item)


class MCPInterceptor:
    def __init__(self, session: Any, run: RunFn) -> None:
        self._session = session
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
        proxy = RecordingSession(self._session, collector)
        t0 = time.perf_counter()
        final = self._run(_prompt(messages), proxy)
        if inspect.iscoroutine(final):
            import asyncio

            final = asyncio.run(final)
        return collector.to_result(messages, str(final), time.perf_counter() - t0)
