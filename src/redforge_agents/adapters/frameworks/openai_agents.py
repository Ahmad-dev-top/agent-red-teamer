"""OpenAI Agents SDK adapter. Observes tools through RunHooks.

Start/end pairing is FIFO. That is correct for sequential tool use; nested or
parallel calls may mispair. Args come from ctx.tool_arguments when the SDK
exposes them.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from redforge_agents.adapters.frameworks.collector import CallCollector
from redforge_agents.schemas import Attack, RunResult, Target, Turn

RunFn = Callable[[str, Any], str]


def _prompt(messages: list[Turn]) -> str:
    users = [m.content for m in messages if m.role == "user"]
    if users:
        return users[-1]
    return messages[-1].content if messages else ""


class OpenAIToolHooks:
    """Duck-typed hooks. Subclassed from RunHooks when the SDK is installed."""

    def __init__(self, collector: CallCollector) -> None:
        self._collector = collector

    async def on_tool_start(self, ctx: Any, agent: Any, tool: Any) -> None:
        del agent
        raw = getattr(ctx, "tool_arguments", None) or {}
        args = dict(raw) if isinstance(raw, dict) else {"input": raw}
        self._collector.start(str(getattr(tool, "name", tool)), args)

    async def on_tool_end(self, ctx: Any, agent: Any, tool: Any, result: Any) -> None:
        del ctx, agent
        name = str(getattr(tool, "name", "") or "") or None
        self._collector.finish(result, name=name)


def build_hooks(collector: CallCollector) -> Any:
    base = OpenAIToolHooks(collector)
    try:
        from agents import RunHooks
    except ImportError:
        return base

    class _SdkHooks(RunHooks):  # type: ignore[misc]
        async def on_tool_start(self, ctx: Any, agent: Any, tool: Any) -> None:
            await base.on_tool_start(ctx, agent, tool)

        async def on_tool_end(self, ctx: Any, agent: Any, tool: Any, result: Any) -> None:
            await base.on_tool_end(ctx, agent, tool, result)

    return _SdkHooks()


class OpenAIAgentsAdapter:
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
        hooks = build_hooks(collector)
        t0 = time.perf_counter()
        final = str(self._run(_prompt(messages), hooks))
        return collector.to_result(messages, final, time.perf_counter() - t0)
