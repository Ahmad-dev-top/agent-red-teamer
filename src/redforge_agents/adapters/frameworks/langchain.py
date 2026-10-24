"""LangChain / LangGraph adapter. Observes tools through a callback handler.

The framework import is lazy. Without langchain-core the handler is a plain
object with the same on_tool_start / on_tool_end methods, so the package still
imports.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from redforge_agents.adapters.frameworks.collector import CallCollector
from redforge_agents.schemas import Attack, RunResult, Target, Turn

RunFn = Callable[[str, list[Any]], str]


def _prompt(messages: list[Turn]) -> str:
    users = [m.content for m in messages if m.role == "user"]
    if users:
        return users[-1]
    return messages[-1].content if messages else ""


def _handler(collector: CallCollector) -> Any:
    def on_tool_start(serialized: Any, input_str: Any, **kwargs: Any) -> None:
        del kwargs
        name = "tool"
        if isinstance(serialized, dict) and serialized.get("name"):
            name = str(serialized["name"])
        args = input_str if isinstance(input_str, dict) else {"input": input_str}
        collector.start(name, args)

    def on_tool_end(output: Any, **kwargs: Any) -> None:
        del kwargs
        collector.finish(output)

    try:
        from langchain_core.callbacks import BaseCallbackHandler
    except ImportError:
        start = on_tool_start
        end = on_tool_end

        class _Duck:
            def on_tool_start(self, serialized: Any, input_str: Any, **kwargs: Any) -> None:
                start(serialized, input_str, **kwargs)

            def on_tool_end(self, output: Any, **kwargs: Any) -> None:
                end(output, **kwargs)

        return _Duck()

    class _LangChainHandler(BaseCallbackHandler):
        def on_tool_start(  # type: ignore[override]
            self, serialized: dict[str, Any], input_str: str, **kwargs: Any
        ) -> None:
            on_tool_start(serialized, input_str, **kwargs)

        def on_tool_end(self, output: Any, **kwargs: Any) -> None:  # type: ignore[override]
            on_tool_end(output, **kwargs)

    return _LangChainHandler()


class LangChainCallbackAdapter:
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
        del injected  # the user's run function receives the prompt, not a separate channel
        collector = CallCollector(target)
        handler = _handler(collector)
        t0 = time.perf_counter()
        final = str(self._run(_prompt(messages), [handler]))
        return collector.to_result(messages, final, time.perf_counter() - t0)
