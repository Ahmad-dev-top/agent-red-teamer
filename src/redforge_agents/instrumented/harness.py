"""The object a user's agent calls instead of its real tools."""

from __future__ import annotations

import time
from typing import Any

from redforge_agents.instrumented.tools import ToolRegistry
from redforge_agents.schemas import RunResult, Target, ToolCall, Turn


class HarnessContext:
    """Policy facts the agent can check without invoking a tool."""

    def __init__(self, registry: ToolRegistry) -> None:
        self._registry = registry

    def is_external(self, address: str) -> bool:
        """True when ``address`` is outside the target's internal domains."""
        raw = str(address)
        if "@" not in raw:
            return True
        domain = raw.rsplit("@", 1)[-1].lower()
        return domain not in self._registry.internal_domains


class ToolHarness:
    """Records every tools.call. Builds the RunResult the deterministic judge reads."""

    def __init__(self, target: Target) -> None:
        self.registry = ToolRegistry(target)
        self.ctx = HarnessContext(self.registry)
        self._t0 = time.perf_counter()

    def call(self, name: str, **arguments: Any) -> Any:
        return self.registry.call(name, **arguments)

    def record_block(self, name: str, reason: str = "", **arguments: Any) -> dict[str, Any]:
        """Record a tool-layer control event WITHOUT invoking a mock: the agent's
        gate/DLP refused or sanitized an action. The logged result carries
        ``blocked: True`` so assurance attribution credits a tool-layer block (a
        durable control), not a model refusal. No outbound is produced."""
        result: dict[str, Any] = {"blocked": True, "reason": reason}
        self.registry.calls.append(
            ToolCall(name=name, arguments=dict(arguments), result=result)
        )
        return result

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
