"""In-process adapter: the user's agent runs here, against recording mock tools."""

from __future__ import annotations

from collections.abc import Callable

from redforge_agents.instrumented.harness import ToolHarness
from redforge_agents.logging_conf import get_logger
from redforge_agents.schemas import Attack, RunResult, Target, Turn

log = get_logger("local-adapter")

AgentFn = Callable[[list[dict[str, str]], ToolHarness, str | None], str]


class LocalAgentAdapter:
    """Tier 3, in-process. Pass agent_factory for a fresh agent on every run."""

    def __init__(
        self,
        agent: AgentFn | None = None,
        agent_factory: Callable[[], AgentFn] | None = None,
    ) -> None:
        if agent is None and agent_factory is None:
            raise ValueError("LocalAgentAdapter needs agent= or agent_factory=")
        self._agent = agent
        self._factory = agent_factory

    def _resolve(self) -> AgentFn:
        if self._factory is not None:
            return self._factory()
        assert self._agent is not None
        return self._agent

    def run_attack(self, target: Target, attack: Attack) -> RunResult:
        turns = [Turn(role="user", content=t) for t in attack.turns]
        if not turns:
            turns = [Turn(role="user", content=attack.description or attack.title)]
        return self.run_turns(target, turns, attack.injected_content)

    def run_turns(
        self, target: Target, messages: list[Turn], injected: str | None = None
    ) -> RunResult:
        harness = ToolHarness(target)
        wire = [{"role": m.role, "content": m.content} for m in messages]
        try:
            final = str(self._resolve()(wire, harness, injected))
        except Exception as exc:  # noqa: BLE001 — a broken agent is a failed run, not a scanner crash
            log.warning("local agent failed: %s", exc)
            failed = harness.to_result(messages, "")
            return RunResult(error=f"{type(exc).__name__}: {exc}", seconds=failed.seconds)
        return harness.to_result(messages, final)
