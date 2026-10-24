"""Target adapters connect the scanner to the agent under test.

Two methods:
- `run_attack(target, attack)` — single-shot: run a seed's own turns once. (Weeks 1-2)
- `run_turns(target, messages, injected)` — send an arbitrary, evolving
  conversation (user + assistant turns) and return the result. The multi-turn
  attacker loop (Week 3) drives the agent through this, appending each of the
  agent's replies and the attacker's next message. `run_attack` is a convenience
  wrapper over `run_turns`.

Adapters are injected so the loop and judge are testable with a stub (no network,
no API key). HTTP and stub ship now; OpenAI-compatible and MCP land in weeks 3-4.
"""

from __future__ import annotations

from typing import Protocol

from redforge_agents.schemas import AdapterKind, Attack, RunResult, Target, Turn


class TargetAdapter(Protocol):
    def run_attack(self, target: Target, attack: Attack) -> RunResult: ...

    def run_turns(
        self, target: Target, messages: list[Turn], injected: str | None = None
    ) -> RunResult: ...


def build_adapter(kind: AdapterKind) -> TargetAdapter:
    """Factory — returns the adapter for a target's declared kind."""
    from redforge_agents.adapters.http import HttpAdapter
    from redforge_agents.adapters.stub import StubAdapter

    if kind is AdapterKind.HTTP:
        return HttpAdapter()
    if kind is AdapterKind.STUB:
        return StubAdapter()
    # openai_compatible and mcp are scaffolded in CURSOR.md (weeks 3-4).
    raise NotImplementedError(f"adapter '{kind.value}' not yet implemented; use http or stub")
