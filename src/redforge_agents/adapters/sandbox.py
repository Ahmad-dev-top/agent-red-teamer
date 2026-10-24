"""Tier 3 with Docker isolation. The agent and mock tools run in a network-none container.

``runner`` is injectable so tests never need Docker. A real run uses SandboxRunner.
Multi-turn is stateless: each turn is a fresh container.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Protocol

from redforge_agents.logging_conf import get_logger
from redforge_agents.sandbox.runner import SandboxResult, SandboxRunner
from redforge_agents.schemas import Attack, RunResult, Target, Turn

log = get_logger("sandbox-adapter")


class SandboxLike(Protocol):
    def run(self, command: str, workspace: Path) -> SandboxResult: ...


class SandboxAdapter:
    def __init__(
        self,
        agent_ref: str,
        runner: SandboxLike | None = None,
        agent_pythonpath: str = "/work/agent",
    ) -> None:
        self.agent_ref = agent_ref
        self.agent_pythonpath = agent_pythonpath
        self.runner = runner if runner is not None else SandboxRunner(network="none")

    def run_attack(self, target: Target, attack: Attack) -> RunResult:
        turns = [Turn(role="user", content=t) for t in attack.turns]
        if not turns:
            turns = [Turn(role="user", content=attack.description or attack.title)]
        return self.run_turns(target, turns, attack.injected_content)

    def run_turns(
        self, target: Target, messages: list[Turn], injected: str | None = None
    ) -> RunResult:
        job: dict[str, Any] = {
            "agent_ref": self.agent_ref,
            "pythonpath": self.agent_pythonpath,
            "injected": injected,
            "target": target.model_dump(mode="json"),
            "messages": [m.model_dump(mode="json") for m in messages],
        }
        with tempfile.TemporaryDirectory(prefix="rfa-sandbox-") as raw:
            workspace = Path(raw)
            (workspace / "job.json").write_text(json.dumps(job), encoding="utf-8")
            command = "python -m redforge_agents.instrumented.runner_entry /work/job.json"
            log.info("sandbox agent_ref=%s", self.agent_ref)
            result = self.runner.run(command, workspace)
        if not result.ok:
            detail = result.stderr.strip() or f"sandbox exit {result.exit_code}"
            return RunResult(error=detail)
        try:
            return RunResult.model_validate_json(result.stdout)
        except ValueError:
            return RunResult(error="sandbox returned no run result")
