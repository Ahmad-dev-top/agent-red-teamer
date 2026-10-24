"""In-sandbox entrypoint. Reads a job file, runs the agent on mock tools, prints a RunResult.

Stdout is the result JSON and nothing else. Logs stay off this stream.
"""

from __future__ import annotations

import importlib
import json
import sys
from typing import Any

from redforge_agents.instrumented.harness import ToolHarness
from redforge_agents.schemas import RunResult, Target, Turn


def load_agent(ref: str) -> Any:
    """Import ``module:attr``. If attr is a factory, call it to get the agent function."""
    module_name, _, attr = ref.partition(":")
    if not module_name or not attr:
        raise ValueError(f"agent_ref must be 'module:attr', got {ref!r}")
    module = importlib.import_module(module_name)
    factory = getattr(module, attr)
    agent = factory() if callable(factory) else factory
    if not callable(agent):
        raise TypeError(f"{ref} did not produce a callable agent")
    return agent


def run_job(job: dict[str, Any]) -> RunResult:
    pythonpath = str(job.get("pythonpath") or "")
    if pythonpath and pythonpath not in sys.path:
        sys.path.insert(0, pythonpath)
    target = Target.model_validate(job["target"])
    messages = [Turn.model_validate(m) for m in job.get("messages") or []]
    injected = job.get("injected")
    wire = [{"role": m.role, "content": m.content} for m in messages]
    harness = ToolHarness(target)
    try:
        final = str(load_agent(str(job["agent_ref"]))(wire, harness, injected))
    except Exception as exc:  # noqa: BLE001 — sandbox result must carry the agent error
        return RunResult(error=f"{type(exc).__name__}: {exc}")
    return harness.to_result(messages, final)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    path = args[0] if args else "/work/job.json"
    with open(path, encoding="utf-8") as handle:
        job = json.load(handle)
    result = run_job(job)
    sys.stdout.write(result.model_dump_json())
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
