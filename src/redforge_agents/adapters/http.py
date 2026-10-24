"""HTTP adapter — talks to an agent exposed over an HTTP chat endpoint.

Request JSON:
    {
      "messages":  [{"role": "user"|"assistant", "content": "..."}, ...],
      "injected":  "<poisoned document/email/page, or null>"
    }

Expected response JSON (fields optional unless noted):
    {
      "output":      "final assistant message",        # required
      "tool_calls":  [{"name": "...", "arguments": {...}, "result": ...}, ...],
      "outbound":    ["https://evil/x?d=...", "email body ..."],  # strings sent to sinks
      "steps":       7,
      "cost_usd":    0.0123
    }

The multi-turn attacker loop sends the full evolving conversation (user and
assistant turns) through `run_turns`; `run_attack` is the single-shot wrapper
used by the Week-1/2 campaign.
"""

from __future__ import annotations

import time

import httpx

from redforge_agents.config import settings
from redforge_agents.logging_conf import get_logger
from redforge_agents.schemas import Attack, RunResult, Target, ToolCall, Turn

log = get_logger("http-adapter")


class HttpAdapter:
    def run_attack(self, target: Target, attack: Attack) -> RunResult:
        turns = [Turn(role="user", content=t) for t in attack.turns]
        if not turns:
            turns = [Turn(role="user", content=attack.description or attack.title)]
        return self.run_turns(target, turns, attack.injected_content)

    def run_turns(
        self, target: Target, messages: list[Turn], injected: str | None = None
    ) -> RunResult:
        url = target.config.get("url")
        if not url:
            return RunResult(error="target.config.url is required for the http adapter")
        headers = dict(target.config.get("headers", {}))
        wire = [{"role": m.role, "content": m.content} for m in messages]
        payload = {"messages": wire, "injected": injected}

        t0 = time.perf_counter()
        try:
            resp = httpx.post(url, json=payload, headers=headers, timeout=settings.http_timeout_s)
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            return RunResult(error=f"{type(exc).__name__}: {exc}", seconds=time.perf_counter() - t0)

        tool_calls = [
            ToolCall(
                name=str(tc.get("name", "")),
                arguments=dict(tc.get("arguments", {})),
                result=tc.get("result"),
            )
            for tc in data.get("tool_calls", [])
        ]
        output = str(data.get("output", ""))
        transcript = list(messages)
        transcript.append(Turn(role="assistant", content=output, tool_calls=tool_calls))

        return RunResult(
            transcript=transcript,
            tool_calls=tool_calls,
            outbound_payloads=[str(x) for x in data.get("outbound", [])],
            final_output=output,
            steps=int(data.get("steps", len(tool_calls))),
            cost_usd=float(data.get("cost_usd", 0.0)),
            seconds=time.perf_counter() - t0,
        )
