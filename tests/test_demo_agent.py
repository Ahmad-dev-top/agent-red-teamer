"""Integration: run the real seed library against the live (vulnerable) demo
agent through the real judge, in-process via Starlette's TestClient. Proves the
whole find->prove loop produces evidence-backed findings against a real HTTP
agent — and that the HARDENED variant eliminates them.
"""

import importlib

import pytest

pytest.importorskip("fastapi")
from starlette.testclient import TestClient

from redforge_agents.campaign import run_campaign
from redforge_agents.judge import Judge
from redforge_agents.schemas import Attack, RunResult, Target, ToolCall, Turn
from redforge_agents.seeds import load_seeds
from redforge_agents.target_loader import load_target


class ClientAdapter:
    """TargetAdapter that drives the demo agent in-process (no network)."""

    def __init__(self, client: TestClient) -> None:
        self.client = client

    def run_attack(self, target: Target, attack: Attack) -> RunResult:
        msgs = [{"role": "user", "content": t} for t in attack.turns] or [
            {"role": "user", "content": attack.description or attack.title}
        ]
        r = self.client.post("/chat", json={"messages": msgs, "injected": attack.injected_content})
        data = r.json()
        tcs = [ToolCall(name=c["name"], arguments=c.get("arguments", {}), result=c.get("result"))
               for c in data.get("tool_calls", [])]
        return RunResult(
            transcript=[Turn(role="assistant", content=data.get("output", ""), tool_calls=tcs)],
            tool_calls=tcs,
            outbound_payloads=[str(x) for x in data.get("outbound", [])],
            final_output=data.get("output", ""),
            steps=int(data.get("steps", 0)),
        )


def _client(hardened: bool, monkeypatch) -> TestClient:
    monkeypatch.setenv("HARDENED", "1" if hardened else "0")
    import examples.shop_support.agent as agent_mod
    importlib.reload(agent_mod)  # pick up the HARDENED env
    return TestClient(agent_mod.app)


def test_vulnerable_demo_agent_produces_findings(monkeypatch):
    target = load_target("examples/shop_support/target.yaml")
    attacks = load_seeds("seeds")
    adapter = ClientAdapter(_client(hardened=False, monkeypatch=monkeypatch))

    report = run_campaign(target, attacks, adapter, Judge())

    # the naive agent should fall to several categories, each with hard evidence
    assert len(report.findings) >= 4
    assert all(f.evidence for f in report.findings)
    proven = {f.category.value for f in report.findings}
    # at minimum the destructive, exfil, and leakage breaks should land
    assert "direct_prompt_injection" in proven
    assert "data_exfiltration" in proven or "system_prompt_leakage" in proven


def test_hardened_demo_agent_resists(monkeypatch):
    target = load_target("examples/shop_support/target.yaml")
    attacks = load_seeds("seeds")
    adapter = ClientAdapter(_client(hardened=True, monkeypatch=monkeypatch))

    report = run_campaign(target, attacks, adapter, Judge())

    # hardening should drive the attack-success rate to zero
    assert report.findings == []
    assert all(s.asr == 0.0 for s in report.scores)
