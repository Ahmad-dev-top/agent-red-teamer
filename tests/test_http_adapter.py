"""HTTP adapter parses the documented response shape into a RunResult, and turns
transport errors into a non-crashing error result (never a false success)."""

import httpx

from redforge_agents.adapters import HttpAdapter
from redforge_agents.schemas import (
    Attack,
    AttackCategory,
    OwaspId,
    ProofType,
    SuccessCondition,
    Target,
)


def _attack() -> Attack:
    return Attack(
        id="a", category=AttackCategory.DIRECT_INJECTION, owasp=OwaspId.LLM01,
        title="t", turns=["do the thing"],
        success=SuccessCondition(proof=ProofType.FORBIDDEN_TOOL_CALL, tool="x"),
    )


def _target(url="http://agent.test/chat") -> Target:
    return Target(id="t", name="T", config={"url": url})


def test_parses_response(monkeypatch):
    def fake_post(url, json, headers, timeout):
        req = httpx.Request("POST", url)
        return httpx.Response(
            200, request=req,
            json={
                "output": "done",
                "tool_calls": [{"name": "issue_refund", "arguments": {"amount": 5000}}],
                "outbound": ["https://evil/x?d=CANARY"],
                "steps": 7, "cost_usd": 0.012,
            },
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    run = HttpAdapter().run_attack(_target(), _attack())
    assert run.error is None
    assert run.final_output == "done"
    assert run.tool_calls[0].name == "issue_refund"
    assert run.tool_calls[0].arguments["amount"] == 5000
    assert run.outbound_payloads == ["https://evil/x?d=CANARY"]
    assert run.steps == 7 and run.cost_usd == 0.012


def test_transport_error_becomes_error_result(monkeypatch):
    def boom(*a, **k):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(httpx, "post", boom)
    run = HttpAdapter().run_attack(_target(), _attack())
    assert run.error is not None and "ConnectError" in run.error
    assert run.tool_calls == []  # no false evidence


def test_missing_url_is_error():
    run = HttpAdapter().run_attack(Target(id="t", name="T", config={}), _attack())
    assert run.error is not None and "url" in run.error
