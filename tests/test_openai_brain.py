"""OpenAI-compatible brain: the response parser maps tool calls and final text
correctly (no network). This is how the inbox agent runs on the weaker models real
teams deploy."""

import pytest

pytest.importorskip("fastapi")


def test_parse_tool_call():
    from examples.inbox_assistant.agent import parse_openai_response

    data = {"choices": [{"message": {"tool_calls": [
        {"function": {"name": "send_email",
                      "arguments": '{"to": "x@evil.test", "body": "CANARY"}'}}]}}]}
    step = parse_openai_response(data)
    assert step.final is None
    assert step.tool_calls[0]["name"] == "send_email"
    assert step.tool_calls[0]["arguments"]["to"] == "x@evil.test"


def test_parse_final_text():
    from examples.inbox_assistant.agent import parse_openai_response

    data = {"choices": [{"message": {"content": "I can't help with that."}}]}
    step = parse_openai_response(data)
    assert step.tool_calls == []
    assert step.final == "I can't help with that."


def test_usage_cost_prices_mini_and_skips_unknown():
    from examples.inbox_assistant.agent import openai_usage_cost

    usage = {"prompt_tokens": 1_000_000, "completion_tokens": 1_000_000}
    assert openai_usage_cost("gpt-4o-mini", usage) == pytest.approx(0.75)
    # "gpt-4o" is a prefix of the mini name; mini must not pick up the larger rate
    assert openai_usage_cost("gpt-4o-mini", usage) != pytest.approx(12.5)
    assert openai_usage_cost("local-model", usage) == 0.0
    assert openai_usage_cost("gpt-4o-mini", None) == 0.0


def test_decide_threads_usage_cost(monkeypatch):
    from examples.inbox_assistant.agent import OpenAICompatBrain

    class _Resp:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {
                "choices": [{"message": {"content": "no"}}],
                "usage": {"prompt_tokens": 1_000_000, "completion_tokens": 0},
            }

    monkeypatch.setattr("httpx.post", lambda *args, **kwargs: _Resp())
    step = OpenAICompatBrain(api_key="sk-test", model="gpt-4o-mini").decide(
        [{"role": "user", "content": "hi"}], [],
    )
    assert step.final == "no"
    assert step.cost_usd == pytest.approx(0.15)


def test_handle_sums_brain_cost_into_chat_response():
    from examples.inbox_assistant.agent import BrainStep, InboxAgent, ScriptedBrain

    agent = InboxAgent(ScriptedBrain([
        BrainStep(tool_calls=[{"name": "get_calendar", "arguments": {}}], cost_usd=0.004),
        BrainStep(final="done", cost_usd=0.006),
    ]), profile="insecure")
    out = agent.handle([{"role": "user", "content": "hi"}])
    assert out["cost_usd"] == pytest.approx(0.01)


def test_parse_bad_arguments_defaults_empty():
    from examples.inbox_assistant.agent import parse_openai_response

    data = {"choices": [{"message": {"tool_calls": [
        {"function": {"name": "read_emails", "arguments": "not json"}}]}}]}
    step = parse_openai_response(data)
    assert step.tool_calls[0]["arguments"] == {}
