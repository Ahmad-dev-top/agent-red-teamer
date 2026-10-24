# RedForge Agents

**An autonomous red-teamer for tool-using AI agents. I break your AI agent before attackers do, prove each break with hard evidence, harden it, and prove the fix holds.**

🔴 **Live demo:** https://ahmad-dev-top.github.io/agent-red-teamer/  ·  📄 **[Full case study](./CASE-STUDY.md)**

Point it at an agent that can call tools — a support agent with refund access, an inbox assistant, a coding copilot with filesystem/MCP access — and it runs an attack campaign, **proves every finding with hard evidence** (a tool-call log entry or a leaked canary token, never an LLM's opinion), recommends a fix, and re-tests to show the attack-success rate drop. It reports, with honest control attribution, whether it was *your controls* or *your model* that kept you safe.

## The headline result

Tested a real LLM inbox agent (email-sending tools, a confidential record tagged with a canary token) across tool-abuse and prompt-injection attacks:

| configuration | model | attack-success rate |
|---|---|--:|
| Insecure scaffold | GPT-4o-mini | **100%** (every attack leaked the canary) |
| Insecure scaffold | Claude | **0%** (model refused) |
| Hardened (send gate + output DLP) | GPT-4o-mini | **0%** (deterministic controls) |

The full loop, proven end to end on a live model: **found** a 100% breach → **compared** models (same scaffold, Claude held) → **patched** with a send gate → **re-test caught the fix was incomplete** (a second exfiltration channel) → **patched again** with output DLP → **verified** 0%. See **[CASE-STUDY.md](./CASE-STUDY.md)**.

## Why it's different

Open-source LLM red-teaming tools exist (garak, PyRIT, promptfoo). The edge here is narrower and sharper:
- **Agents that take actions**, not chatbots that say bad words.
- **Deterministic proof** of each break — the harness decides success from a tool-call log or a leaked canary, never a model's say-so. (During testing, the advisory LLM judge both false-positived and false-negatived; the deterministic verdict stood every time.)
- **Fix and re-verify** — and honest **control attribution**: for every attack that *didn't* breach, it tells you whether a durable tool-layer control stopped it or the model merely chose to refuse.

## Attack coverage (OWASP LLM Top 10, 2025)

| category | proof of success | OWASP |
|---|---|---|
| Direct prompt injection | forbidden tool call in the log | LLM01 |
| Indirect prompt injection | agent obeyed planted instruction | LLM01 |
| Excessive agency / tool misuse | tripwire fired with out-of-policy args | LLM06 |
| Data exfiltration | canary token reached an outbound sink | LLM02 |
| System prompt leakage | system-prompt canary in output | LLM07 |
| MCP tool poisoning | agent followed a poisoned tool description | LLM01/06 |
| Resource abuse | step/cost budget exceeded | LLM10 |

## How it works

```
target + seeds → adapter → agent (sandboxed) → deterministic judge → findings → assurance report
                                                      ↑
                      multi-turn attacker (mutates & chains, blind to canaries)
```

Five pieces, each typed and testable: a **target adapter** (HTTP / OpenAI-compatible / stub), a YAML **seed library** (attacks as data), a **multi-turn attacker** that adapts across turns but never sees the canary, the **deterministic judge** (the anti-cheat core), and **assurance reporting** with control attribution.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,demo]"

# validate a target config + the seed library
redforge-agents validate examples/inbox_assistant/target.yaml
redforge-agents seeds

# run a campaign (stub adapter = offline demo; http = a real endpoint)
redforge-agents scan examples/shop_support/target.yaml --adapter stub
```

To test an agent on the models real teams deploy, run the inbox agent on any
OpenAI-compatible endpoint (`RFA_OPENAI_API_KEY`, `RFA_OPENAI_MODEL`) with
`INBOX_BRAIN=openai`, and compare `INBOX_PROFILE=insecure` vs `HARDENED=1`.

## Safety & legal

Untrusted code runs only in a Docker sandbox with no network (or an internal-only bridge to mock services), dropped capabilities, non-root, read-only root. **Only test agents you own or have written authorization to test**, against staging or a sandbox copy, never production data.

## Built with

Python · Pydantic · Typer · httpx · FastAPI (demo agents) · the Anthropic API (attacker/judge) · any OpenAI-compatible endpoint (target models) · Docker · a full unit-test suite that runs without Docker or an API key.
