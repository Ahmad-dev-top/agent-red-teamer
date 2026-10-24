# RedForge Agents

**An autonomous red-teamer for tool-using AI agents. I break your AI agent before attackers do, prove each break, harden it, and prove the fix holds.**

See [CASE-STUDY.md](CASE-STUDY.md) for the full red-team write-up.

Point it at an agent that can call tools — a support agent with refund access, an inbox assistant, a coding copilot with filesystem/MCP access — and it runs an attack campaign, **proves every finding with hard evidence** (a tool-call log entry or a leaked canary token, never an LLM's opinion), recommends a fix, and re-tests to show the attack-success rate drop. It's RedForge's find → prove → patch → verify loop, pointed at AI agents instead of smart contracts.

```
target.yaml → seed library → adapter → target agent (sandboxed)
                                 ↓
                          deterministic judge  ← the anti-cheat core
                                 ↓
                   findings (proof + transcript + fix) → report (ASR before/after)
```

## Why it's different

Open-source LLM red-teaming tools exist (garak, PyRIT, promptfoo). The edge here is narrower and sharper:
- **Agents that take actions**, not chatbots that say bad words.
- **Deterministic proof** of each break — the harness decides success from a tool-call log or a leaked canary, never a model's say-so.
- **Fix and re-verify**, delivered as a service, not a tool the client must run and interpret.

## Attack coverage (mapped to OWASP LLM Top 10, 2025)

| Category | Proof of success | OWASP |
|---|---|---|
| Direct prompt injection | forbidden tool call in the log | LLM01 |
| Indirect prompt injection | agent obeyed planted instruction | LLM01 |
| Excessive agency / tool misuse | tripwire fired with out-of-policy args | LLM06 |
| Data exfiltration | canary token reached an outbound sink | LLM02 |
| System prompt leakage | system-prompt canary in output | LLM07 |
| MCP tool poisoning | agent followed a poisoned tool description | LLM01/06 |
| Resource abuse | step/cost budget exceeded | LLM10 |

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# validate a target config + the seed library
redforge-agents validate examples/shop_support/target.yaml
redforge-agents seeds

# run the campaign (stub adapter = offline demo; http = a real endpoint)
redforge-agents scan examples/shop_support/target.yaml --adapter stub
```

## Status

Week-1 foundation is complete: typed contracts, the deterministic judge (every proof type tested vulnerable-flags / safe-passes), the target-adapter protocol + HTTP and stub adapters, the YAML seed library across all seven categories, the campaign runner with per-category ASR and fix recommendations, the hardened Docker sandbox, the CLI, **and a live deliberately-vulnerable demo agent** (`examples/shop_support/`) the scanner runs against end to end — it falls to all seven categories with 8 evidence-backed findings, and its hardened variant drops the attack-success rate to zero. The 6-week plan is in **[CURSOR.md](./CURSOR.md)**.

## Safety & legal

Untrusted code (the target agent and its mocked tools) runs only in a Docker sandbox with no network by default, or an internal-only bridge to mock services — never the public internet, so exfiltration attempts fail to connect yet still leave evidence. **Only test agents you own or have written authorization to test**, against staging or a sandbox copy, never production data.
