"""Fix recommendations per attack category.

Baseline, category-level guidance so every finding ships with a concrete next
step. The LLM-tailored, code-specific recommendation (Week 5) layers on top of
these; keeping a deterministic baseline means a report is never empty-handed.
"""

from __future__ import annotations

from redforge_agents.schemas import Attack, AttackCategory

_FIXES: dict[AttackCategory, str] = {
    AttackCategory.DIRECT_INJECTION: (
        "Separate instructions from data: keep the system prompt privileged and treat all "
        "user content as untrusted. Gate high-impact tools behind an allowlist and an "
        "out-of-band confirmation that user text cannot satisfy."
    ),
    AttackCategory.INDIRECT_INJECTION: (
        "Treat tool-returned content (web pages, emails, docs) as untrusted data, never as "
        "instructions. Strip/neutralize instruction-like text before it reaches the model, and "
        "require explicit user confirmation before acting on content fetched by a tool."
    ),
    AttackCategory.EXCESSIVE_AGENCY: (
        "Enforce authorization in the tool layer, not the prompt. Add policy checks and limits "
        "(amount caps, role checks, idempotency) on state-changing tools, and require a human "
        "approval step for irreversible actions."
    ),
    AttackCategory.DATA_EXFILTRATION: (
        "Prevent outbound exfiltration: disallow model-authored URLs/markdown images to arbitrary "
        "hosts, allowlist outbound destinations, and redact secrets before they can enter any "
        "tool argument or output."
    ),
    AttackCategory.SYSTEM_PROMPT_LEAKAGE: (
        "Assume the system prompt is public — never put secrets in it. Move credentials and keys "
        "to the tool layer, and refuse requests to reveal system instructions."
    ),
    AttackCategory.MCP_TOOL_POISONING: (
        "Pin and verify MCP tool definitions: hash tool descriptions, reject changes after "
        "approval, and sandbox each server. Don't let a tool's description carry instructions the "
        "model will follow."
    ),
    AttackCategory.RESOURCE_ABUSE: (
        "Bound consumption: hard per-session step and token budgets, per-tool rate limits, and a "
        "loop/recursion detector that halts runaway tool-calling."
    ),
}


def recommend_fix(attack: Attack) -> str:
    return _FIXES.get(attack.category, "Review the transcript and add a policy check at the tool layer.")
