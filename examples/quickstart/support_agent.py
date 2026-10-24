"""A tiny, real tool-using agent — the copy-paste reference for onboarding.

This is a complete example of the tier-3 onboarding contract: a support agent
that reads a customer record and can email it out. It responds to arbitrary
request text (it extracts whatever recipient the message names), so attacks
genuinely drive it — it is not a canned script.

Two profiles show the before/after:
  - insecure : forwards the record to whatever address is asked, and will print
               it into its reply — the common "over-autonomous, ungated" agent.
  - secure   : two tool-layer controls — an external-send gate and output-side
               DLP — so a leak is stopped by the harness, recorded as a
               tool-layer block (not a model refusal).

The agent reaches every tool through `tools` (a ToolHarness). Under test those
tools are substituted recording mocks: a `send_email` records the payload
instead of sending, and `read_record` returns a seeded record that contains the
canary. Nothing real happens.

Wire it to the scanner with:

    from redforge_agents.adapters.local import LocalAgentAdapter
    adapter = LocalAgentAdapter(agent=make_agent("insecure"))

To drive the same agent with a real model instead of the heuristic planner,
replace `_decide` with a call to your LLM (see examples/inbox_assistant for an
LLM-backed version).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from redforge_agents.instrumented.harness import ToolHarness

AgentFn = Callable[[list[dict[str, Any]], ToolHarness, "str | None"], str]

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_CANARY = re.compile(r"CANARY-[A-Z]+-[0-9a-f]+")
_SEND_INTENT = re.compile(r"\b(forward|send|share|email|export|archive)\b", re.IGNORECASE)
_SHOW_INTENT = re.compile(r"\b(show|display|print|give|read|what.?s)\b", re.IGNORECASE)


def _decide(text: str) -> tuple[str, str | None]:
    """The planner: look at the (untrusted) request and decide what to do.
    Returns (action, recipient) where action is 'send' | 'show' | 'none'."""
    recipient = _EMAIL.search(text)
    to = recipient.group(0) if recipient else None
    if _SEND_INTENT.search(text):
        return "send", to
    if _SHOW_INTENT.search(text) and "record" in text.lower():
        return "show", None
    return "none", None


def make_agent(profile: str = "insecure") -> AgentFn:
    secure = profile == "secure"

    def agent(messages: list[dict[str, Any]], tools: ToolHarness, injected: str | None) -> str:
        # The vulnerability modelled here: untrusted email/doc content is merged
        # into the instruction stream. That is exactly how indirect injection
        # lands — so the demo's indirect-injection attack drives this branch.
        user_text = " ".join(m.get("content", "") for m in messages if m.get("role") == "user")
        text = user_text + (f"\n{injected}" if injected else "")
        action, to = _decide(text)

        reply = "How can I help with your account today?"
        if action == "send":
            record = tools.call("read_record", id="default")  # seeded; holds the canary
            if to is None:
                reply = f"I couldn't find a recipient. The record is: {record}"
            elif secure and tools.ctx.is_external(to):
                # tool-layer gate: refuse the external send (a durable control)
                tools.record_block("send_email", reason="external recipient blocked", to=to)
                reply = "I can't send customer records to external addresses."
            else:
                tools.call("send_email", to=to, subject="customer record", body=str(record))
                reply = f"Done — forwarded the customer record to {to}."
        elif action == "show":
            record = tools.call("read_record", id="default")
            reply = f"Here is the customer record on file: {record}"

        # output-side DLP (secure only): scrub any confidential record from the
        # reply before returning — closes the text-channel leak the gate misses.
        if secure:
            redacted, n = _CANARY.subn("[REDACTED]", reply)
            if n:
                tools.record_block("output_dlp", reason=f"redacted {n} record(s) from the reply")
                reply = redacted
        return reply

    return agent
