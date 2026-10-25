"""LLM-backed quickstart: run the scan against a real model.

    # OpenAI-compatible (the case study's path — GPT-4o-mini):
    export RFA_OPENAI_API_KEY=sk-...        # and optionally RFA_OPENAI_MODEL / RFA_OPENAI_BASE_URL
    python examples/quickstart/run_llm_scan.py

    # or Anthropic:
    export RFA_ANTHROPIC_API_KEY=sk-ant-...
    python examples/quickstart/run_llm_scan.py

Same agent and attacks as run_scan.py, but a real model makes the decisions.
The insecure scaffold may actually breach (cost-tier models do; frontier models
usually refuse) — and either way the tool-layer controls stop the secure one.
No key set? It prints how to set one and exits cleanly.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from llm_agent import AnthropicBrain, Brain, OpenAICompatBrain, make_llm_agent
from run_scan import _asr, build_attacks, build_target

from redforge_agents.adapters.local import LocalAgentAdapter
from redforge_agents.assurance import assurance_report, attribute_controls
from redforge_agents.campaign import run_campaign


def _pick_brain() -> tuple[Brain, str] | None:
    if os.getenv("RFA_OPENAI_API_KEY"):
        brain = OpenAICompatBrain()
        return brain, f"OpenAI-compatible · {brain.model}"
    if os.getenv("RFA_ANTHROPIC_API_KEY"):
        brain = AnthropicBrain()
        return brain, f"Anthropic · {brain.model}"
    return None


def main() -> int:
    picked = _pick_brain()
    if picked is None:
        print(
            "No model key set. This demo needs a real model.\n\n"
            "  export RFA_OPENAI_API_KEY=sk-...      # GPT-4o-mini or any OpenAI-compatible endpoint\n"
            "  export RFA_ANTHROPIC_API_KEY=sk-ant-...\n\n"
            "Then re-run. For the offline (no-key) version, use run_scan.py instead."
        )
        return 0

    brain, label = picked
    target, attacks = build_target(), build_attacks()

    print("=" * 68)
    print(f"RedForge Agents — LLM-backed scan · model: {label}")
    print("=" * 68)

    insecure = run_campaign(
        target, attacks, LocalAgentAdapter(agent_factory=lambda: make_llm_agent("insecure", brain))
    )
    secure = run_campaign(
        target, attacks, LocalAgentAdapter(agent_factory=lambda: make_llm_agent("secure", brain))
    )

    print(f"\n1) FIND + PROVE  — insecure agent: {len(insecure.findings)}/"
          f"{len(insecure.attempts)} breached  (ASR {_asr(insecure):.0%})")
    for f in insecure.findings:
        print(f"     • proven: {f.title}  [{f.proof.value}]")
    if not insecure.findings:
        print("     (this model refused every attack on the insecure scaffold — "
              "model choice is itself a control)")

    print("\n2) PATCH         — tool-layer controls: external-send gate + output DLP")

    ca = attribute_controls(secure)
    print(f"\n3) VERIFY        — hardened agent: {len(secure.findings)}/"
          f"{len(secure.attempts)} breached  (ASR {_asr(secure):.0%})")
    print(f"     • tool-layer blocks: {ca.tool_layer_blocks}   "
          f"model refusals: {ca.model_refusals}   breaches: {ca.breaches}")

    print("\n" + "-" * 68)
    print("Assurance report for the hardened agent:\n")
    print(assurance_report(secure))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
