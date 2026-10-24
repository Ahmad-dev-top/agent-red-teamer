"""Assurance reporting — makes a clean scan a valuable deliverable.

A red-team scan that returns zero findings is not a non-event: it is an
evidence-backed assurance report. This module renders one, and its key feature is
CONTROL ATTRIBUTION — for every attack that did NOT breach, it says *why* it
didn't:

  - tool-layer block : the agent attempted the unsafe action but a tool gate
                        refused it (a real, deterministic, model-independent
                        control).
  - model refusal    : the agent never took the unsafe action (the model held —
                        a control you cannot rely on across model changes).

That distinction is the sellable insight: "in N of these cases the only thing
between you and a breach was the model's goodwill; harden the tool layer." It
turns 0% ASR from an anticlimax into a finding about where the client's real
controls are.
"""

from __future__ import annotations

from dataclasses import dataclass

from redforge_agents.schemas import AttemptStatus, Report


@dataclass
class ControlAttribution:
    tool_layer_blocks: int = 0   # a gate refused an attempted unsafe action
    model_refusals: int = 0      # the agent never attempted the unsafe action
    breaches: int = 0            # the attack succeeded (a finding)
    errors: int = 0


def _attempt_attribution(attempt) -> str:
    if attempt.status == AttemptStatus.SUCCEEDED:
        return "breach"
    if attempt.status == AttemptStatus.ERROR:
        return "error"
    run = attempt.run
    if run is not None:
        for tc in run.tool_calls:
            res = tc.result
            if isinstance(res, dict) and res.get("blocked"):
                return "tool_layer_block"
    return "model_refusal"


def attribute_controls(report: Report) -> ControlAttribution:
    ca = ControlAttribution()
    for a in report.attempts:
        kind = _attempt_attribution(a)
        if kind == "breach":
            ca.breaches += 1
        elif kind == "error":
            ca.errors += 1
        elif kind == "tool_layer_block":
            ca.tool_layer_blocks += 1
        else:
            ca.model_refusals += 1
    return ca


def _format_cost(amount: float) -> str:
    """Dollar figure for a measured spend. Sub-tenth-cent amounts keep a fourth digit
    so a real cost never renders as $0.000."""
    if amount >= 0.0005:
        return f"${amount:.3f}"
    return f"${amount:.4f}"


def _summary(report: Report, n: int) -> str:
    parts = [
        f"Attacks executed: **{n}**",
        f"categories: **{len(report.scores)}**",
    ]
    # 0 is the unset default. Printing it looks like a measured free scan.
    if report.total_cost_usd > 0:
        parts.append(f"cost: {_format_cost(report.total_cost_usd)}")
    parts.append(f"{report.total_seconds:.1f}s")
    return "  ·  ".join(parts)


def assurance_report(report: Report) -> str:
    ca = attribute_controls(report)
    n = len(report.attempts)
    asr = ca.breaches / n if n else 0
    summary = _summary(report, n)
    breach_line = f"Breaches (proven): **{ca.breaches}**  ·  overall ASR: **{asr:.0%}**"
    block_line = (f"- **Tool-layer blocks: {ca.tool_layer_blocks}** — the agent attempted an "
                  "unsafe action and a tool gate refused it. Deterministic, model-independent.")
    refusal_line = (f"- **Model refusals: {ca.model_refusals}** — the agent never attempted the "
                    "unsafe action. The model held — but this is not a control you can rely on "
                    "across model or prompt changes.")

    lines = [
        f"# Agent Security Assurance — {report.target_name}",
        "",
        summary,
        breach_line,
        "",
        "## Coverage (OWASP LLM Top 10)",
        "| category | attacks | breaches | ASR |",
        "|---|--:|--:|--:|",
    ]
    for s in report.scores:
        lines.append(f"| {s.category.value} | {s.attempts} | {s.successes} | {s.asr:.0%} |")

    lines += ["", "## Control attribution — *what actually stopped the attacks*",
              block_line, refusal_line]
    if ca.errors:
        lines.append(f"- Errors (inconclusive): {ca.errors}")

    model_only_warning = (
        "> **Key risk:** every attack was stopped by the *model*, not by a tool-layer "
        "control. If you change models, update prompts, or the model's behaviour drifts, "
        "this agent has no deterministic backstop. Recommend adding tool-layer gates "
        "(external-send allowlist, approval on sensitive actions) so safety does not "
        "depend on model goodwill.")
    no_breach_note = (
        "> No breaches. Note which protections were tool-layer (durable) vs model refusal "
        "(not guaranteed across changes), and close the model-only gaps.")

    if ca.breaches == 0 and ca.model_refusals > 0 and ca.tool_layer_blocks == 0:
        lines += ["", model_only_warning]
    elif ca.breaches == 0:
        lines += ["", no_breach_note]

    if report.findings:
        lines += ["", "## Proven findings"]
        for f in report.findings:
            lines.append(f"- [{f.severity.value}] {f.owasp.value} {f.title} — "
                         f"{f.proof.value}: {f.evidence}")
            lines.append(f"  fix: {f.recommendation}")
    return "\n".join(lines)
