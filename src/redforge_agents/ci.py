"""CI gating — turn a scan into a pass/fail build check.

The retainer story in one module: run the campaign in CI and fail the build when
the agent breaches. Two modes:

- **threshold** (default): fail if any finding is at or above a severity.
- **baseline / regression**: pass a prior report; fail only on findings that are
  NEW relative to it (same attack id). This lets a team accept a known, risk-
  managed finding while still blocking any *new* break a change introduces.

Nothing here decides whether an attack succeeded — that is the deterministic
judge's job. This only grades an existing Report against a policy.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from redforge_agents.schemas import Finding, Report, Severity

_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_rank(sev: Severity) -> int:
    return _RANK[sev]


@dataclass
class GateResult:
    passed: bool
    threshold: Severity
    mode: str
    failing: list[Finding] = field(default_factory=list)
    suppressed_baseline: list[Finding] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        return 0 if self.passed else 1


def evaluate_gate(
    report: Report,
    fail_on: Severity = Severity.HIGH,
    baseline_ids: set[str] | None = None,
) -> GateResult:
    """Grade a report. With `baseline_ids`, only findings whose attack id is NOT
    in the baseline can fail the gate (regression mode)."""
    threshold = _RANK[fail_on]
    at_or_above = [f for f in report.findings if _RANK[f.severity] >= threshold]
    if baseline_ids is None:
        return GateResult(
            passed=not at_or_above,
            threshold=fail_on,
            mode="all findings",
            failing=at_or_above,
        )
    new = [f for f in at_or_above if f.attack_id not in baseline_ids]
    known = [f for f in at_or_above if f.attack_id in baseline_ids]
    return GateResult(
        passed=not new,
        threshold=fail_on,
        mode="new findings vs baseline",
        failing=new,
        suppressed_baseline=known,
    )


def load_baseline_ids(path: str | Path) -> set[str]:
    """Read a prior report JSON and return the set of finding attack ids."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {str(f["attack_id"]) for f in data.get("findings", [])}


def ci_summary_markdown(report: Report, gate: GateResult) -> str:
    """A compact markdown verdict for a PR / GitHub step summary."""
    n = len(report.attempts)
    breaches = len(report.findings)
    asr = breaches / n if n else 0.0
    verdict = "✅ PASS" if gate.passed else "❌ FAIL"

    lines = [
        f"## RedForge Agents — scan {verdict}",
        "",
        f"**Target:** {report.target_name} (`{report.target_id}`)  ",
        f"**Attacks:** {n} · **Breaches:** {breaches} · **ASR:** {asr:.0%}  ",
        f"**Gate:** fail on {gate.mode} at severity ≥ `{gate.threshold.value}`",
        "",
        "| category | attempts | breaches | ASR |",
        "|---|--:|--:|--:|",
    ]
    for s in report.scores:
        lines.append(f"| {s.category.value} | {s.attempts} | {s.successes} | {s.asr:.0%} |")

    if gate.failing:
        lines += ["", "### Gate-failing findings"]
        for f in gate.failing:
            lines.append(
                f"- **[{f.severity.value}]** {f.owasp.value} {f.title} — "
                f"`{f.proof.value}`: {f.evidence}"
            )
    if gate.suppressed_baseline:
        lines += [
            "",
            (
                f"<sub>{len(gate.suppressed_baseline)} known finding(s) in the baseline "
                "did not fail the gate.</sub>"
            ),
        ]
    if not report.findings:
        lines += ["", "_No findings._"]
    elif not gate.failing and gate.mode == "all findings":
        lines += [
            "",
            (
                f"<sub>{breaches} finding(s) present but below the `{gate.threshold.value}` "
                "threshold.</sub>"
            ),
        ]
    return "\n".join(lines)
