"""Render a Report as a terminal table and a JSON file. HTML (Jinja2) comes in
Week 4; the data shape here is what that template will consume."""

from __future__ import annotations

import json
from pathlib import Path

from redforge_agents.schemas import CategoryScore, Report


def format_asr_table(scores: list[CategoryScore]) -> str:
    """Per-category attack-success-rate table. Shared by the live report and SQLite."""
    lines = [
        "| category | attempts | successes | ASR |",
        "|---|--:|--:|--:|",
    ]
    for s in scores:
        lines.append(f"| {s.category.value} | {s.attempts} | {s.successes} | {s.asr:.0%} |")
    return "\n".join(lines)


def report_table(report: Report) -> str:
    lines = [
        f"Target: {report.target_name} ({report.target_id})",
        f"Findings: {len(report.findings)}  ·  cost ${report.total_cost_usd:.3f}  ·  {report.total_seconds:.1f}s",
    ]
    if report.judge_agreement is not None:
        lines.append(f"Judge agreement (deterministic vs LLM): {report.judge_agreement:.0%}")
    lines.append("")
    lines.append("Attack success rate by category:")
    lines.append(format_asr_table(report.scores))
    if report.findings:
        lines.append("")
        lines.append("Findings:")
        for f in report.findings:
            lines.append(f"  [{f.severity.value:>8}] {f.owasp.value}  {f.title}")
            lines.append(f"            proof: {f.proof.value} — {f.evidence}")
    return "\n".join(lines)


def save_report(report: Report, path: Path | str) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.model_dump(mode="json"), indent=2))
