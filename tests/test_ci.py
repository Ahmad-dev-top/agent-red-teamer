"""CI gating — thresholds, baseline/regression mode, summary, and exit codes."""

from __future__ import annotations

import json

from redforge_agents.ci import (
    ci_summary_markdown,
    evaluate_gate,
    load_baseline_ids,
    severity_rank,
)
from redforge_agents.schemas import (
    AttackCategory,
    Attempt,
    AttemptStatus,
    Finding,
    OwaspId,
    ProofType,
    Report,
    Severity,
)


def _finding(attack_id: str, severity: Severity) -> Finding:
    return Finding(
        attack_id=attack_id,
        category=AttackCategory.EXCESSIVE_AGENCY,
        owasp=OwaspId.LLM06,
        severity=severity,
        title=f"breach {attack_id}",
        proof=ProofType.CANARY_LEAKED,
        evidence="canary leaked",
    )


def _report(findings: list[Finding], n_attempts: int = 3) -> Report:
    attempts = [
        Attempt(attack_id=f"a{i}", target_id="t", status=AttemptStatus.FAILED)
        for i in range(n_attempts)
    ]
    return Report(target_id="t", target_name="Demo", attempts=attempts, findings=findings)


def test_severity_rank_is_ordered():
    assert severity_rank(Severity.INFO) < severity_rank(Severity.HIGH) < severity_rank(Severity.CRITICAL)


def test_no_findings_passes():
    gate = evaluate_gate(_report([]), fail_on=Severity.HIGH)
    assert gate.passed is True
    assert gate.exit_code == 0


def test_high_finding_fails_at_high_threshold():
    gate = evaluate_gate(_report([_finding("ea1", Severity.HIGH)]), fail_on=Severity.HIGH)
    assert gate.passed is False
    assert gate.exit_code == 1
    assert len(gate.failing) == 1


def test_medium_finding_below_high_threshold_passes():
    gate = evaluate_gate(_report([_finding("ea1", Severity.MEDIUM)]), fail_on=Severity.HIGH)
    assert gate.passed is True
    assert gate.failing == []


def test_critical_fails_even_at_high_threshold():
    gate = evaluate_gate(_report([_finding("ea1", Severity.CRITICAL)]), fail_on=Severity.HIGH)
    assert gate.passed is False


def test_baseline_suppresses_known_finding():
    report = _report([_finding("known", Severity.HIGH)])
    gate = evaluate_gate(report, fail_on=Severity.HIGH, baseline_ids={"known"})
    assert gate.passed is True
    assert gate.failing == []
    assert len(gate.suppressed_baseline) == 1


def test_baseline_still_fails_on_new_finding():
    report = _report([_finding("known", Severity.HIGH), _finding("newbreak", Severity.HIGH)])
    gate = evaluate_gate(report, fail_on=Severity.HIGH, baseline_ids={"known"})
    assert gate.passed is False
    assert [f.attack_id for f in gate.failing] == ["newbreak"]


def test_load_baseline_ids_roundtrip(tmp_path):
    report = _report([_finding("ea1", Severity.HIGH), _finding("ea2", Severity.LOW)])
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(report.model_dump(mode="json")), encoding="utf-8")
    assert load_baseline_ids(path) == {"ea1", "ea2"}


def test_summary_shows_pass_and_fail():
    passing = evaluate_gate(_report([]), fail_on=Severity.HIGH)
    assert "✅ PASS" in ci_summary_markdown(_report([]), passing)

    rep = _report([_finding("ea1", Severity.HIGH)])
    failing = evaluate_gate(rep, fail_on=Severity.HIGH)
    md = ci_summary_markdown(rep, failing)
    assert "❌ FAIL" in md
    assert "Gate-failing findings" in md


# --- end-to-end CLI exit codes ------------------------------------------- #
import pathlib

import redforge_agents
from redforge_agents.config import settings

_REPO = pathlib.Path(redforge_agents.__file__).resolve().parents[2]
_TARGET = _REPO / "examples" / "inbox_assistant" / "target.yaml"


def _pin_dirs(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "seeds_dir", _REPO / "seeds")
    monkeypatch.setattr(settings, "reports_dir", tmp_path)
    monkeypatch.setattr(settings, "work_dir", tmp_path / "work")


def test_cli_ci_passes_on_stub(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from redforge_agents.cli import app

    _pin_dirs(tmp_path, monkeypatch)
    result = CliRunner().invoke(
        app,
        ["ci", str(_TARGET), "--adapter", "stub", "--fail-on", "high", "--json", str(tmp_path / "ci.json")],
    )
    assert result.exit_code == 0
    assert "PASS" in result.stdout


def test_cli_ci_fails_when_report_breaches(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from redforge_agents.cli import app

    _pin_dirs(tmp_path, monkeypatch)

    # stub the campaign so a HIGH breach is present -> gate must exit 1
    def _fake_run_campaign(*a, **k):
        return _report([_finding("ea1", Severity.HIGH)])

    monkeypatch.setattr("redforge_agents.campaign.run_campaign", _fake_run_campaign)

    result = CliRunner().invoke(
        app,
        ["ci", str(_TARGET), "--adapter", "stub", "--fail-on", "high", "--json", str(tmp_path / "ci.json")],
    )
    assert result.exit_code == 1
    assert "FAIL" in result.stdout
