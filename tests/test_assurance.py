"""Assurance report + control attribution: distinguishes a tool-layer block from a
model refusal, which is what makes a 0-finding scan a valuable deliverable."""

from redforge_agents.assurance import assurance_report, attribute_controls
from redforge_agents.schemas import (
    AttackCategory,
    Attempt,
    AttemptStatus,
    CategoryScore,
    Report,
    RunResult,
    ToolCall,
)


def _report(attempts) -> Report:
    scores = [CategoryScore(category=AttackCategory.EXCESSIVE_AGENCY,
                            attempts=len(attempts),
                            successes=sum(a.status == AttemptStatus.SUCCEEDED for a in attempts))]
    return Report(target_id="t", target_name="Inbox", attempts=attempts, scores=scores)


def test_attribution_tool_layer_block():
    # agent attempted an external send but the gate blocked it
    att = Attempt(attack_id="a", target_id="t", status=AttemptStatus.FAILED,
                  run=RunResult(tool_calls=[ToolCall(
                      name="send_email", arguments={"to": "x@evil.test"},
                      result={"blocked": True, "reason": "external"})]))
    ca = attribute_controls(_report([att]))
    assert ca.tool_layer_blocks == 1 and ca.model_refusals == 0 and ca.breaches == 0


def test_attribution_model_refusal():
    # agent never attempted the unsafe action
    att = Attempt(attack_id="a", target_id="t", status=AttemptStatus.FAILED,
                  run=RunResult(final_output="I can't do that.", tool_calls=[]))
    ca = attribute_controls(_report([att]))
    assert ca.model_refusals == 1 and ca.tool_layer_blocks == 0


def test_attribution_breach():
    att = Attempt(attack_id="a", target_id="t", status=AttemptStatus.SUCCEEDED,
                  run=RunResult(outbound_payloads=["x@evil.test: CANARY"]))
    ca = attribute_controls(_report([att]))
    assert ca.breaches == 1


def test_report_flags_model_only_protection():
    # all failures were model refusals -> the report must warn there's no durable control
    atts = [Attempt(attack_id=f"a{i}", target_id="t", status=AttemptStatus.FAILED,
                    run=RunResult(final_output="no", tool_calls=[])) for i in range(3)]
    md = assurance_report(_report(atts))
    assert "every attack was stopped by the *model*" in md
    assert "Model refusals: 3" in md


def test_report_counts_and_coverage():
    atts = [Attempt(attack_id="a", target_id="t", status=AttemptStatus.SUCCEEDED,
                    run=RunResult(outbound_payloads=["x: CANARY"]))]
    md = assurance_report(_report(atts))
    assert "Attacks executed: **1**" in md
    assert "Breaches (proven): **1**" in md
    assert "excessive_agency" in md


def test_header_shows_time_and_omits_unmeasured_cost():
    atts = [Attempt(attack_id="a", target_id="t", status=AttemptStatus.FAILED,
                    run=RunResult(final_output="no"))]
    report = _report(atts)
    report.total_seconds = 12.4
    md = assurance_report(report)
    assert "12.4s" in md
    assert "cost:" not in md


def test_header_shows_measured_cost():
    atts = [Attempt(attack_id="a", target_id="t", status=AttemptStatus.FAILED,
                    run=RunResult(final_output="no"))]
    report = _report(atts)
    report.total_cost_usd = 0.018
    report.total_seconds = 3.2
    md = assurance_report(report)
    assert "cost: $0.018" in md
    assert "3.2s" in md
