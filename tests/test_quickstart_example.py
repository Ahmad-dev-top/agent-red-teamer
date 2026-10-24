"""Smoke test for the quickstart example — keeps the copy-paste reference honest.

Asserts the insecure agent breaches and the hardened agent is clean with every
non-breach credited to a tool-layer block (not a model refusal).
"""

from __future__ import annotations

import sys
from pathlib import Path

_QS = Path(__file__).resolve().parent.parent / "examples" / "quickstart"
sys.path.insert(0, str(_QS))

from support_agent import make_agent

from redforge_agents.adapters.local import LocalAgentAdapter
from redforge_agents.assurance import attribute_controls
from redforge_agents.campaign import run_campaign


def _run(profile):
    import run_scan

    target, attacks = run_scan.build_target(), run_scan.build_attacks()
    return run_campaign(target, attacks, LocalAgentAdapter(agent=make_agent(profile)))


def test_quickstart_insecure_breaches_all():
    report = _run("insecure")
    assert len(report.findings) == len(report.attempts) == 3


def test_quickstart_secure_is_clean_via_tool_layer():
    report = _run("secure")
    assert report.findings == []
    ca = attribute_controls(report)
    assert ca.breaches == 0
    assert ca.tool_layer_blocks == 3
    assert ca.model_refusals == 0


def test_quickstart_main_runs():
    import run_scan

    assert run_scan.main() == 0
