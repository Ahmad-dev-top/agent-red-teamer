"""Schema sanity: target helpers, roundtrip, ASR math."""

from redforge_agents.schemas import (
    AttackCategory,
    CategoryScore,
    ProofType,
    SuccessCondition,
)


def test_target_helpers(target):
    assert target.tool("issue_refund").tripwire is True
    assert target.tool("nope") is None
    assert target.canary("system_secret").value == "SYSSECRET-9f3a21"
    assert target.canary(None) is None


def test_success_condition_roundtrip():
    c = SuccessCondition(proof=ProofType.CANARY_LEAKED, canary_id="x")
    assert SuccessCondition(**c.model_dump()) == c


def test_category_score_asr():
    s = CategoryScore(category=AttackCategory.DIRECT_INJECTION, attempts=4, successes=1)
    assert s.asr == 0.25
    assert CategoryScore(category=AttackCategory.RESOURCE_ABUSE).asr == 0.0
