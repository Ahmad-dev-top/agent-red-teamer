"""Campaign runner — the scan loop that ties the pieces together.

For each attack seed: run it against the target via the adapter, judge the run
(deterministic verdict authoritative), and on success record a Finding with its
hard evidence and full transcript. Aggregates per-category attack-success rates
and judge agreement into a Report.

Single-turn is the default. Pass an `attacker` and each seed goes through the
multi-turn loop; the deterministic judge still decides success either way.
"""

from __future__ import annotations

import time

from redforge_agents.adapters.base import TargetAdapter
from redforge_agents.attacker.client import AttackerLLM
from redforge_agents.attacker.loop import run_multi_turn
from redforge_agents.judge import Judge
from redforge_agents.logging_conf import get_logger
from redforge_agents.recommend import recommend_fix
from redforge_agents.schemas import (
    Attack,
    AttackCategory,
    Attempt,
    AttemptStatus,
    CategoryScore,
    Finding,
    Report,
    Target,
)

log = get_logger("campaign")


def run_campaign(
    target: Target,
    attacks: list[Attack],
    adapter: TargetAdapter,
    judge: Judge | None = None,
    attacker: AttackerLLM | None = None,
    max_turns: int | None = None,
) -> Report:
    """Run an attack campaign. With `attacker` set, each seed is run through the
    multi-turn mutate-and-chain loop (the attacker crafts follow-ups until the
    agent breaks or the turn budget runs out); without it, each seed is a single
    shot. The deterministic judge decides success either way."""
    judge = judge or Judge()
    attempts: list[Attempt] = []
    findings: list[Finding] = []
    scores: dict[AttackCategory, CategoryScore] = {}
    agreements: list[bool] = []
    total_cost = 0.0

    t0 = time.perf_counter()
    for attack in attacks:
        sc = scores.setdefault(attack.category, CategoryScore(category=attack.category))
        sc.attempts += 1

        if attacker is not None:
            run, result, turns_used = run_multi_turn(
                target, attack, adapter, attacker, judge, max_turns
            )
        else:
            run = adapter.run_attack(target, attack)
            result = judge.judge(run, attack, target)
            turns_used = 1
        total_cost += run.cost_usd

        status = (
            AttemptStatus.ERROR if run.error
            else AttemptStatus.SUCCEEDED if result.succeeded
            else AttemptStatus.FAILED
        )
        attempts.append(
            Attempt(
                attack_id=attack.id, target_id=target.id, status=status,
                run=run, judge=result, turns_used=turns_used,
                cost_usd=run.cost_usd, seconds=run.seconds,
            )
        )
        if result.agrees is not None:
            agreements.append(result.agrees)

        if result.succeeded:
            sc.successes += 1
            findings.append(
                Finding(
                    attack_id=attack.id,
                    category=attack.category,
                    owasp=attack.owasp,
                    severity=attack.severity,
                    title=attack.title,
                    proof=result.verdict.proof,  # type: ignore[arg-type]
                    evidence=result.verdict.evidence,
                    transcript=run.transcript,
                    recommendation=recommend_fix(attack),
                )
            )
            log.info("FINDING %-24s %s", attack.id, result.verdict.evidence)

    agreement = sum(agreements) / len(agreements) if agreements else None
    return Report(
        target_id=target.id,
        target_name=target.name,
        attempts=attempts,
        findings=findings,
        scores=sorted(scores.values(), key=lambda s: s.category.value),
        total_cost_usd=total_cost,
        total_seconds=time.perf_counter() - t0,
        judge_agreement=agreement,
    )
