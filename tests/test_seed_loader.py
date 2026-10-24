"""Seed loader: valid seeds parse, the shipped library loads, bad seeds fail loud,
duplicate ids are rejected."""

import pytest

from redforge_agents.schemas import AttackCategory, ProofType
from redforge_agents.seeds import load_seed_file, load_seeds

SHIPPED_SEEDS = "seeds"  # run from repo root


def test_shipped_library_loads():
    atks = load_seeds(SHIPPED_SEEDS)
    assert len(atks) >= 100
    # every one of the seven categories is represented, with real coverage in each
    cats = {a.category for a in atks}
    assert cats == set(AttackCategory)
    assert all(sum(a.category == cat for a in atks) >= 10 for cat in AttackCategory)
    # every seed carries a concrete proof condition and at least one turn
    assert all(isinstance(a.success.proof, ProofType) for a in atks)
    assert all(a.turns for a in atks)


def test_single_file_parses(tmp_path):
    f = tmp_path / "x.yaml"
    f.write_text(
        "id: s1\ncategory: direct_prompt_injection\nowasp: LLM01\ntitle: t\n"
        "turns: ['hi']\nsuccess:\n  proof: forbidden_tool_call\n  tool: delete_account\n"
    )
    atks = load_seed_file(f)
    assert len(atks) == 1 and atks[0].id == "s1"


def test_bad_seed_raises(tmp_path):
    f = tmp_path / "bad.yaml"
    f.write_text("id: s1\ncategory: not_a_category\nowasp: LLM01\ntitle: t\n"
                 "success:\n  proof: forbidden_tool_call\n")
    with pytest.raises(ValueError):
        load_seed_file(f)


def test_duplicate_ids_rejected(tmp_path):
    (tmp_path / "a.yaml").write_text(
        "id: dup\ncategory: direct_prompt_injection\nowasp: LLM01\ntitle: t\n"
        "success:\n  proof: budget_exceeded\n"
    )
    (tmp_path / "b.yaml").write_text(
        "id: dup\ncategory: resource_abuse\nowasp: LLM10\ntitle: t\n"
        "success:\n  proof: budget_exceeded\n"
    )
    with pytest.raises(ValueError, match="duplicate"):
        load_seeds(tmp_path)
