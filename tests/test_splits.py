from __future__ import annotations

from tracer.benchmark.splits import (
    Split,
    split_agentdojo_by_injection,
    split_by_key,
    split_injecagent_by_attack_type,
)
from tracer.injecagent.adapter import AttackCategory, InjecAgentCase
from tracer.types import AgentTrajectory, TaskMeta


def _traj(suite: str, user_id: str, inj_id: str | None) -> AgentTrajectory:
    meta = TaskMeta(
        suite=suite,
        user_task_id=user_id,
        injection_task_id=inj_id,
        user_prompt="x",
        injection_goal="y" if inj_id else None,
    )
    return AgentTrajectory(
        id=f"{suite}/{user_id}" + (f"/{inj_id}" if inj_id else ""),
        meta=meta, steps=[], utility=True,
        security=False if inj_id else None,
        has_injection=bool(inj_id),
    )


def _case(case_id: int, attack_type: str) -> InjecAgentCase:
    return InjecAgentCase(
        case_id=case_id,
        category=AttackCategory.DIRECT_HARM,
        user_instruction="x", user_tool="T", tool_parameters={},
        tool_response="r", attacker_tools=["AT"],
        attacker_instruction="i", expected_achievements="e",
        attack_type=attack_type,
    )


# --- generic split_by_key -----------------------------------------------------

def test_split_by_key_partitions():
    items = ["a", "b", "c", "d"]
    split = split_by_key(items, held_out_keys={"b", "d"}, key_fn=lambda x: x)
    assert split.train == ["a", "c"]
    assert split.held_out == ["b", "d"]


def test_split_by_key_empty_heldout():
    items = [1, 2, 3]
    split = split_by_key(items, held_out_keys=set(), key_fn=lambda x: x)
    assert split.train == [1, 2, 3]
    assert split.held_out == []


def test_split_len():
    s = Split(train=[1, 2], held_out=[3])
    assert len(s) == 3


# --- AgentDojo split ----------------------------------------------------------

def test_agentdojo_split_holds_out_injection_id():
    trajs = [
        _traj("workspace", "ut0", "injection_task_0"),
        _traj("workspace", "ut0", "injection_task_1"),
        _traj("workspace", "ut1", "injection_task_5"),
    ]
    split = split_agentdojo_by_injection(trajs, held_out_injection_ids={"injection_task_5"})
    assert len(split.train) == 2
    assert len(split.held_out) == 1
    assert split.held_out[0].meta.injection_task_id == "injection_task_5"


def test_agentdojo_benign_always_in_train():
    trajs = [
        _traj("workspace", "ut0", None),
        _traj("workspace", "ut0", "injection_task_0"),
    ]
    split = split_agentdojo_by_injection(trajs, held_out_injection_ids={"injection_task_0"})
    # benign should never leak into held_out
    assert all(t.meta.injection_task_id is not None for t in split.held_out)
    assert any(t.meta.injection_task_id is None for t in split.train)


def test_agentdojo_no_heldout_returns_all_in_train():
    trajs = [_traj("workspace", "ut0", "injection_task_0")]
    split = split_agentdojo_by_injection(trajs, held_out_injection_ids=set())
    assert len(split.train) == 1
    assert split.held_out == []


# --- InjecAgent split ---------------------------------------------------------

def test_injecagent_split_by_attack_type():
    cases = [
        _case(0, "Physical Harm"),
        _case(1, "Financial Harm"),
        _case(2, "Data Security Harm"),
        _case(3, "Physical Harm"),
    ]
    split = split_injecagent_by_attack_type(cases, held_out_attack_types={"Data Security Harm"})
    assert len(split.train) == 3
    assert len(split.held_out) == 1
    assert split.held_out[0].attack_type == "Data Security Harm"


def test_injecagent_multiple_heldout_types():
    cases = [_case(i, t) for i, t in enumerate(["A", "B", "C", "A", "B"])]
    split = split_injecagent_by_attack_type(cases, held_out_attack_types={"A", "C"})
    assert len(split.train) == 2  # the two "B"s
    assert len(split.held_out) == 3  # 2x A + 1x C


# --- disjointness invariant ---------------------------------------------------

def test_split_is_disjoint():
    items = list(range(10))
    split = split_by_key(items, held_out_keys={3, 7}, key_fn=lambda x: x)
    assert set(split.train).isdisjoint(set(split.held_out))
    assert set(split.train) | set(split.held_out) == set(items)
