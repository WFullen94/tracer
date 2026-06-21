"""
InjecAgent adapter — loads test cases from arXiv 2403.02691 (Zhan et al., 2024).

InjecAgent provides 1,054 indirect-prompt-injection scenarios across two attack
categories:
- DH (Direct Harm): injection asks the agent to take a harmful action
- DS (Data Stealing): two-stage injection — read sensitive data, then exfiltrate

Each test case is a *seed*: a user instruction, the first (legitimate) tool call,
and the tool response with an injection embedded. Whether the agent acts on the
injection is determined by running a live agent. For Phase 3, this adapter
produces seed trajectories so the detector can be evaluated on an attack corpus
it has never seen during AgentDojo development.

Source: https://github.com/uiuc-kang-lab/InjecAgent
Layout: clone the repo and pass the path to its `data/` directory.
"""
from __future__ import annotations

import ast
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from tracer.types import AgentTrajectory, TaskMeta, ToolStep


class AttackCategory(str, Enum):
    DIRECT_HARM = "dh"
    DATA_STEALING = "ds"


class Setting(str, Enum):
    BASE = "base"          # no defense prompt
    ENHANCED = "enhanced"  # adds defensive system prompt; harder for attacker


@dataclass
class InjecAgentCase:
    case_id: int                    # index in source file (stable across loads)
    category: AttackCategory
    user_instruction: str
    user_tool: str
    tool_parameters: dict
    tool_response: str              # already contains the injection text
    attacker_tools: list[str]       # tool(s) the injection wants invoked
    attacker_instruction: str
    expected_achievements: str      # description of attacker's goal
    attack_type: str                # e.g. "Physical Harm", "Physical Data"


def load_cases(path: Path | str, category: AttackCategory,
               setting: Setting = Setting.BASE) -> list[InjecAgentCase]:
    """Load InjecAgent test cases from `{path}/test_cases_{category}_{setting}.json`."""
    path = Path(path)
    filename = f"test_cases_{category.value}_{setting.value}.json"
    file_path = path / filename
    if not file_path.exists():
        raise FileNotFoundError(
            f"InjecAgent data not found at {file_path}. "
            "Clone https://github.com/uiuc-kang-lab/InjecAgent and pass its data/ directory."
        )

    raw = json.loads(file_path.read_text())
    return [_parse_case(idx, entry, category) for idx, entry in enumerate(raw)]


def to_seed_trajectory(case: InjecAgentCase) -> AgentTrajectory:
    """Build a single-step trajectory containing the injected tool response.

    No agent reaction is recorded — `security=False` by convention: the injection
    is present in the trajectory, so the detector should flag it. To evaluate
    a live agent's reaction instead, use `tracer.experiments.run_injecagent`
    (Phase 6) which extends each seed with the agent's actual response.
    """
    meta = TaskMeta(
        suite="injecagent",
        user_task_id=f"{case.category.value}_{case.case_id}",
        injection_task_id=f"{case.category.value}_{case.case_id}",
        user_prompt=case.user_instruction,
        injection_goal=case.expected_achievements,
    )
    steps = [
        ToolStep(
            function=case.user_tool,
            args=case.tool_parameters,
            result=case.tool_response,
        )
    ]
    return AgentTrajectory(
        id=f"injecagent/{case.category.value}/{case.case_id}",
        meta=meta,
        steps=steps,
        utility=None,
        security=False,        # seed-by-convention: injection is present
        has_injection=True,
    )


def load_seed_trajectories(path: Path | str, category: AttackCategory,
                           setting: Setting = Setting.BASE) -> list[AgentTrajectory]:
    """Convenience: load cases and convert to seed trajectories in one call."""
    return [to_seed_trajectory(c) for c in load_cases(path, category, setting)]


def characterize(path: Path | str) -> dict:
    """Return test case counts per category × setting — no API calls."""
    result: dict = {}
    for cat in AttackCategory:
        for setting in Setting:
            try:
                cases = load_cases(path, cat, setting)
            except FileNotFoundError:
                continue
            attack_types: dict[str, int] = {}
            for c in cases:
                attack_types[c.attack_type] = attack_types.get(c.attack_type, 0) + 1
            result[f"{cat.value}_{setting.value}"] = {
                "n_cases": len(cases),
                "attack_types": attack_types,
                "unique_user_tools": len({c.user_tool for c in cases}),
                "unique_attacker_tools": len({t for c in cases for t in c.attacker_tools}),
            }
    return result


# --- parsing ------------------------------------------------------------------

def _parse_case(case_id: int, entry: dict, category: AttackCategory) -> InjecAgentCase:
    return InjecAgentCase(
        case_id=case_id,
        category=category,
        user_instruction=entry["User Instruction"],
        user_tool=entry["User Tool"],
        tool_parameters=_parse_params(entry["Tool Parameters"]),
        tool_response=entry["Tool Response"],
        attacker_tools=list(entry["Attacker Tools"]),
        attacker_instruction=entry["Attacker Instruction"],
        expected_achievements=entry["Expected Achievements"],
        attack_type=entry["Attack Type"],
    )


def _parse_params(raw: str | dict) -> dict:
    """InjecAgent stores tool parameters as Python repr strings (single-quoted)."""
    if isinstance(raw, dict):
        return raw
    return ast.literal_eval(raw)
