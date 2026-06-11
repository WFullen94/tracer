from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from tracer.types import AgentTrajectory, TaskMeta, ToolStep

if TYPE_CHECKING:
    from agentdojo.base_tasks import BaseInjectionTask, BaseUserTask
    from agentdojo.types import ChatMessage

BENCHMARK_VERSION = "v1"

# Suites available in AgentDojo v1 and their injection task families.
# Used for characterization and held-out split design (Phase 3).
SUITE_NAMES = ("workspace", "travel", "banking", "slack")


def from_messages(
    messages: list[ChatMessage],
    meta: TaskMeta,
    utility: bool,
    security: bool | None,
    has_injection: bool,
) -> AgentTrajectory:
    """Convert an AgentDojo message list into an AgentTrajectory.

    Tool steps are extracted by pairing AssistantMessage tool_calls with the
    following ToolResultMessages. is_injected defaults False on all steps —
    Phase 5 (provenance tracker) will populate it from taint labels.
    """
    steps: list[ToolStep] = []
    raw = [dict(m) for m in messages]

    pending_calls: dict[str | None, tuple[str, dict]] = {}

    for msg in messages:
        role = msg.get("role")
        if role == "assistant":
            for tc in (msg.get("tool_calls") or []):
                pending_calls[tc.id] = (tc.function, dict(tc.args))
        elif role == "tool":
            tc = msg["tool_call"]
            fn, args = pending_calls.pop(tc.id, (tc.function, dict(tc.args)))
            content_blocks = msg.get("content") or []
            result_text = "\n".join(
                b.get("content", "") for b in content_blocks if b.get("content")
            )
            steps.append(ToolStep(function=fn, args=args, result=result_text))

    traj_id = (
        f"{meta.suite}/{meta.user_task_id}/{meta.injection_task_id}"
        if meta.injection_task_id
        else f"{meta.suite}/{meta.user_task_id}"
    )
    return AgentTrajectory(
        id=traj_id,
        meta=meta,
        steps=steps,
        utility=utility,
        security=security,
        has_injection=has_injection,
        raw_messages=raw,
    )


def from_agentdojo_run(
    suite_name: str,
    user_task: BaseUserTask,
    injection_task: BaseInjectionTask | None,
    messages: list[ChatMessage],
    utility: bool,
    security: bool,
) -> AgentTrajectory:
    """Convenience wrapper for converting a live AgentDojo task run."""
    meta = TaskMeta(
        suite=suite_name,
        user_task_id=user_task.ID,
        injection_task_id=injection_task.ID if injection_task else None,
        user_prompt=user_task.PROMPT,
        injection_goal=injection_task.GOAL if injection_task else None,
    )
    return from_messages(
        messages=messages,
        meta=meta,
        utility=utility,
        security=security if injection_task else None,
        has_injection=injection_task is not None,
    )


def save(trajectories: list[AgentTrajectory], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    records = [_traj_to_dict(t) for t in trajectories]
    path.write_text(json.dumps(records, indent=2))


def load(path: Path) -> list[AgentTrajectory]:
    records = json.loads(path.read_text())
    return [_dict_to_traj(r) for r in records]


# --- characterization ---------------------------------------------------------

def characterize() -> dict:
    """Return task counts and injection task IDs per suite — no API calls."""
    from agentdojo.task_suite.load_suites import get_suites

    suites = get_suites(BENCHMARK_VERSION)
    result = {}
    for name in SUITE_NAMES:
        suite = suites.get(name)
        if suite is None:
            continue
        result[name] = {
            "user_tasks": len(suite.user_tasks),
            "injection_tasks": len(suite.injection_tasks),
            "injection_task_ids": list(suite.injection_tasks.keys()),
            "user_task_ids": list(suite.user_tasks.keys()),
        }
    return result


# --- serialization helpers ----------------------------------------------------

def _traj_to_dict(t: AgentTrajectory) -> dict:
    return {
        "id": t.id,
        "meta": {
            "suite": t.meta.suite,
            "user_task_id": t.meta.user_task_id,
            "injection_task_id": t.meta.injection_task_id,
            "user_prompt": t.meta.user_prompt,
            "injection_goal": t.meta.injection_goal,
        },
        "steps": [
            {"function": s.function, "args": s.args, "result": s.result, "is_injected": s.is_injected}
            for s in t.steps
        ],
        "utility": t.utility,
        "security": t.security,
        "has_injection": t.has_injection,
        "raw_messages": t.raw_messages,
    }


def _dict_to_traj(d: dict) -> AgentTrajectory:
    meta = TaskMeta(**d["meta"])
    steps = [ToolStep(**s) for s in d["steps"]]
    return AgentTrajectory(
        id=d["id"],
        meta=meta,
        steps=steps,
        utility=d["utility"],
        security=d["security"],
        has_injection=d["has_injection"],
        raw_messages=d.get("raw_messages", []),
    )
