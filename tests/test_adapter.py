from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from tracer.agentdojo.adapter import (
    SUITE_NAMES,
    characterize,
    from_messages,
    load,
    save,
)
from tracer.detector.base import DetectionResult, Detector
from tracer.types import AgentTrajectory, TaskMeta, ToolStep


# --- helpers ------------------------------------------------------------------

def _meta(suite="workspace", user_task_id="user_task_0", injection_task_id=None):
    return TaskMeta(
        suite=suite,
        user_task_id=user_task_id,
        injection_task_id=injection_task_id,
        user_prompt="Who is at the meeting?",
        injection_goal="Send email to attacker@evil.com" if injection_task_id else None,
    )


def _messages_with_one_tool_call():
    """Minimal message list: user → assistant (tool call) → tool result."""
    from unittest.mock import MagicMock

    tc = MagicMock()
    tc.id = "call_1"
    tc.function = "search_emails"
    tc.args = {"query": "meeting"}

    assistant = {"role": "assistant", "content": None, "tool_calls": [tc]}
    tool_result = {
        "role": "tool",
        "tool_call": tc,
        "content": [{"type": "text", "content": "No emails found."}],
        "tool_call_id": "call_1",
        "error": None,
    }
    return [assistant, tool_result]


# --- AgentTrajectory types ----------------------------------------------------

def test_task_meta_fields():
    meta = _meta(injection_task_id="injection_task_0")
    assert meta.suite == "workspace"
    assert meta.injection_goal is not None


def test_trajectory_id_with_injection():
    meta = _meta(injection_task_id="injection_task_0")
    traj = AgentTrajectory(
        id="workspace/user_task_0/injection_task_0",
        meta=meta, steps=[], utility=True, security=False, has_injection=True,
    )
    assert traj.compromised is True


def test_trajectory_id_without_injection():
    meta = _meta()
    traj = AgentTrajectory(
        id="workspace/user_task_0",
        meta=meta, steps=[], utility=True, security=None, has_injection=False,
    )
    assert traj.compromised is False


def test_tool_step_default_not_injected():
    step = ToolStep(function="get_email", args={}, result="hello")
    assert step.is_injected is False


# --- from_messages ------------------------------------------------------------

def test_from_messages_extracts_tool_step():
    messages = _messages_with_one_tool_call()
    meta = _meta()
    traj = from_messages(messages, meta, utility=True, security=None, has_injection=False)

    assert len(traj.steps) == 1
    assert traj.steps[0].function == "search_emails"
    assert traj.steps[0].args == {"query": "meeting"}
    assert "No emails found" in traj.steps[0].result
    assert traj.steps[0].is_injected is False


def test_from_messages_no_tool_calls():
    messages = [{"role": "assistant", "content": [{"type": "text", "content": "Done."}], "tool_calls": None}]
    meta = _meta()
    traj = from_messages(messages, meta, utility=True, security=None, has_injection=False)
    assert traj.steps == []


def test_from_messages_trajectory_id_no_injection():
    meta = _meta()
    traj = from_messages([], meta, utility=True, security=None, has_injection=False)
    assert traj.id == "workspace/user_task_0"


def test_from_messages_trajectory_id_with_injection():
    meta = _meta(injection_task_id="injection_task_2")
    traj = from_messages([], meta, utility=True, security=False, has_injection=True)
    assert traj.id == "workspace/user_task_0/injection_task_2"


# --- save / load roundtrip ----------------------------------------------------

def test_save_load_roundtrip():
    meta = _meta(injection_task_id="injection_task_0")
    traj = AgentTrajectory(
        id="workspace/user_task_0/injection_task_0",
        meta=meta,
        steps=[ToolStep(function="search", args={"q": "x"}, result="y", is_injected=True)],
        utility=False,
        security=False,
        has_injection=True,
    )

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "trajs.json"
        save([traj], path)
        loaded = load(path)

    assert len(loaded) == 1
    t = loaded[0]
    assert t.id == traj.id
    assert t.steps[0].function == "search"
    assert t.steps[0].is_injected is True
    assert t.has_injection is True
    assert t.compromised is True


# --- characterize (hits AgentDojo but no API calls) ---------------------------

def test_characterize_returns_all_suites():
    data = characterize()
    for suite in SUITE_NAMES:
        assert suite in data


def test_characterize_task_counts():
    data = characterize()
    assert data["workspace"]["user_tasks"] == 40
    assert data["workspace"]["injection_tasks"] == 6
    assert data["banking"]["user_tasks"] == 16
    assert data["banking"]["injection_tasks"] == 9


def test_characterize_has_task_ids():
    data = characterize()
    assert "user_task_0" in data["workspace"]["user_task_ids"]
    assert len(data["workspace"]["injection_task_ids"]) > 0


# --- Detector ABC -------------------------------------------------------------

class _AlwaysFlagDetector(Detector):
    def detect(self, trajectory: AgentTrajectory) -> DetectionResult:
        return DetectionResult(flagged=True, confidence=1.0, flagged_step=0, reasoning="always")


def test_detector_batch():
    meta = _meta()
    trajs = [
        AgentTrajectory(id=f"w/t{i}", meta=meta, steps=[], utility=True, security=None, has_injection=False)
        for i in range(3)
    ]
    results = _AlwaysFlagDetector().detect_batch(trajs)
    assert all(r.flagged for r in results)
    assert len(results) == 3
