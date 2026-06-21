from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tracer.detector.behavioral import BehavioralDetector, _format_trajectory, _parse_result
from tracer.types import AgentTrajectory, TaskMeta, ToolStep


def _meta():
    return TaskMeta(
        suite="workspace",
        user_task_id="user_task_0",
        injection_task_id=None,
        user_prompt="Find the meeting notes.",
        injection_goal=None,
    )


def _traj(steps=None, has_injection=False, security=None):
    return AgentTrajectory(
        id="workspace/user_task_0",
        meta=_meta(),
        steps=steps or [],
        utility=True,
        security=security,
        has_injection=has_injection,
    )


# --- _format_trajectory -------------------------------------------------------

def test_format_empty_trajectory():
    result = _format_trajectory(_traj())
    assert "(no tool calls)" in result


def test_format_trajectory_shows_step():
    steps = [ToolStep(function="search_emails", args={"query": "meeting"}, result="Found: notes.txt")]
    result = _format_trajectory(_traj(steps=steps))
    assert "search_emails" in result
    assert "meeting" in result
    assert "Found: notes.txt" in result


def test_format_trajectory_truncates_long_result():
    long_result = "x" * 500
    steps = [ToolStep(function="read_file", args={}, result=long_result)]
    result = _format_trajectory(_traj(steps=steps))
    assert "..." in result


# --- _parse_result ------------------------------------------------------------

def test_parse_flagged_yes():
    text = "Analysis done.\nFLAGGED: yes\nCONFIDENCE: 0.9\nFLAGGED_STEP: 2\nREASONING: Agent exfiltrated email."
    flagged, conf, step, reason = _parse_result(text)
    assert flagged is True
    assert conf == pytest.approx(0.9)
    assert step == 2
    assert "exfiltrated" in reason


def test_parse_flagged_no():
    text = "FLAGGED: no\nCONFIDENCE: 0.1\nFLAGGED_STEP: -1\nREASONING: Normal behavior."
    flagged, conf, step, reason = _parse_result(text)
    assert flagged is False
    assert step is None


def test_parse_negative_step_becomes_none():
    text = "FLAGGED: yes\nCONFIDENCE: 0.8\nFLAGGED_STEP: -1\nREASONING: Suspicious."
    _, _, step, _ = _parse_result(text)
    assert step is None


def test_parse_missing_fields_defaults():
    flagged, conf, step, reason = _parse_result("No relevant output here.")
    assert flagged is False
    assert conf == pytest.approx(0.5)
    assert step is None


# --- BehavioralDetector -------------------------------------------------------

def _mock_response(text: str):
    block = MagicMock()
    block.text = text
    resp = MagicMock()
    resp.content = [block]
    return resp


def test_detector_flags_injection():
    verdict = "FLAGGED: yes\nCONFIDENCE: 0.95\nFLAGGED_STEP: 1\nREASONING: Agent sent email to attacker."
    client = MagicMock()
    client.messages.create.return_value = _mock_response(verdict)

    detector = BehavioralDetector(client=client)
    traj = _traj(has_injection=True, security=False)
    result = detector.detect(traj)

    assert result.flagged is True
    assert result.confidence == pytest.approx(0.95)
    assert result.flagged_step == 1


def test_detector_clears_benign():
    verdict = "FLAGGED: no\nCONFIDENCE: 0.05\nFLAGGED_STEP: -1\nREASONING: Agent completed task normally."
    client = MagicMock()
    client.messages.create.return_value = _mock_response(verdict)

    detector = BehavioralDetector(client=client)
    traj = _traj()
    result = detector.detect(traj)

    assert result.flagged is False
    assert result.flagged_step is None


def test_detector_passes_user_prompt_to_api():
    client = MagicMock()
    client.messages.create.return_value = _mock_response(
        "FLAGGED: no\nCONFIDENCE: 0.1\nFLAGGED_STEP: -1\nREASONING: ok"
    )
    detector = BehavioralDetector(client=client)
    detector.detect(_traj())

    call_kwargs = client.messages.create.call_args
    messages = call_kwargs.kwargs["messages"]
    assert "Find the meeting notes" in messages[0]["content"]
