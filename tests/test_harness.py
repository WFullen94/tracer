from __future__ import annotations

import json
from pathlib import Path

from tracer.benchmark.harness import (
    BenchmarkReport,
    evaluate,
    group_by_injection_id,
    group_by_suite,
    save_report,
)
from tracer.detector.base import DetectionResult, Detector
from tracer.types import AgentTrajectory, TaskMeta


def _traj(suite: str, inj_id: str | None, compromised: bool) -> AgentTrajectory:
    meta = TaskMeta(
        suite=suite, user_task_id="ut0", injection_task_id=inj_id,
        user_prompt="x", injection_goal="y" if inj_id else None,
    )
    return AgentTrajectory(
        id=f"{suite}/ut0" + (f"/{inj_id}" if inj_id else ""),
        meta=meta, steps=[], utility=True,
        security=False if compromised else (True if inj_id else None),
        has_injection=bool(inj_id),
    )


class _ScriptedDetector(Detector):
    """Detector that returns a pre-set verdict per trajectory id."""

    def __init__(self, verdicts: dict[str, bool]):
        self._verdicts = verdicts

    def detect(self, trajectory: AgentTrajectory) -> DetectionResult:
        flagged = self._verdicts.get(trajectory.id, False)
        return DetectionResult(
            flagged=flagged, confidence=0.9 if flagged else 0.1,
            flagged_step=0 if flagged else None, reasoning="scripted",
        )


# --- evaluate -----------------------------------------------------------------

def test_evaluate_basic_metrics():
    trajs = [
        _traj("workspace", "injection_task_0", compromised=True),   # positive
        _traj("workspace", None, compromised=False),                # benign
    ]
    detector = _ScriptedDetector({"workspace/ut0/injection_task_0": True})
    report = evaluate(detector, trajs, name="basic")

    assert isinstance(report, BenchmarkReport)
    assert report.name == "basic"
    assert report.metrics.n_total == 2
    assert report.metrics.n_true_positive == 1
    assert report.metrics.n_true_negative == 1
    assert report.metrics.f1 == 1.0


def test_evaluate_calls_detector_on_each_trajectory():
    trajs = [_traj("w", f"injection_task_{i}", True) for i in range(3)]
    calls: list[str] = []

    class _Recording(Detector):
        def detect(self, t):
            calls.append(t.id)
            return DetectionResult(flagged=False, confidence=0.1, flagged_step=None, reasoning="")

    evaluate(_Recording(), trajs)
    assert calls == [t.id for t in trajs]


def test_evaluate_with_group_by_suite():
    trajs = [
        _traj("workspace", "injection_task_0", True),
        _traj("workspace", None, False),
        _traj("banking", "injection_task_0", True),
    ]
    detector = _ScriptedDetector({
        "workspace/ut0/injection_task_0": True,
        "banking/ut0/injection_task_0": False,  # missed
    })
    report = evaluate(detector, trajs, group_fn=group_by_suite)

    assert set(report.metrics_by_group.keys()) == {"workspace", "banking"}
    assert report.metrics_by_group["workspace"].recall == 1.0
    assert report.metrics_by_group["banking"].recall == 0.0


def test_evaluate_with_group_by_injection_id():
    trajs = [
        _traj("workspace", "injection_task_0", True),
        _traj("workspace", "injection_task_1", True),
        _traj("workspace", None, False),
    ]
    detector = _ScriptedDetector({"workspace/ut0/injection_task_0": True})
    report = evaluate(detector, trajs, group_fn=group_by_injection_id)

    assert "injection_task_0" in report.metrics_by_group
    assert "injection_task_1" in report.metrics_by_group
    assert "benign" in report.metrics_by_group


def test_evaluate_no_group_fn_means_no_breakdown():
    trajs = [_traj("workspace", "injection_task_0", True)]
    detector = _ScriptedDetector({})
    report = evaluate(detector, trajs)
    assert report.metrics_by_group == {}


def test_evaluate_samples_preserved():
    trajs = [_traj("workspace", "injection_task_0", True)]
    detector = _ScriptedDetector({"workspace/ut0/injection_task_0": True})
    report = evaluate(detector, trajs)
    assert len(report.samples) == 1
    assert report.samples[0].result.flagged is True


def test_report_summary_runs():
    trajs = [_traj("workspace", "injection_task_0", True)]
    detector = _ScriptedDetector({"workspace/ut0/injection_task_0": True})
    report = evaluate(detector, trajs, name="test", group_fn=group_by_suite)
    summary = report.summary()
    assert "test" in summary
    assert "workspace" in summary


# --- save_report --------------------------------------------------------------

def test_save_report_roundtrip(tmp_path: Path):
    trajs = [
        _traj("workspace", "injection_task_0", True),
        _traj("workspace", None, False),
    ]
    detector = _ScriptedDetector({"workspace/ut0/injection_task_0": True})
    report = evaluate(detector, trajs, name="rt", group_fn=group_by_suite)

    out = tmp_path / "report.json"
    save_report(report, out)
    data = json.loads(out.read_text())

    assert data["name"] == "rt"
    assert data["metrics"]["n_total"] == 2
    assert "workspace" in data["metrics_by_group"]
    assert len(data["samples"]) == 2
    assert data["samples"][0]["trajectory_id"].startswith("workspace")
