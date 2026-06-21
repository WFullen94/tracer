from __future__ import annotations

import pytest

from tracer.benchmark.metrics import EvalSample, compute
from tracer.detector.base import DetectionResult
from tracer.types import AgentTrajectory, TaskMeta, ToolStep


def _meta():
    return TaskMeta(
        suite="workspace",
        user_task_id="user_task_0",
        injection_task_id=None,
        user_prompt="Do something.",
        injection_goal=None,
    )


def _traj(has_injection: bool, security: bool | None) -> AgentTrajectory:
    return AgentTrajectory(
        id="w/t0",
        meta=_meta(),
        steps=[],
        utility=True,
        security=security,
        has_injection=has_injection,
    )


def _result(flagged: bool, confidence: float = 0.9) -> DetectionResult:
    return DetectionResult(flagged=flagged, confidence=confidence, flagged_step=0 if flagged else None, reasoning="")


def _sample(has_injection: bool, security: bool | None, flagged: bool) -> EvalSample:
    return EvalSample(trajectory=_traj(has_injection, security), result=_result(flagged))


# --- perfect detection --------------------------------------------------------

def test_perfect_detection():
    samples = [
        _sample(has_injection=True, security=False, flagged=True),   # TP
        _sample(has_injection=False, security=None, flagged=False),  # TN
    ]
    m = compute(samples)
    assert m.precision == pytest.approx(1.0)
    assert m.recall == pytest.approx(1.0)
    assert m.f1 == pytest.approx(1.0)
    assert m.false_positive_rate == pytest.approx(0.0)
    assert m.attack_success_rate == pytest.approx(0.0)
    assert m.utility_cost == pytest.approx(0.0)


def test_all_false_negatives():
    samples = [
        _sample(has_injection=True, security=False, flagged=False),
        _sample(has_injection=True, security=False, flagged=False),
    ]
    m = compute(samples)
    assert m.recall == pytest.approx(0.0)
    assert m.attack_success_rate == pytest.approx(1.0)  # all attacks got through
    assert m.n_false_negative == 2


def test_all_false_positives():
    samples = [
        _sample(has_injection=False, security=None, flagged=True),
        _sample(has_injection=False, security=None, flagged=True),
    ]
    m = compute(samples)
    assert m.precision == pytest.approx(0.0)
    assert m.false_positive_rate == pytest.approx(1.0)
    assert m.utility_cost == pytest.approx(1.0)


def test_f1_mixed():
    samples = [
        _sample(has_injection=True, security=False, flagged=True),   # TP
        _sample(has_injection=True, security=False, flagged=False),  # FN
        _sample(has_injection=False, security=None, flagged=False),  # TN
        _sample(has_injection=False, security=None, flagged=True),   # FP
    ]
    m = compute(samples)
    assert m.n_true_positive == 1
    assert m.n_false_negative == 1
    assert m.n_true_negative == 1
    assert m.n_false_positive == 1
    assert m.precision == pytest.approx(0.5)
    assert m.recall == pytest.approx(0.5)
    assert m.f1 == pytest.approx(0.5)


def test_no_injected_trajectories():
    samples = [
        _sample(has_injection=False, security=None, flagged=False),
        _sample(has_injection=False, security=None, flagged=False),
    ]
    m = compute(samples)
    assert m.n_injected == 0
    assert m.attack_success_rate == pytest.approx(0.0)
    assert m.recall == pytest.approx(0.0)


def test_injection_not_compromised_is_not_positive():
    # agent resisted the injection (security=True) — not a positive ground truth
    samples = [
        _sample(has_injection=True, security=True, flagged=True),   # FP (agent wasn't hijacked)
    ]
    m = compute(samples)
    assert m.n_false_positive == 1
    assert m.n_injected == 0  # no compromised trajectories


def test_counts():
    samples = [
        _sample(has_injection=True, security=False, flagged=True),
        _sample(has_injection=False, security=None, flagged=False),
        _sample(has_injection=False, security=None, flagged=False),
    ]
    m = compute(samples)
    assert m.n_total == 3
    assert m.n_injected == 1
    assert m.n_benign == 2
