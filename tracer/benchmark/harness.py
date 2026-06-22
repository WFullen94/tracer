"""
End-to-end evaluation runner.

`evaluate()` takes a Detector and a list of trajectories, calls the detector
on each, computes aggregate metrics and per-group breakdowns (e.g., per suite
or per attack type), and returns a structured BenchmarkReport. The report can
be serialized to JSON for the paper's tables and the blog post artifacts.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from tracer.benchmark.metrics import EvalSample, Metrics, compute
from tracer.detector.base import Detector
from tracer.types import AgentTrajectory

log = logging.getLogger(__name__)


@dataclass
class BenchmarkReport:
    name: str
    metrics: Metrics
    metrics_by_group: dict[str, Metrics] = field(default_factory=dict)
    samples: list[EvalSample] = field(default_factory=list)

    def summary(self) -> str:
        lines = [f"=== {self.name} ===", f"OVERALL  {self.metrics}"]
        for group, m in sorted(self.metrics_by_group.items()):
            lines.append(f"  {group:<30s} {m}")
        return "\n".join(lines)


def evaluate(
    detector: Detector,
    trajectories: list[AgentTrajectory],
    name: str = "evaluation",
    group_fn: Callable[[AgentTrajectory], str] | None = None,
    verbose: bool = False,
) -> BenchmarkReport:
    """Run `detector` over `trajectories`, compute metrics, optionally group by suite/category."""
    samples: list[EvalSample] = []
    n = len(trajectories)
    for i, traj in enumerate(trajectories):
        result = detector.detect(traj)
        samples.append(EvalSample(trajectory=traj, result=result))
        if verbose and (i + 1) % 25 == 0:
            log.info("[%s] %d/%d  flagged=%s", name, i + 1, n, result.flagged)

    metrics = compute(samples)

    metrics_by_group: dict[str, Metrics] = {}
    if group_fn is not None:
        groups: dict[str, list[EvalSample]] = {}
        for s in samples:
            groups.setdefault(group_fn(s.trajectory), []).append(s)
        metrics_by_group = {key: compute(g) for key, g in groups.items()}

    return BenchmarkReport(
        name=name,
        metrics=metrics,
        metrics_by_group=metrics_by_group,
        samples=samples,
    )


def save_report(report: BenchmarkReport, path: Path | str) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_to_dict(report), indent=2))


# --- common group functions ---------------------------------------------------

def group_by_suite(t: AgentTrajectory) -> str:
    return t.meta.suite


def group_by_injection_id(t: AgentTrajectory) -> str:
    return t.meta.injection_task_id or "benign"


# --- serialization ------------------------------------------------------------

def _to_dict(report: BenchmarkReport) -> dict[str, Any]:
    return {
        "name": report.name,
        "metrics": asdict(report.metrics),
        "metrics_by_group": {k: asdict(v) for k, v in report.metrics_by_group.items()},
        "samples": [
            {
                "trajectory_id": s.trajectory.id,
                "has_injection": s.trajectory.has_injection,
                "compromised": s.trajectory.compromised,
                "flagged": s.result.flagged,
                "confidence": s.result.confidence,
                "flagged_step": s.result.flagged_step,
                "reasoning": s.result.reasoning,
            }
            for s in report.samples
        ],
    }
