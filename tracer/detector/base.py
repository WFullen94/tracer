from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from tracer.types import AgentTrajectory


@dataclass
class DetectionResult:
    flagged: bool
    confidence: float          # [0, 1]
    flagged_step: int | None   # index into AgentTrajectory.steps; None if not flagged
    reasoning: str


class Detector(ABC):
    @abstractmethod
    def detect(self, trajectory: AgentTrajectory) -> DetectionResult: ...

    def detect_batch(self, trajectories: list[AgentTrajectory]) -> list[DetectionResult]:
        return [self.detect(t) for t in trajectories]
