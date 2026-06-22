"""
Split trajectories by attack family for honest held-out evaluation.

The project thesis: detectors look good because benchmarks are split poorly.
splits.py provides primitives for partitioning AgentDojo trajectories by
injection task ID and InjecAgent cases by attack_type, so the detector can
be developed on one slice and evaluated on a disjoint slice it has never
seen.

Phase 6 will lock in canonical held-out IDs (see HELDOUT_AGENTDOJO and
HELDOUT_INJECAGENT below) — this module just provides the primitives.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Generic, TypeVar

from tracer.injecagent.adapter import InjecAgentCase
from tracer.types import AgentTrajectory

T = TypeVar("T")


@dataclass
class Split(Generic[T]):
    """A train/held-out partition of trajectories or cases."""
    train: list[T]
    held_out: list[T]

    def __len__(self) -> int:
        return len(self.train) + len(self.held_out)


def split_by_key(items: Iterable[T], held_out_keys: Iterable, key_fn: Callable[[T], object]) -> Split[T]:
    """Partition `items` by `key_fn` — anything matching a held-out key goes to held_out."""
    held = set(held_out_keys)
    train: list[T] = []
    held_out: list[T] = []
    for item in items:
        if key_fn(item) in held:
            held_out.append(item)
        else:
            train.append(item)
    return Split(train=train, held_out=held_out)


def split_agentdojo_by_injection(
    trajectories: Iterable[AgentTrajectory],
    held_out_injection_ids: Iterable[str],
) -> Split[AgentTrajectory]:
    """Hold out specific AgentDojo injection task IDs.

    Benign trajectories (injection_task_id is None) always go to train.
    """
    held = set(held_out_injection_ids)
    train: list[AgentTrajectory] = []
    held_out: list[AgentTrajectory] = []
    for traj in trajectories:
        inj_id = traj.meta.injection_task_id
        if inj_id is not None and inj_id in held:
            held_out.append(traj)
        else:
            train.append(traj)
    return Split(train=train, held_out=held_out)


def split_injecagent_by_attack_type(
    cases: Iterable[InjecAgentCase],
    held_out_attack_types: Iterable[str],
) -> Split[InjecAgentCase]:
    """Hold out InjecAgent cases by their `attack_type` field."""
    return split_by_key(cases, held_out_attack_types, lambda c: c.attack_type)


# --- canonical held-out families (locked in Phase 6) -------------------------
# These names are documented here so any future training code that touches
# them can be flagged in review. Do not tune against these.

HELDOUT_AGENTDOJO: dict[str, tuple[str, ...]] = {
    # Per-suite injection task IDs reserved for held-out evaluation.
    # Populated in Phase 6 after attack family clustering.
}

HELDOUT_INJECAGENT: tuple[str, ...] = (
    # InjecAgent attack_type strings reserved for held-out evaluation.
    # Populated in Phase 6.
)
