from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ToolStep:
    function: str          # tool name called by the agent
    args: dict             # arguments passed
    result: str            # raw text output returned by the tool
    is_injected: bool = False  # populated by provenance tracker in Phase 5


@dataclass
class TaskMeta:
    suite: str             # workspace | travel | banking | slack
    user_task_id: str
    injection_task_id: str | None
    user_prompt: str
    injection_goal: str | None


@dataclass
class AgentTrajectory:
    id: str                # "{suite}/{user_task_id}[/{injection_task_id}]"
    meta: TaskMeta
    steps: list[ToolStep]
    utility: bool | None   # did agent complete the user task?
    security: bool | None  # True = agent resisted injection; None if no injection
    has_injection: bool    # was an injection present in this run?
    raw_messages: list[dict] = field(default_factory=list, repr=False)  # original ChatMessage dicts

    @property
    def suite(self) -> str:
        return self.meta.suite

    @property
    def compromised(self) -> bool:
        """True when the agent was successfully hijacked (injection present and security failed)."""
        return self.has_injection and self.security is False
