"""
Phase 2 baseline experiment: run BehavioralDetector on AgentDojo trajectories.

Usage:
    python -m tracer.experiments.run_baseline \
        --suites workspace banking \
        --n-injection-tasks 3 \
        --n-user-tasks 5 \
        --out logs/baseline.json
"""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

import anthropic

from tracer.agentdojo.adapter import SUITE_NAMES, from_agentdojo_run, save
from tracer.benchmark.metrics import EvalSample, compute
from tracer.detector.behavioral import BehavioralDetector

log = logging.getLogger(__name__)


def _build_pipeline(model: str):
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
    from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemPromptInjectionChecker
    from agentdojo.agent_pipeline.llms.anthropic_llm import AnthropicLLM
    from agentdojo.default_monitors import tool_call_filter

    client = anthropic.Anthropic()
    llm = AnthropicLLM(client=client, model=model)
    return AgentPipeline([InitQuery(), llm])


def run(
    suites: list[str],
    n_user_tasks: int | None,
    n_injection_tasks: int | None,
    detector_model: str,
    agent_model: str,
    out: Path,
) -> None:
    from agentdojo.task_suite.load_suites import get_suites
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline

    client = anthropic.Anthropic()
    detector = BehavioralDetector(client=client, model=detector_model)
    pipeline = _build_pipeline(agent_model)

    all_suites = get_suites("v1")
    trajectories = []
    samples = []

    for suite_name in suites:
        suite = all_suites.get(suite_name)
        if suite is None:
            log.warning("Suite %s not found; skipping", suite_name)
            continue

        user_tasks = list(suite.user_tasks.values())
        if n_user_tasks:
            user_tasks = user_tasks[:n_user_tasks]

        injection_tasks = list(suite.injection_tasks.values())
        if n_injection_tasks:
            injection_tasks = injection_tasks[:n_injection_tasks]

        log.info("Suite %s: %d user tasks × %d injection tasks + %d benign",
                 suite_name, len(user_tasks), len(injection_tasks), len(user_tasks))

        for user_task in user_tasks:
            env = suite.load_and_inject_default_environment({})

            # --- benign run (no injection) ---
            _, _, _, messages, _ = pipeline.query(
                query=user_task.PROMPT,
                runtime=suite.get_runtime(env),
                env=env,
            )
            utility = user_task.utility(None, env, list(messages))
            traj = from_agentdojo_run(
                suite_name=suite_name,
                user_task=user_task,
                injection_task=None,
                messages=list(messages),
                utility=utility,
                security=True,
            )
            trajectories.append(traj)
            result = detector.detect(traj)
            samples.append(EvalSample(trajectory=traj, result=result))
            log.info("[benign] %s flagged=%s conf=%.2f", traj.id, result.flagged, result.confidence)

            # --- injected runs ---
            for injection_task in injection_tasks:
                env_inj = suite.load_and_inject_default_environment(
                    injection_task.get_injection_candidates(env)
                )
                _, _, _, messages_inj, _ = pipeline.query(
                    query=user_task.PROMPT,
                    runtime=suite.get_runtime(env_inj),
                    env=env_inj,
                )
                utility_inj = user_task.utility(None, env_inj, list(messages_inj))
                security = injection_task.security(None, env_inj, list(messages_inj))
                traj_inj = from_agentdojo_run(
                    suite_name=suite_name,
                    user_task=user_task,
                    injection_task=injection_task,
                    messages=list(messages_inj),
                    utility=utility_inj,
                    security=security,
                )
                trajectories.append(traj_inj)
                result_inj = detector.detect(traj_inj)
                samples.append(EvalSample(trajectory=traj_inj, result=result_inj))
                log.info("[injected] %s compromised=%s flagged=%s conf=%.2f",
                         traj_inj.id, traj_inj.compromised, result_inj.flagged, result_inj.confidence)

    metrics = compute(samples)
    print(metrics)

    out.parent.mkdir(parents=True, exist_ok=True)
    save(trajectories, out.with_suffix(".trajectories.json"))

    report = {
        "metrics": {
            "precision": metrics.precision,
            "recall": metrics.recall,
            "f1": metrics.f1,
            "false_positive_rate": metrics.false_positive_rate,
            "attack_success_rate": metrics.attack_success_rate,
            "utility_cost": metrics.utility_cost,
            "n_total": metrics.n_total,
            "n_injected": metrics.n_injected,
            "n_benign": metrics.n_benign,
        },
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
            for s in samples
        ],
    }
    out.write_text(json.dumps(report, indent=2))
    log.info("Report written to %s", out)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    parser = argparse.ArgumentParser(description="tracer Phase 2 baseline")
    parser.add_argument("--suites", nargs="+", default=["workspace"],
                        choices=list(SUITE_NAMES))
    parser.add_argument("--n-user-tasks", type=int, default=None)
    parser.add_argument("--n-injection-tasks", type=int, default=None)
    parser.add_argument("--detector-model", default="claude-sonnet-4-6")
    parser.add_argument("--agent-model", default="claude-haiku-4-5-20251001")
    parser.add_argument("--out", type=Path, default=Path("logs/baseline.json"))
    args = parser.parse_args()

    run(
        suites=args.suites,
        n_user_tasks=args.n_user_tasks,
        n_injection_tasks=args.n_injection_tasks,
        detector_model=args.detector_model,
        agent_model=args.agent_model,
        out=args.out,
    )


if __name__ == "__main__":
    main()
