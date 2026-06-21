# tracer

Runtime detector for hijacked and malicious agent behavior — trajectory analysis plus a rigorous benchmark that exposes where existing detectors fail.

**GitHub:** `github.com/WFullen94/tracer`
**Thesis:** Current injection detectors pass evaluation benchmarks by learning surface patterns on weak attack sets. tracer builds a trajectory-based hijack detector and a more honest benchmark: held-out attack families the detector never saw, a stricter leakage-aware success metric, and evaluation against adaptive variants of published attacks. The contribution is in the measurement methodology as much as the detector itself.

**Deliverables:** Research blog series (2 posts) + arXiv preprint targeting NeurIPS/ICLR agent safety track.

---

## What this project does

A prompt injection attack hijacks an agent mid-task: the agent was given goal A, a tool returns malicious content containing injected instructions, and the agent's subsequent actions start serving goal B instead. tracer detects this from the trajectory — the sequence of tool calls and decisions the agent made — by watching for goal deviation and untrusted provenance.

Two detection signals:
- **Behavioral**: LLM-based trajectory judge that reads the execution trace and flags where the agent's actions diverge from the original task goal
- **Provenance**: taint tracker that labels tool outputs as trusted (user-originated) or untrusted (external data), then flags agent actions that trace back to untrusted sources

Novel contribution: the benchmark harness. The field's own papers have shown that existing benchmarks have weak attacks, flawed success metrics, and evaluation splits that detectors effectively overfit to. tracer evaluates honestly — held-out attack families, the stricter "actual data leakage" success metric rather than mere task hijacking, and adaptive attack variants from published corpora.

Built on AgentDojo (the canonical multi-step agent benchmark, extended by US + UK AISI). Evaluation baseline: AgentSentry.

**Connection to crucible:** crucible optimizes skill documents for injection detection. In Phase 7, tracer uses crucible-optimized skills as the behavioral detector's classification logic — the two projects share a detection interface by design.

**Connection to wargames:** tracer's detector is the blue team detection module that wargames will eventually run at simulation scale.

---

## Reading list (sequenced — each paper informs the next build step)

1. **AgentDojo** (arXiv 2406.13352) — the benchmark environment; understand task/trajectory format before writing any code
2. **AgentSentry** (arXiv 2503.xxxxx) — closest prior detector; counterfactual re-execution at tool-return boundaries + context purification; your baseline and direct comparison target
3. **Firewall/benchmark critique** — shows near-perfect scores expose benchmark weaknesses: weak attacks, flawed metrics, implementation issues; motivates your held-out evaluation design
4. **Data-flow threat model** — reframes success as actual leakage (not mere hijack); this is your stricter metric

---

## Phased Roadmap

### Phase 1 — AgentDojo setup + trajectory format
- [ ] Install AgentDojo; run existing baselines to verify environment
- [ ] Understand trajectory schema: task, tool calls, tool returns, final action
- [ ] `tracer/agentdojo/adapter.py`: load AgentDojo trajectories into tracer's internal format
- [ ] Characterize the dataset: how many tasks, attack families, trajectory lengths

### Phase 2 — Behavioral detector (baseline)
- [ ] `tracer/detector/base.py`: `Detector` ABC — `detect(trajectory) -> DetectionResult`
- [ ] `tracer/detector/behavioral.py`: LLM judge reads full trajectory, flags goal deviation; reasoning + confidence score
- [ ] `DetectionResult` dataclass: flagged (bool), confidence (float), flagged_step (int | None), reasoning (str)
- [ ] Evaluate on AgentDojo: precision, recall, F1, utility score (does detection hurt benign tasks?)

### Phase 3 — Benchmark harness + held-out InjecAgent corpus
- [ ] `tracer/benchmark/splits.py`: partition AgentDojo by attack family; reserve held-out families the detector is never trained/tuned on
- [ ] `tracer/benchmark/metrics.py`: standard ASR (attack success rate) + utility score
- [ ] `tracer/benchmark/harness.py`: end-to-end eval runner — takes a detector, returns a full metrics report
- [ ] `tracer/injecagent/adapter.py`: load InjecAgent v1 test cases (DH + DS, base + enhanced); produce seed trajectories the detector has never seen during AgentDojo development — the true generalization test for Phase 6
- [ ] Reproduce AgentSentry numbers as sanity check

### Phase 4 — Stricter leakage-aware metric
- [ ] Extend `metrics.py`: implement data-flow–aware success metric — attack only counts if agent actually leaks data, not merely if task is hijacked
- [ ] Re-evaluate behavioral detector and AgentSentry baseline under strict metric
- [ ] Result: does the ranking of detectors change under the stricter metric?

### Phase 5 — Provenance tracking
- [ ] `tracer/detector/provenance.py`: taint labels on tool outputs (trusted = user-originated, untrusted = external); flag actions tracing back to untrusted sources
- [ ] Evaluate provenance detector on same benchmark splits
- [ ] Compare: behavioral vs. provenance — which is more precise? Which has lower utility cost?

### Phase 6 — Systematic evaluation
- [ ] Evaluate both detectors on held-out attack families (Phase 3 splits)
- [ ] Evaluate against adaptive/cascaded attack variants from published corpora
- [ ] Ablation: detector with vs. without held-out split discipline — does the gap expose benchmark overfitting?
- [ ] Generate full comparison table: tracer behavioral, tracer provenance, AgentSentry, no-defense baseline

### Phase 7 — Crucible integration
- [ ] Wire crucible-optimized skill documents as the behavioral detector's classification logic
- [ ] Compare: fixed LLM judge vs. skill-optimized judge on same AgentDojo splits
- [ ] Result: does a skill-optimized detector outperform a fixed one? At what optimization cost?

### Phase 8 — Distribution + reporting
- [ ] Clean public API: `tracer.detect(trajectory)` returns `DetectionResult`
- [ ] Full benchmark report as Markdown/HTML artifact
- [ ] PyPI package
- [ ] Blog posts (see below)

---

## Conventions

- Conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `chore:`
- Tag each phase: `v0.1.0`, `v0.2.0`, etc.
- `Detector` is the only interface that changes per detection approach
- Benchmark harness is deterministic: same seed → same splits → same numbers
- Never train or tune on held-out attack families — enforce this in `splits.py`
- Evaluation uses AgentDojo's existing trajectory format; tracer does not modify the benchmark

## Related work in this repo

- `~/crucible/` — skill optimizer whose detection task is prompt injection; Phase 7 connects the two projects directly
- `~/llm-security/` — notebooks 02 (direct injection), 03 (indirect injection), 08 (agentic attacks), 16 (red teaming); foundational reading for the attack taxonomy
- `~/agentic-ai/` — notebooks 08 (agent evaluation), 09 (trust and safety); covers the trajectory analysis foundations
- `~/wargames/` — the eventual simulation environment where tracer's detector runs as the blue team
- `~/bouncer/` — static complement: bouncer catches vulnerabilities pre-deployment, tracer catches hijacking at runtime

## Current Status

Phase 1 — not started. Start by reading AgentDojo (arXiv 2406.13352), then run their existing baseline to verify the environment works.
