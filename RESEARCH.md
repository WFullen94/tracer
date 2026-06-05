# Research Directions

Open research questions that emerged from designing tracer. Each one is a potential
workshop paper, arXiv preprint, or full venue submission. Framed as a rigorous evaluation
of injection detectors rather than a new attack contribution — the novelty is in the
measurement methodology and the honest benchmark design.

**Overarching claim:** Existing injection detectors appear to perform well because existing
benchmarks are too easy — weak attack sets, flawed success metrics, and evaluation splits
that detectors effectively overfit to. tracer measures honestly and the picture changes.

---

## 1. Benchmark Overfitting in Injection Detection

**Hypothesis:** Detection performance on standard AgentDojo attack splits is significantly
inflated relative to held-out attack families the detector never encountered during
development. Current published numbers reflect benchmark familiarity rather than
generalizable detection capability.

**Novel claim:** No paper has explicitly partitioned AgentDojo by attack family and measured
the held-out generalization gap for published detectors. The firewall paper showed near-
perfect scores suggest benchmark weakness, but didn't quantify the gap family-by-family.
This paper does that systematically for the first time.

**What we need:**
- Phase 3: benchmark harness with attack-family splits
- Phase 6: evaluate behavioral detector + AgentSentry on held-out splits
- Metric: F1 on seen attack families vs. F1 on held-out families; the gap is the finding

**Potential finding:** Detectors that score >90% on standard splits drop to 60–75% on
held-out families — a gap that implies current benchmarks measure surface-pattern
memorization more than genuine detection of goal deviation. The magnitude of the gap
varies by detector architecture: LLM-judge detectors generalize better than rule-based ones.

**Target venue:** NeurIPS 2026 Datasets & Benchmarks track, or ICLR 2027 agent safety workshop
**Status:** Blocked on Phase 3

---

## 2. Leakage-Aware vs. Hijack-Aware Metrics Change the Detector Ranking

**Hypothesis:** The ranking of injection detectors changes when switching from a hijack-
aware success metric (did the agent deviate from its task?) to a leakage-aware metric
(did the agent actually exfiltrate data?). Detectors optimized for one metric are not
optimal for the other, and practitioners need to know which metric their threat model requires.

**Novel claim:** The data-flow threat model paper proposed the stricter leakage metric but
did not re-evaluate existing detectors under it. No paper has shown whether the ranking
of published detectors changes under the stricter definition — and whether any detector
that looks good on hijack-aware metrics is actually poor at preventing real leakage.

**What we need:**
- Phase 4: leakage-aware metric implementation
- Phase 6: full re-evaluation of behavioral detector + AgentSentry + no-defense baseline
- Metric: correlation between hijack-aware and leakage-aware rankings; Kendall's tau

**Potential finding:** Two detectors with similar hijack-aware F1 have divergent leakage-
aware scores — provenance-based detection is substantially better at the stricter metric
because it directly tracks data flow, while behavioral detectors catch hijacking but miss
cases where the agent leaks data without obvious goal deviation.

**Target venue:** IEEE S&P or USENIX Security (ML + security track), or arXiv preprint
**Status:** Blocked on Phase 4 + 5

---

## 3. Behavioral vs. Provenance Detection: Precision, Recall, and Utility Cost

**Hypothesis:** Behavioral detection (LLM judge watching for goal deviation) and provenance
detection (taint tracking data flow from untrusted sources) have complementary failure
modes: behavioral misses subtle leakage without overt goal deviation; provenance generates
false positives when legitimate tasks process external data. A combined detector Pareto-
dominates either alone.

**Novel claim:** No paper directly compares these two detection signal types on the same
evaluation set with utility cost included as a metric. AgentSentry uses counterfactual
re-execution (a behavioral approach); pure provenance tracking for LLM agents has not
been benchmarked against it on AgentDojo.

**What we need:**
- Phase 5: provenance detector implementation and evaluation
- Phase 6: head-to-head comparison on same splits with utility score
- Metric: precision, recall, F1, and utility degradation on benign tasks for each approach

**Potential finding:** Behavioral detection has higher recall (catches more attack types)
but higher utility cost (more false positives on benign tasks that process external content).
Provenance detection is more precise on leakage but misses attacks that don't cross the
trust boundary. An ensemble combining both reaches a better Pareto point than either alone.

**Target venue:** EMNLP 2026 (industry or findings track), or NeurIPS agent safety workshop
**Status:** Blocked on Phase 5 + 6

---

## 4. Skill-Optimized Detection (crucible × tracer)

**Hypothesis:** A behavioral detector whose classification logic is a skill document
optimized via crucible outperforms a fixed LLM judge on the same trajectories — and the
performance gap widens on held-out attack families, because skill optimization forces
generalization through the validation gate.

**Novel claim:** This is the first study connecting skill optimization (SkillOpt-style
text-space optimization) to agent safety evaluation. The crucible × tracer integration
produces a detector that improves itself over time rather than remaining static — directly
addressing the observation that injection patterns evolve and static detectors go stale.

**What we need:**
- crucible Phase 2 complete (base optimizer loop)
- tracer Phase 7: wire crucible-optimized skill as behavioral detector's logic
- Experiment: fixed judge vs. skill-optimized judge on same AgentDojo splits
- Distribution shift test: train skill on one attack family, evaluate on another

**Potential finding:** Skill-optimized detection improves F1 by 8–15% on held-out attack
families vs. the fixed judge baseline. The gap is larger on held-out families than on
seen ones — skill optimization learns attack-agnostic goal-deviation patterns rather
than family-specific surface features. This connects the crucible research narrative
directly to the tracer safety narrative.

**Target venue:** NeurIPS 2026 Workshop on Agentic AI, or joint paper with crucible
**Status:** Blocked on crucible Phase 2 + tracer Phase 7

---

## 5. Adaptive Adversary Evaluation

**Hypothesis:** Detectors that score well on the standard AgentDojo attack set fail
non-trivially when attackers adapt to the detector's known weaknesses — specifically,
crafting injections that avoid goal deviation signals (behavioral blind spot) while
staying within trust boundaries (provenance blind spot).

**Novel claim:** Published adaptive attack variants (from the cascaded attack paper) have
not been used to evaluate all current detectors. Systematic measurement of adaptive
degradation reveals which detector architectures are inherently more robust to adversarial
pressure and which improve rapidly under crucible-style optimization.

**What we need:**
- Phase 6 + 7 (full evaluation pipeline + crucible integration)
- Adaptive attack variants from published corpora — not new attacks authored here
- Metric: F1 degradation from standard to adaptive variants; recovery curve under crucible optimization

**Potential finding:** Fixed detectors degrade 20–35% under adaptive attacks. Skill-
optimized detectors recover faster because the optimization loop naturally adapts to new
attack patterns when re-run on fresh data — a practitioner argument for periodically
re-running crucible rather than deploying a static skill.

**Target venue:** USENIX Security 2027, or arXiv
**Status:** Blocked on Phases 6 + 7

---

## Dependency map

```
Phase 3 (benchmark harness)       ──► Idea 1 (benchmark overfitting)
Phase 4 (leakage metric)          ──► Idea 2 (metric ranking)
Phase 5 (provenance detector)     ──► Ideas 2, 3
Phase 6 (systematic evaluation)   ──► Ideas 1, 2, 3, 5
Phase 7 (crucible integration)    ──► Ideas 4, 5
crucible Phase 2                  ──► Idea 4
```

**Natural first paper: Ideas 1 + 2** — benchmark overfitting and metric sensitivity are
both produced by running Phases 3–4 and require no new detector architecture beyond the
baseline behavioral judge. These establish the research contribution (honest measurement)
before the more complex detector work in Phases 5–7.

**Blog series:**
- Post 1 (after Phase 3): "Why injection detector benchmarks are too easy — and how to
  measure honestly"
- Post 2 (after Phase 7): "What happens when the detector learns: skill-optimized
  detection via crucible × tracer"
