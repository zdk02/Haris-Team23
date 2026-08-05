# Haris — Simulation-Based Evaluation: Design Note

**Status: authoritative spec for the evaluation harness. Read before touching eval code.**

The Phase-3 evaluation is a *curated 9-case set on one app* (`demo_app/hospital/eval_harness.py`).
It proves each mechanism fires; it does **not** show generalization. This harness replaces that with a
**generated evaluation over many different multi-agent systems**, producing a credible, measured claim:
*unguarded multi-agent systems leak, and Haris measurably reduces that leakage across systems it was never
hardcoded for.*

---

## Locked decisions (do not deviate)

1. **Generate many DIFFERENT systems, not more hospital cases.** Hospital stays as the fully-wired reference
   app; education, finance, HR are *distinct* systems the generator produces. This is the generalization
   result.
2. **We specify domains + secret/leak recipes; the generator automates the rest** — secret values, scenario
   combinations, message traffic, ground-truth labels, the runs, and the scoring.
3. **Haris is app-agnostic already.** A new domain is run by passing its config (trust boundary +
   authorization allow-list + source data type + tokens) into the existing agents. No agent is forked or
   rewritten per domain.
4. **The ground-truth oracle is independent of Haris.** It labels leak / no-leak from the injected facts
   (did the known secret reach a recipient outside the domain's allow-list, or a wrong subject's session?),
   **never** from Haris's decision. Verify independence by labeling with Haris disabled.
5. **We do NOT target 100% detection / 0% false positives.** A perfect score on a broad eval reads as
   rigged. We build a deliberate difficulty spectrum and report per-domain / per-class breakdowns so results
   are high but realistic, with visible, explainable edges.
6. **The semantic/paraphrase AGENT (the defense) is out of scope.** But we INCLUDE a paraphrase leak class
   as a *measured miss*: because we author those leaks from a known secret, their ground truth is still
   deterministic, so Haris missing them yields an honest false-negative number that motivates the future
   semantic agent. ("Paraphrase agent" and "semantic agent" are the same, unbuilt, component.)
7. **The core evaluation is fully deterministic — no LLM judge.** The only LLM judge appears in the small,
   optional real-LLM realism slice (later).
8. **Every scenario runs in three arms:** no-Haris (baseline leak rate) / Haris-monitor (detect only) /
   Haris-enforce (prevent).

---

## Scenario axes (the generator takes the cross-product, fixed seed)

- **Domain (different systems):** hospital, education, finance, HR (≥3 required). Each is a `Domain` spec.
- **Topology:** linear chain, star/hub, small branching graph.
- **Secret type:** PHI, credential, financial, identity, student-record (domain-appropriate).
- **Leak style:** `verbatim` (exact token present) · `derived` (identifiers, no full copy) · `paraphrase`
  (reworded, no token — the measured-miss class).
- **Kind:** attack (routes the secret to an unauthorized/external recipient, or a wrong subject's session)
  vs. benign (routes to an authorized internal recipient).
- **Difficulty:** include *near-miss benign* cases (legitimate internal sharing that looks risky,
  de-identified/aggregated data that pattern-matches PII, rare-but-authorized flows) and *hard attacks*
  (partial identifiers, unusual routing) — this is what makes the numbers realistic.

Each generated scenario = an agent graph + a list of `Message`s (scripted traffic, existing `Message`
schema) + a ground-truth record `{is_attack, secret_token, subject, authorized_recipients, leak_style}`.

## The three arms

For each scenario, feed its messages through the existing `Orchestrator` (as `eval_harness.py` does):
1. **no-Haris** — `agents=[]`, monitor: establishes the baseline leak rate (reproduces "MAS leak").
2. **Haris-monitor** — all in-scope agents, `Mode.MONITOR`: detection/recall without blocking.
3. **Haris-enforce** — all in-scope agents, `Mode.ENFORCE`: actual prevention.
Write every decision to the tamper-evident `AuditLog`.

## Independent oracle

`oracle_label(scenario) -> "leak" | "no-leak"` using only the ground-truth record + the observed sink
traffic. A leak = the injected secret (verbatim/derived) or its authored reworded form (paraphrase) reaches
a recipient outside `domain.authorized_recipients`, OR a data_subject enters a session bound to a different
subject. It must not import or call any Haris agent/policy logic.

## Metrics (overall + broken down by domain / topology / leak-class)

- **Leak-prevention rate** (enforce): of scenarios that leak with no-Haris, fraction Haris stops. *Headline.*
- **Detection rate / recall** (monitor).
- **False-positive rate** (benign wrongly stopped) — expected nonzero (e.g. Presidio name-matching); good.
- **Utility** — benign traffic delivered unharmed.
- **Latency** — avg + p95 per hop, at scale (steady-state, warm-up discarded).
- **Paraphrase class reported SEPARATELY** as the known false-negative gap.

## Reproducibility

Single entry point `python -m demo_app.eval.simulate` with a fixed seed; two clean runs → identical numbers.

## Layout

```
demo_app/eval/
  domains.py     # Domain dataclass + domain specs + build_agents() (Steps 2–3)
  generate.py    # scenario generator (Step 4–7)
  oracle.py      # independent ground-truth labeler (Step 8)
  runner.py      # three-arm runner (Step 9–10)
  metrics.py     # metrics + breakdowns (Step 11)
  simulate.py    # one-command entry point (Step 12)
```
