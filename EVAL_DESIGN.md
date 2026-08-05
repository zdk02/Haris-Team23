# Haris — Simulation-Based Evaluation: Design & Results

**Status: authoritative description of the evaluation harness as built. Read before touching
eval code.** (Supersedes the initial plan-time draft; this reflects the shipped code.)

The Phase-3 evaluation was a *curated 9-case set on one app* (`demo_app/hospital/eval_harness.py`):
it proves each mechanism fires, but not generalization. This harness replaces that with a
**generated evaluation over many different multi-agent systems**, producing a credible, measured
claim: *unguarded multi-agent systems leak, and Haris measurably reduces that leakage across
systems it was never hardcoded for.*

One command runs everything, reproducibly:

    python -m demo_app.eval.simulate               # print the report (Presidio off, fixed seed)
    python -m demo_app.eval.simulate --secrets     # add the Presidio Secrets/PII agent
    python -m demo_app.eval.simulate --json out.json   # also export metrics for the report

---

## Locked decisions (do not deviate)

1. **Generate many DIFFERENT systems, not more hospital cases.** Hospital is the fully-wired
   reference app; education, finance, HR are *distinct* systems the generator produces.
2. **We specify domains + secret/leak recipes; the generator automates the rest** — secret
   values, scenario combinations, message traffic, labels, runs, scoring.
3. **Haris is app-agnostic already.** A new domain is run by passing its config (trust boundary,
   authorization allow-list, source data type, tokens) into the existing agents — no agent is
   forked or rewritten per domain (`demo_app/eval/domains.py::build_agents`).
4. **The ground-truth oracle is independent of Haris.** It labels leak/no-leak from injected
   facts + traffic, never from Haris's decision. It is allowed to be *more thorough* than Haris
   (e.g. normalized matching) — that is what independent ground truth means.
5. **We do NOT target 100% detection / 0% false positives.** A deliberate difficulty spectrum
   plus per-class breakdowns make the numbers high but realistic, with visible, explainable edges.
6. **Two honest "measured-miss" classes, no new defense built:**
   - **Semantic paraphrase** — reworded, no exact token. Ground truth by construction (we author
     it). Haris misses it → motivates the future semantic agent (out of scope).
   - **Trivial obfuscation** — a reformatted identifier (`MRN-4821` → `MRN - 4821`). The oracle
     catches it via normalized matching; Haris's exact-match taint misses part of it → shows the
     detector's brittleness and motivates a normalization/semantic upgrade.
7. **The core evaluation is fully deterministic — no LLM judge.** Secrets are synthesized with
   **Faker (seeded)**, following the source paper's method. The only LLM judge is the optional
   real-LLM realism slice (future work).
8. **Every scenario runs in three arms:** no-Haris (baseline) / monitor (detect) / enforce (prevent).

---

## Scenario axes (generator takes the cross-product; fixed seed = 23)

- **Domain:** hospital, education, finance, hr (`domains.py`).
- **Topology:** chain, star, branch.
- **Leak style:** verbatim · derived · obfuscated · paraphrase · credential · none.
- **Kind:** attack (secret → unauthorized/external recipient, or wrong-subject session) vs benign.
- **Variants:** 2 per combination → **312 scenarios** (192 attacks, 120 benign).

Each scenario = an agent graph + a list of `Message`s (scripted traffic, frozen `Message` schema)
+ a ground-truth record `{is_attack, injected secret + identifiers, subject, authorized_recipients,
leak_style, leak_occurred}`.

### Families (each exercises a specific agent / limitation)

| Family | Kind | Exercises | Expected |
|---|---|---|---|
| external_verbatim | attack | Info-flow taint (+ Secrets/PII) | caught |
| external_derived | attack | Info-flow taint | caught |
| external_credential | attack | Secrets/PII (+ taint) | caught |
| policy_egress | attack | Authorization (sensitive type → external) | caught |
| subject_mismatch | attack | Subject-binding (patient-A vs B) | caught |
| spoof | attack | Identity (missing token) | caught |
| **external_obfuscated** | attack | reformatted id vs exact-match taint | **partly caught (hard)** |
| **external_paraphrase** | attack | (no in-scope defense) | **missed (the gap)** |
| internal_derived / internal_clean | benign | — | allowed |
| near_miss_benign | benign | looks sensitive, stays internal | allowed |
| same_subject | benign | subject-binding negative control | allowed |
| **authorized_external** | benign | coarse trust boundary | **wrongly stopped (FP source)** |

## The three arms

For each scenario, feed its messages through the existing `Orchestrator` (as `eval_harness.py`
does): (1) no-Haris `agents=[]` monitor → baseline; (2) all agents `MONITOR` → detection;
(3) all agents `ENFORCE` → prevention + latency (written to the tamper-evident `AuditLog`).
Presidio is off by default (Info-flow's structured taint carries verbatim/derived/credential),
so the run is deterministic and dependency-free.

## Independent oracle (`oracle.py`)

`oracle_should_stop(scenario) -> (bool, method)`, using only injected facts + traffic:
cross-subject (two subjects in one session) · bad-token (missing/wrong token vs the known
registry) · identifier-egress (a known identifier reaches an unauthorized recipient, **exact or
normalized** — the normalized check catches the obfuscated class) · else paraphrase-by-construction.
Verified: it reproduces **all 312 labels**, **92% from traffic**; only paraphrase relies on
construction.

## Metrics (`runner.py` + `simulate.py` JSON export)

Overall and broken down by **leak-style / domain / topology / family**: leak-prevention (enforce),
detection (monitor), false-positive (benign wrongly stopped), utility (benign delivered unharmed),
latency (avg + p95 per hop).

## Results snapshot (Presidio off, seed 23)

    scenarios 312 (attacks 192 · benign 120)
    leak-prevention 80% · detection 80% · false-positive 20% · utility 80% · ~0.1 ms/hop

    by leak style : verbatim/derived/credential 100% · obfuscated 42% · paraphrase 0%
    by domain     : hospital 83 · finance 81 · hr 79 · education 77  (consistent = generalization)
    by topology   : chain 83 · branch 80 · star 78  (near-flat: Haris mediates per hop)
    false positives confined to authorized_external (coarse internal/external boundary)

Honest reading: high where Haris is designed to be strong; two documented gap classes (semantic
paraphrase, trivial obfuscation); false positives limited to one explainable class. The aggregate
rates depend on the family mix, so the **per-class breakdowns are the real result**.

## Layout

    demo_app/eval/
      domains.py     # Domain dataclass + specs + build_agents() (per-domain config)
      generate.py    # scenario generator: families, Faker secret injection, leak styles
      oracle.py      # independent ground-truth labeler (exact + normalized)
      runner.py      # three-arm runner + metrics/breakdowns
      simulate.py    # one-command entry point + JSON export

## Deferred / future work

Real-LLM realism slice (a few LLM-driven scenarios + an independent LLM judge); the semantic agent
that would close the paraphrase (and harden the obfuscation) gap; enabling Presidio in CI for the
Secrets/PII contribution and a realistic (~11 ms) latency figure.
