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
4. **The generator constructs ground truth; the check confirms the traffic realises it.**
   `oracle.py` re-derives each label from the generated traffic and never consults Haris's
   decision. It is NOT independent adjudication: it reads the same facts the generator wrote,
   using checks that mirror Haris's own agents, and it disagrees with the generator **0 times
   out of 312**. Call it a *label consistency check*. Genuine third-party confirmation is
   bought separately — `external_check.py` runs `detect-secrets` over the egress traffic and
   confirms **24 of 312** labels (credential-shaped secrets only; it has no opinion on names,
   record ids or diagnoses). A small honest number, not a large dishonest one.
5. **We do NOT target 100% detection / 0% false positives.** A deliberate difficulty spectrum
   plus per-class breakdowns make the numbers high but realistic, with visible, explainable edges.
6. **Both former "measured-miss" classes turned out not to be what we claimed.** Recorded here
   rather than quietly dropped:
   - **Trivial obfuscation** — was 42% caught, presented as a difficulty tier. It was our
     matcher being brittle, not the attack being hard. Normalising both sides took it to 100%
     (`report/evidence/eval_before_C1.txt` vs `eval_after_C1.txt`). It is no longer a tier;
     a graded ladder is task M2.
   - **Semantic paraphrase** — presented as the honest ceiling. Measured 2026-08-24: those 24
     messages carry **no injected identifier at all**, so a correct detector *should* pass
     them. It was an empty test scored as a failure, not a ceiling. Task M3 replaces it with
     paraphrases that genuinely retain the secret.
7. **The core evaluation is fully deterministic — no LLM judge.** Secrets are synthesized with
   **Faker (seeded)**, following the source paper's method. The only LLM judge is the optional
   real-LLM realism slice (future work).
8. **Every scenario runs in two arms:** monitor (detect) / enforce (prevent). The former
   third arm — `agents=[]` in monitor mode — could not stop anything, so its output was a
   constant rather than a baseline; it was removed and replaced by a measured leak metric.

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

## The arms

For each scenario, feed its messages through the existing `Orchestrator`:
(1) all agents `MONITOR` → detection; (2) all agents `ENFORCE` → prevention + latency
(written to the tamper-evident `AuditLog`). Presidio is off by default, so the run is
deterministic and dependency-free.

**There is no "no-Haris" arm.** The old one ran `agents=[]` in monitor mode, which cannot
stop anything — `most_restrictive([])` is ALLOW and monitor clamps above FLAG regardless — so
its "100% of attacks leak" was fixed before the run started.

The reference point is now **measured** instead (`leak_check.py`): a scenario *leaks* when
content reaching an unauthorised recipient still carries an injected identifier. The same rule
scores every arm, so success means "the secret did not arrive" rather than "a detector said
block". Measured on the untouched traffic: **120 of 192** attack scenarios leak — not 192.
48 name no external recipient at all (policy violations, nothing egresses) and 24 carry no
identifier to leak.

## Label consistency check (`oracle.py`)

`label_consistency_check(scenario) -> (bool, method)`, using only injected facts + traffic:
cross-subject (two subjects in one session) · bad-token (missing/wrong token vs the known
registry) · identifier-egress (a known identifier reaches an unauthorized recipient, **exact or
normalized** — the normalized check catches the obfuscated class) · else paraphrase-by-construction.
It re-derives **all 312 labels**, **92% from traffic**; only paraphrase rests on construction.

That agreement is *not* evidence the check works — it reads the facts the generator wrote, so
it cannot disagree on a corpus the generator built correctly. What does establish something is
`tests/test_label_check_mutation.py`: it defuses one attack property at a time (redirect the
egress to an authorised address, strip the identifiers, supply the correct token, collapse two
subjects into one) and asserts the label flips, plus one test planting a secret into benign
traffic and asserting it flips the other way. A check that can fail is worth something; one
that cannot is decoration.

## Metrics (`runner.py` + `simulate.py` JSON export)

Overall and broken down by **leak-style / domain / topology / difficulty / family**:
leak-prevention (enforce), detection (monitor), false-positive (benign wrongly stopped),
utility (benign delivered unharmed), latency (avg + p95 per hop).

**Difficulty gradient (data-exfiltration threat).** A derived axis over the exfiltration
attacks showing how detection degrades as the attacker hides the leaked identifier —
**easy** (`external_verbatim`, `external_derived`: exact token present) →
**medium** (`external_obfuscated`: identifier trivially reformatted) →
**hard** (`external_paraphrase`: semantically reworded, no literal token). This is an
*additive reporting view* — it re-groups existing scenarios, adds no new ones and changes
no numbers.

It was described here as a "graceful degradation curve (100% → 42% → 0%)" until 2026-08-24.
Both halves of that are now wrong, and the correction matters more than the numbers:

  * The 42% was **matcher brittleness, not attacker skill**. `external_obfuscated` only
    reformats the identifier (`MRN-0001` → `M R N 0 0 0 1`); once the info-flow matcher
    normalised separators, medium went to 100%. A "difficulty" axis that moves when you fix
    a bug in the detector was measuring the detector, not the attack.
  * The remaining 0% is not a hard tier either. Verified 2026-08-24: the `external_paraphrase`
    messages contain **no identifier at all**, so there is nothing present to leak. Scoring
    them as missed detections invents a weakness.

So the honest shape is **100% · 100% · 0%** — a cliff at a family that carries no secret,
not a curve. Keep the axis for the reporting view, but do not read it as evidence that Haris
degrades gracefully under obfuscation; the corpus contains no attack it fails to stop. Task K
(attack families a metadata heuristic cannot catch) is what would give this axis real hard
cases, and only then does "motivates the semantic agent" mean anything.

## Results snapshot (Presidio off, seed 23)

**Regenerate this block whenever the numbers move** — `python -m demo_app.eval.simulate`.
It was last stale for two days after the normalisation fix, still quoting 80% / 42% and a
per-domain spread that no longer existed, which is precisely the failure mode the rest of
this document is about. Current, verified 2026-08-24:

    scenarios 312 (attacks 192 · benign 120)

    corpus (measured, not asserted):
      144 of 192 attack scenarios address anything outside at all
      120 of 192 actually leak with no mediation — 48 never egress, 24 carry no identifier

    leak prevention 120/120 = 100% of the scenarios that actually leak
    (verdict-based 168/192 = 88%, a denominator containing 72 that cannot leak)
    detection 88% · false-positive 20% · utility 80% · ~0.1 ms/hop structured-only

    by leak style : verbatim/derived/credential/obfuscated 100% · paraphrase 0%
    by domain     : hospital / finance / hr / education all 88 · 88 · 20
    by topology   : chain / branch / star all 88 · 88 · 20
    by difficulty : easy 100% · medium 100% · hard 0%  — a cliff, not a curve
    false positives confined to authorized_external (a partner never configured; task I2)

**Honest reading, and it is not flattering.** Haris prevents every leak that actually
occurs in this corpus. That is a statement about the corpus, not about Haris: nothing in
312 scenarios defeats it, so the evaluation cannot show where it breaks. The per-domain and
per-topology spreads that used to look like evidence of generalisation were Faker
coin-flips; they are now identical across every cell, which is what "the axis measures
nothing" looks like. Tasks K and L (attack families a metadata heuristic cannot catch, and
reference arms to compare against) are what would make these numbers mean something.

The aggregate rates depend on the family mix, so the **per-class breakdowns are the real result**.

## Layout

    demo_app/eval/
      domains.py     # Domain dataclass + specs + build_agents() (per-domain config)
      generate.py    # scenario generator: families, Faker secret injection, leak styles
      oracle.py         # label consistency check (exact + normalized)
      leak_check.py     # outcome-based leak metric, independent of any detector
      external_check.py # third-party confirmation via detect-secrets
      golden.py         # per-family regression guard (golden_rates.json)
      runner.py      # two Haris arms (monitor/enforce) + the measured unmediated
                     #   reference, plus metrics and breakdowns
      simulate.py    # one-command entry point + JSON export

## Deferred / future work

Real-LLM realism slice (a few LLM-driven scenarios + an independent LLM judge); the semantic agent
that would close the paraphrase (and harden the obfuscation) gap; enabling Presidio in CI for the
Secrets/PII contribution and a realistic (~11 ms) latency figure.

Additional evasion techniques Haris does not yet handle — named here as future work rather than
scored, because their ground truth would rely on construction (no literal token survives), which
would dilute the eval's ~92% traffic-verified independence: **encoded** identifiers (base64/hex),
identifiers **split across messages**, and **homoglyph/zero-width** obfuscation. A normalization +
reassembly pre-pass on the info-flow agent would address these; they'd extend the "hard" tier of
the difficulty gradient.