# Haris — Simulation-Based Evaluation: Design & Results

**Status: authoritative description of the evaluation harness as built. Read before touching
eval code.** Last reconciled with the code on 2026-08-26.

The Phase-3 evaluation was a *curated 9-case set on one app* (`demo_app/hospital/eval_harness.py`):
it proves each mechanism fires, but not generalization. This harness replaces that with a
**generated evaluation over many different multi-agent systems**, compared against non-Haris
baselines, producing a claim that can be checked: *lineage-aware mediation catches violations
that metadata checks and content scanning cannot, and costs something measurable in return.*

One command runs everything, reproducibly:

    python -m demo_app.eval.simulate               # print the report (Presidio off, fixed seed)
    python -m demo_app.eval.simulate --secrets     # add the Presidio Secrets/PII agent
    python -m demo_app.eval.baselines              # the four-arm comparison
    python -m demo_app.eval.latency                # mediation cost, with a floor arm
    python -m demo_app.eval.seed_sweep             # seed sensitivity

**Numbers live in `report/RESULTS.md`, not here.** This document describes the design; that one
records what it measured, with every figure traceable to a command. A results block inside a
design document goes stale the moment either changes — which is exactly what happened to the
one that used to sit at the bottom of this file.

---

## Locked decisions (do not deviate)

1. **Generate many DIFFERENT systems, not more hospital cases.** Hospital is the fully-wired
   reference app; education, finance, HR are *distinct* systems the generator produces.
2. **We specify domains + secret/leak recipes; the generator automates the rest** — secret
   values, scenario combinations, message traffic, labels, runs, scoring.
3. **Haris is app-agnostic already.** A new domain is run by passing its config (trust boundary,
   authorization allow-list, source data type, tokens, partner agreements) into the existing
   agents — no agent is forked or rewritten per domain (`demo_app/eval/domains.py::build_agents`).
4. **The generator constructs ground truth; the check confirms the traffic realises it.**
   `oracle.py` re-derives each label from the generated traffic and never consults Haris's
   decision. It is NOT independent adjudication: it reads the same facts the generator wrote,
   using checks that mirror Haris's own agents, and it cannot disagree on a corpus the generator
   built correctly. Call it a *label consistency check*. Genuine third-party confirmation is
   bought separately — `external_check.py` runs `detect-secrets` over the egress traffic and
   confirms the credential-shaped subset only; it has no opinion on names, record ids or
   diagnoses. A small honest number, not a large dishonest one.
5. **Compare against something.** Until 2026-08-24 every number was Haris measured against
   itself, which answers "does Haris catch the attacks we wrote" and not "did anyone need
   Haris". `baselines.py` adds three non-Haris arms scored by the identical rule. The first
   run of it showed a six-line metadata heuristic matching Haris on prevention and beating it
   on false positives — the corpus was separable by metadata alone and could not distinguish
   lineage from a trivial rule. That finding drove task K.
6. **We do NOT target 100% detection / 0% false positives.** A rate of 100% is a statement
   about the corpus. Where the corpus contains no case a defence fails, say so rather than
   reporting the number as a property of the defence.
7. **The core evaluation is fully deterministic — no LLM judge.** Secrets are synthesized with
   **Faker (seeded, 23)**, following the source paper's method. `generate(seed=…)` exists so the
   result can be checked for seed sensitivity, not so numbers can be shopped for.
8. **Every scenario runs in two arms:** monitor (detect) / enforce (prevent). The former
   third arm — `agents=[]` in monitor mode — could not stop anything, so its output was a
   constant rather than a baseline; it was removed and replaced by a measured leak metric. An
   empty agent list IS used as a legitimate denominator in `latency.py`, where the quantity
   being measured is time and time is spent either way.

---

## Scenario axes (generator takes the cross-product; fixed seed = 23)

- **Domain:** hospital, education, finance, hr (`domains.py`).
- **Topology:** chain, star, branch.
- **Record format:** structured `Key: value`, JSON payload, clinician's narrative, chat
  transcript, forwarded email thread — rotated across every family (task N2).
- **Egress phrasing:** four per leak style, rotated by position (task N2).
- **Kind:** attack vs benign.
- **Variants:** 2 per combination → **576 scenarios** (384 attacks, 192 benign), 24 families
  of 24.

Each scenario = an agent graph + a list of `Message`s (scripted traffic, frozen `Message`
schema) + a ground-truth record: the injected secret and its identifiers, every subject whose
record it injects, any identifier written in a transformed form, and the partner agreements in
force.

### Why the format and phrasing axes exist

Before task N, every record was a `Key: value` block — which is exactly what the info-flow
fallback parses — and every scenario of a given leak style carried the same sentence. So the
corpus was written in the shape the detector expects, and could not have detected sensitivity
to wording.

Measured with a controlled probe (`record_format`, identical egress hop across five source
shapes): structured 100%, JSON 100%, **narrative 0%, chat 0%**. Half of the realistic formats
were unparseable and the headline rate was conditioned on the one we happened to author. The
parser was widened rather than the finding documented — a prose extractor for identifier-shaped
tokens, credential-shaped runs and capitalised name runs, plus content binding that reads a
subject named in text as well as bracketed. All five formats now score 100%, and that family
remains as the regression guard.

The phrasing axis came out flat: four different sentences, identical rates, golden unchanged.
That is the "survives the summarizer rewriting everything" claim made falsifiable, and it
passed.

### Families

Twenty-four, grouped by what they exercise. Full behaviour per family is in
`golden_rates.json`; the tests named beside each hold the claim.

**Exfiltration — an identifier reaches an address outside the trust boundary**

| Family | Exercises | Result |
|---|---|---|
| external_verbatim / external_derived | info-flow taint | caught |
| external_credential | Secrets/PII + taint | caught |
| policy_egress | authorization (sensitive type → external) | caught |
| external_obfuscated | six-rung encoding ladder | layout caught, encodings not |
| external_paraphrase | the semantic ceiling | missed (Presidio recovers most) |
| rewrite_chain | cumulative degradation across five hops | falls at the last level |
| deep_chain | 2–8 hops, identifier resurfacing at the end | caught at every depth |
| stored_then_forwarded | parked with no recipient, then forwarded | redacted at the store |
| split_identifier | one identifier across two messages | **missed — see below** |
| record_format | five source shapes, identical egress | caught in all five |

**Boundary crossings — a violation with nothing leaving the system**

| Family | Exercises | Result |
|---|---|---|
| subject_mismatch | session binding | caught |
| subject_forgery | content binding: payload contradicts its own label | caught; **no baseline sees it** |
| partner_scope_violation | agreement scoped per data subject | caught; **no baseline sees it** |
| spoof | identity (missing token) | caught |
| forged_session_scope | an attacker writing their own session scope | **missed by design — see below** |

**Benign**

| Family | Why it is hard | Result |
|---|---|---|
| internal_derived / internal_clean / same_subject | controls | allowed |
| authorized_external | a real record leaving the boundary under a referral agreement | allowed |
| multi_subject_workflow | a ward round: traffic identical to an attack | allowed |
| public_reference | a bulletin quoting a value that IS a taint tag | allowed |
| near_miss_benign | a form template: identifier-shaped, owned by nobody | allowed; **both baselines refuse it** |
| internal_handoff | an agent-to-agent summary with no declared recipient | **refused — the false positive we keep** |

## The arms

Four, over the same corpus, scored by the same rule (`baselines.py`):

- **no defence** — delivers everything. Pins the denominator.
- **content scanner** — per-message inspection at egress: detect-secrets plus
  identifier-shaped regexes. No session state. The "existing guardrail" the thesis is about.
- **metadata heuristic** — the six lines from finding 01: recipient authorised, token present,
  one data subject. Never reads content.
- **Haris** — lineage-aware mediation, ENFORCE.

The comparison is the result, not any single rate. The metadata heuristic **beats Haris on
exfiltration** — a rule that never reads content cannot be defeated by rewriting content — and
scores **zero on boundary crossings**, where Haris takes all of them. It also carries twice the
false-positive rate, because it refuses the partner referral and the form template that Haris
allows. Reading payloads is what buys those, and reading payloads is what encoding defeats.

**Fairness of the baselines, stated because it favours us:** the scanner has no NER, since
Presidio is Haris's own detector and lending it would make the comparison circular. It also
inspects egress only — scanning internal hops would flag the legitimate source read in every
scenario. Both are the charitable reading and both are documented in `baselines.py`.

## The leak metric (`leak_check.py`)

Outcome-based, and independent of every detector's verdict. A scenario leaks when, in what an
arm actually **delivered**:

1. **recipient** — content reaching an unauthorised recipient still carries an injected
   identifier;
2. **subject** — an identifier belonging to subject X appears in a message declared about
   subject Y, wherever it was addressed;
3. **scope** — an identifier belonging to X reaches a partner whose agreement does not cover X.

Rules 2 and 3 were added because rule 1 could not express those threat classes at all: an
authorised recipient can never register as a leak under it, so "internal recipient, wrong data
subject" was unscoreable rather than merely hard. Each was verified additive — firing on no
family that existed before it — and that null result is the evidence the metric was extended
rather than tuned.

**Two identifiers are deliberately NOT scored.** The `fact` (a condition, an account status)
is a statement about the world as much as about a person and appears in guidance that
identifies nobody. The `subject` label is a pseudonymous session key that means nothing outside
the system. Both exclusions cost us on paper — the second alone moved exfiltration prevention
from 66% to 73% — and both are corrections, not conveniences. A deployment whose subject key IS
an identifier must keep it in scope; that is a configuration note.

**Why outcome-based matters.** Four scenarios are `stopped=True` and still leak: redaction is a
*change* guard rather than a completeness guard, so a message carrying two identifiers where
only one is recognised ships partially scrubbed and the verdict reads "redacted". A
verdict-based metric would have scored all four as successes.

## Label consistency check (`oracle.py`)

`label_consistency_check(scenario) -> (bool, method)`, using only injected facts + traffic:
cross-subject · bad token · subject forgery · partner scope · identifier egress (exact or
normalised). Every family but one is labelled **from traffic**.

The exception is `forged_session_scope`, and it cannot be otherwise: its traffic is
byte-for-byte identical to a legitimate ward round, because the attacker wrote a declaration
that looks exactly like a true one. `external_paraphrase` used to sit here too and no longer
does — task M3 gave it identifiers a check can find.

Agreement with the generator is *not* evidence the check works. What establishes something is
`tests/test_label_check_mutation.py`: it defuses one attack property at a time and asserts the
label flips. A check that can fail is worth something; one that cannot is decoration. That
suite is what caught the paraphrase family still returning "attack" after every identifier was
stripped out of it.

## Metrics (`runner.py`, `stats.py`)

**Two headline claims, two denominators.** Exfiltration prevention over the scenarios where an
identifier reaches an outside address; boundary-crossing prevention over the violations where
nothing leaves the system. Reported apart because a reader hearing "leak prevention"
understands the first, and pooling them lets a combined figure hide that the two point in
opposite directions across arms.

**Every rate carries a 95% bootstrap interval.** Percentages computed from 4 observations and
from 264 were being printed in the same format. Degenerate samples fall back to the rule of
three, because a naive bootstrap reports [0-0] for a family it only ever saw fail. Rungs whose
interval is too wide to quote are flagged in the output.

**The ladders are reported as shapes, not values.** At n=4 per rung the intervals span most of
the range; what the obfuscation ladder shows is the ORDER — layout changes recovered by
normalisation, encodings not — and what the rewrite chain shows is which identifier detection
was resting on. Both are in `report/RESULTS.md`.

**Latency has its own harness** (`latency.py`): a no-agents floor arm, one warm-up scenario per
family, three repetitions, median with IQR, and the CPU printed. The runner's by-product
latency figure had none of that and should not be quoted. Building it properly surfaced a real
defect — both PII-consuming agents were constructing their own detector per scenario, and a
cold `analyze()` costs 1686 ms against 4.4 ms warm, so every Presidio latency figure the project
had produced was measuring model initialisation.

## Seed sensitivity (`seed_sweep.py`)

Changing the seed redraws every name, record id and credential while leaving the structure of
every family identical. Across seeds 23–27 the Presidio-OFF rates are invariant, which is
expected — the structural checks do not read names — and means the reported numbers are not an
artefact of one draw. It says nothing about generalisation, and the module says so. With a
single seed it reports UNKNOWN rather than "invariant", because a spread computed from one
sample is zero by construction.

## Layout

    demo_app/eval/
      domains.py        # Domain dataclass + specs + build_agents(); one shared PIIDetector
      generate.py       # scenario generator: families, formats, phrasings, ladders
      oracle.py         # label consistency check
      leak_check.py     # outcome-based leak metric: recipient, subject, scope
      external_check.py # third-party confirmation via detect-secrets
      baselines.py      # the three non-Haris arms + the four-arm comparison
      stats.py          # bootstrap confidence intervals
      latency.py        # mediation cost with a floor arm (task O3)
      seed_sweep.py     # seed sensitivity
      golden.py         # per-family regression guard (golden_rates.json)
      figures.py        # report figures, drawn as SVG from the harness
      runner.py         # the two Haris arms + metrics and breakdowns
      simulate.py       # one-command entry point + JSON export

## Known limits

- **The corpus is authored by us.** Every rate bounds performance on the threat classes we
  modelled. That limit applies to all four arms equally, which is why the differences between
  them carry more weight than any single figure.
- **`split_identifier` is an architectural limit, not a threshold.** Lineage records what a
  session read and whether it resurfaces, not whether fragments across messages compose.
  Closing it needs the matcher to consider a session's egress traffic jointly, which is a
  different design. It is the one attack family where a baseline beats Haris.
- **`forged_session_scope` is the price of honouring a declared scope.** `session_scope` is
  sender-supplied, and THREAT_MODEL.md §2.3 treats that whole class as attacker-controllable.
  The remedy is binding the field at the interception adapter, as E1/E2 did for `receiver` —
  deployment work, not agent work.
- **`internal_handoff` is a false positive we keep.** Relaxing `flag_unknown_destination` would
  let an attacker disable egress control by removing one metadata key. Binding `recipient` at
  the adapter removes the cost without giving up the property; a test demonstrates it.
- **Partial redaction.** Four scenarios ship with one identifier scrubbed and another intact,
  and the verdict reads "redacted".
- **The encoding rungs are unfixed.** Homoglyphs and HTML entities render as the original
  identifier to a human reviewer, which is worse than a silent miss. NFKD normalisation plus
  confusable folding would address them.

## Deferred / future work

Real-LLM realism slice (LLM-driven scenarios + an independent LLM judge); the semantic agent
that would close the paraphrase gap without Presidio; a multi-seed Presidio-ON sweep to
quantify NER recall variation (finding PA-3: non-Anglo surnames are recognised less reliably);
and benign traffic we did not author, which is the single largest improvement available to the
false-positive claim.

**A note on what used to be in this section.** It listed base64 encoding, split identifiers and
homoglyph obfuscation as evasions we would name rather than score, on the grounds that their
ground truth would rest on construction and dilute the traffic-verified proportion. All three
are now built and measured — the generator declares the transformed form as an identifier, so
the metric can see a leak the naive identifier list would miss, and the label still derives
from traffic. The original reasoning was wrong in a way worth recording: "we cannot score this
without weakening our independence" turned out to mean "we had not worked out how to score it".
