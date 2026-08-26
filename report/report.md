# Haris — Real-Time Security Middleware for Multi-Agent AI Systems

**Team Haris · Amazon Mentorship Program · American University of Beirut**
Submission: 31 August 2026

---

> **How to use this file.** Every section below is a stub with (a) what belongs in it,
> (b) where the source material already exists, and (c) an owner and a status. Sections are
> independent — pick any one marked TODO and write it. Delete the `> NOTE:` blocks as you
> fill each section in.
>
> **Status key:** TODO · DRAFT · DONE
>
> **One rule:** every number in this report must be reproducible by a command we can name
> next to it. If we cannot name the command, the number does not go in.

---

## Abstract

**Owner:** — **Status:** TODO *(write this LAST)*

> NOTE: 150–200 words. Problem, our approach, the headline evaluation result with its
> baseline comparison, and the honest limitation. Write it after the evaluation section is
> final, never before.

---

## 1. Introduction — problem and motivation

**Owner:** **Status:** TODO

> NOTE: Source material is Intro deck slides 2–5 and the plan's §1.
> Cover, in order:
> - Applications are moving from one model to teams of specialised agents that exchange
>   messages and act autonomously, with no human watching each internal exchange.
> - The risk is not inside one agent — it is in the channel between them: data and secret
>   leakage, unauthorised behaviour, injected instructions travelling between agents.
> - Existing guardrails (Bedrock Guardrails, NeMo Guardrails) filter one agent's input and
>   output in isolation. They hold no model of the communication graph, the relationships
>   between agents, or the history of how data has moved.
> - Grounding: the source paper on multi-agent privacy leakage; MAScope (per-message
>   guardrails miss cross-agent attacks); G-Safeguard (model agent interaction as a graph);
>   BreachSeek (multi-agent systems automate offensive security).
> - Contribution statement — say plainly what is new here: relationship awareness (rules per
>   sender/receiver pair) and trajectory awareness (provenance across hops), plus a measured
>   evaluation against reference baselines rather than a claim.

### 1.1 Contributions

> NOTE: Four to six bullets, each one falsifiable and each one pointing at the section that
> demonstrates it.

---

## 2. Threat model

**Owner:** **Status:** TODO

> NOTE: Source is `THREAT_MODEL.md`, refreshed. Present as threat → mechanism that answers
> it → the staged attack that demonstrates it. Problems A–F (direct leak, hidden/derived
> leak, wrong recipient, mixed subjects, hidden instructions [roadmap], spoofed identity).
>
> **Do not omit §2.3.** It is the section a security reviewer will look for, and having
> written it ourselves is worth more than any fix we could ship in nine days.

### 2.1 Assets, adversary, and scope

### 2.2 Threats and how Haris answers them

### 2.3 Trust boundary and stated assumptions

> NOTE: State explicitly that Haris trusts the interception adapter to supply `session_id`,
> `sender` and `recipient` from the transport rather than from the message body. Where an
> application allows a compromised agent to set these itself, the corresponding checks are
> bypassable. Binding these at the adapter is the deployment-era requirement. Name it; do
> not bury it.

### 2.4 Protecting Haris itself

> NOTE: Minimise what it holds (hash references; blocked content never retained), keyed
> hash chain, deterministic detectors so inspected content cannot prompt-inject Haris,
> operator-gated dashboard. Be precise about what the chain does and does not resist —
> see §8.

---

## 3. System design

**Owner:** **Status:** TODO

> NOTE: Source is Phase 3 deck slides 5–13. Include the high-level design AND the low-level
> six-step message pipeline (the deck dropped the low-level slide for time; the report has
> room for it).

### 3.1 Architecture overview

### 3.2 The message pipeline — intercept, context, check, resolve, enforce, record

### 3.3 The security agents

> NOTE: One subsection each, and for each one give the **technique**, not just the name:
> what it does, why that design, what it catches, and what it structurally cannot catch.
> - Secrets & PII — Presidio (spaCy NER) + detect-secrets, boundary-aware
> - Authorization — deterministic relationship table, allow-list by default, egress control
> - Information-flow — taint over a lineage graph; **state the matching mechanism honestly**
>   (normalised token matching after the Aug 22 fix; note what the previous exact-substring
>   version missed and that this is measured in §6)
> - Subject-binding — instance-level authorisation, session bound to its first data-subject
> - Identity — per-agent bearer token, constant-time compare; no anti-replay (see §8)

### 3.4 The policy engine

> NOTE: The four rules in order — threshold, most-restrictive-wins, union of redaction
> spans, mode gate. Explain why the mode gate is last.

### 3.5 Product shape — library, service, dashboard

---

## 4. Reliability, logging, audit, and notification

**Owner:** **Status:** TODO

> NOTE: This section is where the non-functional requirements live. Source: Phase 3 tasks
> 2, 5, 7 and the Phase 4 notification workstream.

### 4.1 Failure semantics — fail-open in monitor, fail-closed in enforce

> NOTE: Be precise about coverage: the guard wraps agent execution. State what it does not
> yet wrap.

### 4.2 Two-tier logging — operational vs security-audit

### 4.3 The audit log

> NOTE: Append-only, hash-chained, keyed with HMAC; content stored as a SHA-256 reference;
> blocked content never retained. Say exactly which tampering this detects and which it does
> not (a keyed chain resists silent rewrite and forged append; truncation is covered by the
> persisted head hash).

### 4.4 The notification system

> NOTE: Trigger taxonomy → Notifier → channels. De-duplication, severity routing, the single
> sanitisation choke point, per-channel failure isolation. CI: GitHub Actions on every push,
> failure notification, CODEOWNERS. Source: `NOTIFICATIONS.md`.

---

## 5. Deployment

**Owner:** **Status:** TODO

> NOTE: Reproducible build (pinned dependencies, Dockerfile, compose), the container
> hardening, AWS ECS/Fargate topology, the two scoped IAM roles, secret handling, the
> persisted audit volume, SES alerting. Include the architecture diagram. Policy JSONs and
> the task definition go in Appendix B — a grader reads "scoped IAM" as "show me the policy."

---

## 6. Evaluation

**Owner:** Zeinab **Status:** DRAFT

Every number in this section is reproducible by a named command. The full recorded set,
including the tables not reproduced here, is `report/RESULTS.md`; the raw output of each run is
in `report/appendix/`.

### 6.1 Method

**Why a generated corpus.** The Phase-3 evaluation was nine curated cases on one application.
It demonstrates that each mechanism fires, which is a different claim from the one this project
makes. A curated set also cannot answer the question a reviewer asks first — whether the
defence generalises beyond the system it was written against, or whether the cases were chosen
because they pass.

The harness generates **576 scenarios** from a declarative description of four multi-agent
systems. Each scenario is a list of messages in the frozen `Message` schema, together with a
ground-truth record of the injected secret and its identifiers. Generation is deterministic
under a fixed seed (23), so every figure in this report reproduces exactly.

**Domains.** Hospital, education, finance and HR (`demo_app/eval/domains.py`). A domain is
data, not code: agent roles, trust boundary, the sensitive source data type, per-role identity
tokens, and any data-sharing agreements. Every domain runs on the *same* agent classes as the
hospital reference application — no agent is forked or specialised per domain, which is the
concrete form of the app-agnostic claim in §3.

**Topologies.** Chain, star and branch, so the lineage graph differs in shape rather than only
in length.

**Content diversity.** The source record is written in one of five shapes — a structured
`Key: value` block, a JSON payload, a clinician's narrative note, a chat transcript, and a
forwarded email thread — rotated across every family. The egress message is written in one of
four phrasings per leak style. Both axes exist because of a specific failure described in
§6.4.4: without them, the corpus was written in the one format the detector's fallback parser
expects, and every scenario of a given style carried the same sentence.

**Families.** Twenty-four families of twenty-four scenarios, each exercising a specific
mechanism or a specific limitation. They divide by what the violation *is*:

- **Exfiltration** (264 scenarios) — an injected identifier reaches an address outside the
  trust boundary. Verbatim forwarding, derived references, credentials, obfuscated
  identifiers, semantic paraphrase, a rewrite chain, chains of two to eight hops, an
  identifier split across two messages, and a store-and-forward.
- **Boundary crossings** (48 scenarios) — a real violation where nothing leaves the system: one
  subject's record delivered into a session bound to another, or sent to a partner whose
  data-sharing agreement does not cover that person.
- **Policy violations with no leak path** (72 scenarios) — a forged sender, or a cross-subject
  session carrying nothing that could escape.
- **Benign** (192 scenarios) — including four cases built to be hard: a real patient record
  leaving the trust boundary under a legitimate referral agreement; a ward round whose traffic
  is byte-for-byte identical to a cross-subject attack; a staff bulletin quoting a value that
  is itself a taint tag; and a referral-form template carrying identifier-shaped values that
  belong to nobody.

**Secret injection.** Each scenario carries a synthetic secret generated with Faker under the
fixed seed, following the source paper's method: a name, a domain-appropriate record
identifier, a sensitive detail drawn from that domain's own pool, and a credential. Because the
values are known exactly, ground truth is deterministic and free — no LLM judge is involved in
any scored result.

**The arms.** Every scenario runs twice through the existing orchestrator: all agents in
MONITOR (detection) and all agents in ENFORCE (prevention and latency). Presidio is off by
default so the run is deterministic and dependency-free; §6.5 reports both configurations.

### 6.2 Ground truth and its limits

The generator constructs the labels. A separate check (`oracle.py`) re-derives each label from
the generated traffic — cross-subject, bad token, subject forgery, partner scope, identifier
egress — and never consults Haris's decision.

**This is a self-consistency check, not independent adjudication, and we do not describe it as
independent anywhere in this report.** It reads the same facts the generator wrote, using
checks that mirror Haris's own agents. On a corpus the generator built correctly it *cannot*
disagree, so agreement is not evidence that it works.

What establishes something is that the check can fail. `tests/test_label_check_mutation.py`
defuses one attack property at a time — redirects the egress to an authorised address, strips
the identifiers, supplies the correct token, collapses two subjects into one — and asserts the
label flips; a further test plants a secret in benign traffic and asserts it flips the other
way. A check that cannot fail is decoration. That suite is what caught the paraphrase family
still returning "attack" after every identifier had been removed from it.

**Independence is bought separately and it is small.** `external_check.py` runs `detect-secrets`
— a third-party tool with no knowledge of this project — over the egress traffic and confirms
the credential-shaped subset of labels. It has no opinion on names, record identifiers or
clinical details. We report that number as what it is: a small honest figure rather than a
large dishonest one.

**One family cannot be labelled from traffic at all.** `forged_session_scope` is byte-for-byte
identical to a legitimate multi-patient session, because the attacker writes a session-scope
declaration that looks exactly like a true one. Its label rests on construction, and that is
the finding rather than a shortcut: if no reading of the traffic can separate them, no detector
reading the traffic can either.

### 6.3 Reference baselines

Until late in the project every number was Haris measured against itself, which answers "does
Haris catch the attacks we wrote" and not "did anyone need Haris". Three non-Haris arms now run
over the identical corpus, through the identical orchestrator, policy engine and enforcement
path — only the detector differs, so the difference between arms is attributable to the
detector alone.

- **No defence** delivers everything and pins the denominator.
- **Content scanner** inspects each egress message in isolation: `detect-secrets` plus
  identifier-shaped regexes, with no session state. This stands for the class of guardrail that
  exists today.
- **Metadata heuristic** is six lines — recipient authorised, token present, one data subject —
  and never reads content. It is a **control, not a proposal**: it exists to establish how much
  of the result could be obtained without any of this project's machinery.

All four arms are scored by the same outcome rule (§6.4.1), so no arm can score well by being
confident.

**The first run of this comparison was unflattering and it changed the project.** The metadata
heuristic matched Haris on prevention and beat it on false positives. The corpus was separable
by metadata alone, which meant it could not distinguish lineage-aware mediation from a trivial
rule. That result is why the families in §6.1 exist.

**Fairness, stated because it favours us.** The content scanner has no named-entity detection,
since Presidio is Haris's own detector and lending it to the baseline would make the comparison
circular. It also inspects egress messages only; scanning internal hops would flag the
legitimate source read in every scenario. Both choices are the charitable reading and both are
documented in `demo_app/eval/baselines.py`.

### 6.4 Results

    python -m demo_app.eval.baselines    # the four-arm table
    python -m demo_app.eval.runner       # per-family, per-rung, per-format breakdowns

#### 6.4.1 What counts as a leak

A scenario leaks when, in what an arm actually **delivered**, an injected identifier reaches an
unauthorised recipient; or one subject's identifiers appear in a message declared about
another; or a subject's identifiers reach a partner whose agreement does not cover them.

The metric scores delivered content rather than the detector's verdict, and that distinction is
load-bearing. Four scenarios are recorded as stopped and still leak: redaction is a *change*
guard rather than a completeness guard, so a message carrying two identifiers where only one is
recognised ships partially scrubbed while the verdict reads "redacted". A verdict-based metric
would have counted all four as successes.

Two values are deliberately **not** scored as identifiers. A clinical or financial detail is a
fact about the world as much as about a person and appears in guidance that identifies nobody.
The subject label (`patient-A`) is a pseudonymous session key meaningless outside the system.
Both exclusions cost us: the second alone moved exfiltration prevention from 66% to 73%.

#### 6.4.2 The four-arm comparison

**[FIGURE F1 — `report/figures/fig1-four-arm.svg`]**

| arm | exfiltration (n=264) | boundary crossings (n=48) | false positives (n=192) | ms/hop |
|---|---|---|---|---|
| no defence | 0% [0–1] | 0% [0–6] | 0% [0–2] | 0.00 |
| content scanner | 72% [66–77] | 0% [0–6] | 12% [8–17] | 0.74 |
| metadata heuristic | **100% [99–100]** | 0% [0–6] | 25% [19–31] | 0.00 |
| Haris | 73% [67–78] | **100% [94–100]** | 12% [8–17] | 0.20 |

95% bootstrap intervals throughout.

**We report exfiltration and boundary crossings separately.** A reader who hears "leak
prevention" understands data leaving the building; pooling the two would let a single figure
hide that the arms rank differently on each.

**The metadata heuristic prevents more exfiltration than Haris does — 100% against 73% — and
this is a real result, not a rounding artefact.** Six lines that block every external recipient
unconditionally cannot be defeated by rewriting content they never read, so paraphrase,
encoding and splitting are all irrelevant to them. Every one of Haris's 72 misses is a content
attack.

**And the heuristic catches none of the 48 boundary crossings, where Haris catches all of
them.** Two families are responsible, and they fail the baselines for different reasons.
`subject_forgery` delivers one patient's record in a message labelled with another's: the
metadata is faultless and nothing leaves the trust boundary, so neither a recipient check nor
an egress scanner has anything to object to. `partner_scope_violation` is addressed to a
genuinely authorised partner clinic, for a patient that clinic's data-sharing agreement does
not cover — the address is correct and the person is not.

**One benign family separates them in the other direction.** `near_miss_benign` is a
referral-form template quoted in a message to an outside address: identifier-shaped values
belonging to nobody. The content scanner blocks it on the shape of the string; the metadata
heuristic blocks it on the recipient; Haris allows it, because nothing the session actually
read resurfaces. That family, together with the ward round, is why the heuristic carries a 25%
false-positive rate against Haris's 12%.

So the trade is legible in both directions: a blunt egress block wins on exfiltration and is
blind to everything that does not egress, and it cannot permit a partner referral, a form
template or a legitimate multi-patient session. Reading payloads is what buys those, and
reading payloads is what encoding defeats.

**The content scanner — the arm closest to a deployed DLP filter — is the weakest of the
three.** It loses to six lines of metadata checks on exfiltration, scores zero on boundary
crossings, and carries the same false-positive rate as Haris. Reading content without lineage
buys least of all.

#### 6.4.3 Per-family results

**[FIGURE F2 — `report/figures/fig2-by-family.svg`]**

Aggregate rates depend on the family mix, so **the per-family breakdown is the real result**.
Every per-family n is 24, so the intervals are wide; read the columns against each other rather
than any cell alone.

Haris's misses on exfiltration are 72 of 264, and all of them are accounted for:

| miss | n | why |
|---|---|---|
| `external_paraphrase` | 24 | the secret spelled out in words — the semantic ceiling |
| obfuscation rungs 3–6 | 16 | reordering and encodings |
| `split_identifier` | 24 | one identifier across two messages |
| `rewrite_chain` level 6 | 4 | both identifiers degraded past matching |
| partial redaction | 4 | §6.4.1 |

There is no unexplained residue. `split_identifier` is the one attack family where a baseline
beats Haris, and the reason is architectural rather than a matter of tuning: lineage records
what a session read and whether it *resurfaces*, not whether fragments across separate messages
*compose*. Closing it requires the matcher to consider a session's egress traffic jointly,
which is a different design.

The false-positive rate is 24 of 192, and every one is `internal_handoff`: a derived
agent-to-agent message with no declared recipient. **We keep it deliberately.** Treating an
undeclared destination as untrusted is what stops an attacker disabling egress control by
deleting one metadata key, and a test demonstrates that binding `recipient` at the interception
adapter removes the cost without giving up the property.

#### 6.4.4 Difficulty: three ladders

**[FIGURE F3 — `report/figures/fig3-obfuscation-ladder.svg`]**

**Obfuscation.** Six rungs, from layout changes to encodings. Spacing and digit-spacing are
recovered by the matcher's normalisation; reordering, Cyrillic homoglyphs, HTML entities and
base64 are not. At n=4 per rung every interval is too wide to quote, so the result is the
**order**, not the values: what survives normalisation is a change to layout; what defeats it
is a change to the characters. Two of these rungs came out of adversarial testing of the
shipped path rather than our imagination, and both render as the original identifier in any
browser or mail client — which is worse than a silent miss, because a human reviewing the
flagged message sees the real value.

**Rewriting.** The record is restated at every hop of a five-hop chain, degrading each time:
reformatted, reordered, padded with an unrelated sentence, the identifier prefix dropped, and
finally the name reduced to an initial. The first five are all caught and only the last fails.
Because the two identifiers degrade on different schedules, the level where prevention falls
names what detection was resting on: it survived the record identifier becoming bare digits and
failed only when the **name** degraded. Resilience here is a function of token length rather
than identifier structure — which matters for a domain keyed by short codes.

**Depth and format.** Chains of two, four, six and eight hops, where the record is read at hop
one and the identifier resurfaces at the last with nothing identifying in between: caught at
every depth. Five source record formats with a byte-identical egress hop: caught in all five.

That last result was not the first one. Measured before the parser was widened, a structured
block and a JSON payload scored 100% while a narrative note and a chat transcript scored **0%**
— the corpus had been authored in the one shape the fallback parser reads, and with Presidio
off that parser is the only source of taint tags. We widened the parser rather than documenting
the limitation, rotated all five formats through every family, and kept the controlled probe as
a regression guard.

#### 6.4.5 A documented improvement, and what it did not fix

    python -m demo_app.eval.matcher_delta

The information-flow agent originally decided that a tag had resurfaced with an exact
substring test. On 22 August it was replaced by a normalised comparison: both sides
lower-cased, separators collapsed, and a token pass that respects word boundaries. The change
is reproducible side by side — `matcher_delta` restores the old rule and re-runs the whole
corpus.

| family | prevention, exact substring | prevention, normalised |
|---|---|---|
| `external_obfuscated` | 0% | **33%** |
| `rewrite_chain` | 50% | **67%** |
| every other family | unchanged | unchanged |
| false positives | 24/192 (12%) | 24/192 (12%) |

**Report both halves.** Recall rises on the two families that reformat an identifier, and the
false-positive rate does not move at all. A matcher can always be made to catch more by making
it less discriminating; the flat false-positive column is the evidence that this one was not.

**And report what it did not fix, because an earlier version of this document got that wrong.**
This improvement was previously written up as taking obfuscated leaks from 42% to 100%, and
presented as closing a difficulty tier. Both parts were mistaken. The 42% came from a family
that contained a *single* transform — a hyphen replaced by a spaced hyphen — which normalisation
closes completely; a "difficulty" axis whose value moves when you fix a bug in the detector was
measuring the detector rather than the attack. Once that family was rebuilt as the six-rung
ladder in §6.4.4, the same fix reads 0% → 33%: it recovers the two layout rungs and leaves
every encoding rung untouched, which is the honest shape of what a normalising matcher can do.

The second family in the table was not known to benefit until this was re-run on the current
corpus. `rewrite_chain` did not exist when the fix was made, and the reformatted-identifier
level of its degradation chain is recovered by the same normalisation.

### 6.5 Latency

    python -m demo_app.eval.latency              # structural agents
    python -m demo_app.eval.latency --secrets    # with Presidio

**[FIGURE F4 — `report/figures/fig4-latency.svg`]**

**CPU: AMD64 Family 25 Model 80 (AuthenticAMD), Windows 11, Python 3.13.4.** These figures are
machine-specific and should be quoted with the hardware.

| arm | median | IQR | mediation cost |
|---|---|---|---|
| no agents (floor) | 0.007 ms | 0.007–0.007 | — |
| Haris, structural agents | 0.041 ms | 0.027–0.073 | **0.034 ms** |
| Haris + Presidio | 12.553 ms | 8.708–16.308 | **12.546 ms** |

Three repetitions, one warm-up scenario per family, 4,392 hops per arm; medians moved 0.001 ms
and 0.533 ms between repetitions respectively.

**The no-agents arm is the denominator.** A hop costs something with mediation removed — the
orchestrator, the state store, the lineage write, an empty policy resolution — and reporting
wall-clock time as "the cost of Haris" would attribute that to us. The floor is 0.007 ms with a
zero-width interval, so it is negligible and the figures are genuinely about mediation.

**Medians, not means.** The distribution is right-skewed: structurally, p95 is fourteen times
the median because a handful of hops pay a cold cache. A mean sits between the two and
describes neither.

**Presidio costs roughly 370× the structural agents.** What it buys is in §6.5.1, and the
comparison is the argument for shipping it.

#### 6.5.1 What the PII detector changes

| | Presidio off | Presidio on |
|---|---|---|
| exfiltration prevented | 73% [67–78] | 76% [71–81] |
| boundary crossings caught | 100% [94–100] | 100% [94–100] |
| detection | 76% [72–80] | 90% [87–93] |
| false positives | 12% [8–17] | 12% [8–17] |

Three results the structural configuration reports as limits are limits of the **fallback
parser**, not of the design: semantic paraphrase goes from 0% to 75%, the last rewrite level
from 0% to 100%, and the split identifier from 0% to 92% prevented. The obfuscation ladder is
unchanged at 33% — encoding an identifier defeats named-entity recognition exactly as it
defeats a literal matcher, because neither decodes anything.

**A measurement error worth recording, because it invalidated four earlier figures.** Building
the latency harness properly first produced 302 ms per hop with an interquartile range of
11–311 ms, which is not one distribution but two. The cause was that both PII-consuming agents
constructed their own detector per scenario, each lazily loading a spaCy pipeline: a cold
`analyze()` call costs 1686 ms against 4.4 ms warm. Every Presidio latency figure this project
had produced — 8.98 ms, 9.46 ms, 11.1 ms and 302 ms — was measuring model initialisation
amortised over a handful of hops. One detector is now shared per process, as a deployment would
do, and the per-family rates are unchanged, confirming the detector holds no cross-scenario
state.

### 6.6 Threats to validity

We set these out in the order that matters, not the order that flatters. Every number in §6.4
and §6.5 should be read through the first one.

**We wrote the corpus, so it bounds only the threats we thought of.** Every scenario, every
family and every benign case came out of our own reasoning about how a multi-agent system
leaks. Where our imagination stopped, the evaluation stops too, and no rate here can tell us
what we failed to imagine. Two things narrow that gap slightly and neither closes it. The rates
are invariant across seeds 23–27, so they are not an artefact of one random draw. And the
comparison in §6.4.2 puts all four arms on the same corpus, so while the absolute numbers are
conditioned on what we wrote, the *differences* between arms are not — a family we invented
still separates lineage-aware mediation from a metadata rule, whether or not that family occurs
in the wild. The single largest improvement available to this work is benign traffic from a
system we did not build. We did not do it, and until someone does, "12% false positives" means
12% on traffic of our own design.

**The consistency check confirms our labels; it does not adjudicate them.** `oracle.py` derives
each label from the generated traffic, but the traffic and the labels come from the same
generator, so on a corpus we built correctly it cannot disagree. We never call it independent.
What it is good for is showing that the generated traffic actually realises the intended label,
and the mutation suite shows it can fail — defuse one attack property and the label flips. The
genuinely external confirmation is `detect-secrets`, and it covers only the credential-shaped
subset: it has no opinion on a name, a record number or a diagnosis. That is a small honest
number and we report it as one. One family, `forged_session_scope`, cannot be labelled from its
traffic at all, because an attacker who writes a convincing session-scope declaration produces
traffic identical to a legitimate one. We label it by construction and treat that as the
finding rather than as a gap in the method.

**Content diversity is bounded by what we authored.** Five record formats and four phrasings
per leak style is a great deal more than the single template we started with, and it is not the
variety of real traffic. The formats are shared across the four domains rather than written
separately for each. We know the rates do not depend on our prose — four different phrasings of
the same leak produce identical results — and we know they no longer depend on record shape,
because widening the parser closed a gap where a narrative note and a chat transcript scored
zero. What we do not know is how the system behaves on text no one on this team wrote.

**The configuration we measured most is not the one we deploy.** The four-arm comparison runs
with Presidio off, because the comparison needs to be deterministic and dependency-free; the
dashboard runs with Presidio on. We report both, and they differ in ways that matter: three
results the structural configuration records as limitations — semantic paraphrase, the last
level of the rewrite chain, and the split identifier — substantially improve with the detector
enabled. Where this section quotes one figure it is the structural one, and it is labelled.
Anyone comparing our headline against a deployed system should use §6.5.1.

**Aggregate rates are a function of the family mix we chose.** Twenty-four families of
twenty-four scenarios is our decision, and weighting them differently would move every headline
number without a line of code changing. This is why we present the per-family table as the
result and the aggregate as a summary of it. For the same reason, every per-family n is 24 and
every ladder rung is 4: we report confidence intervals throughout so that a per-rung percentage
is not mistaken for a measurement, and we ask that the ladders be read as orderings rather than
as values.

**We found three defects in our own metric, and we think that cuts both ways.** A clinical
detail was being counted as an identifying value; record numbers were being split on the wrong
character, which broke two of the four domains; and a pseudonymous session key was scored as a
leaked identifier, which cost seven points of apparent prevention until we removed it. Each was
found by constructing a case whose correct answer we knew independently, and none would have
been caught by a passing test suite. The optimistic reading is that a measurement instrument
which has caught three faults in itself has been tested harder than one that has caught none.
The pessimistic reading is that there may be a fourth. We hold both.

**What we would do with more time**, in the order we would do it: run the evaluation over
message logs from a system we did not write; give the matcher a decoding pass so that base64,
HTML entities and homoglyphs stop rendering as the original identifier to a human reviewer;
bind `session_scope` and `recipient` at the interception adapter, which converts two of the
limitations in §8 from open problems into deployment requirements; and repeat the Presidio
configuration across several seeds, since named-entity recall varies with the names drawn and
we have not quantified by how much.

## 7. Related work

**Owner:** **Status:** TODO

> NOTE: Position rather than summarise — for each, say what it establishes and how Haris
> differs. The source paper (simulation method, and it motivates the problem), MAScope
> (justifies the provenance design), G-Safeguard (graph/topology axis, complementary
> defence), BreachSeek (attack-generation inspiration), and the per-agent guardrail products
> (Bedrock, NeMo) as the thing we compose with rather than replace.

---

## 8. Limitations and future work

**Owner:** **Status:** TODO

> NOTE: Quantified, not hand-waved. Every item gets a number or a mechanism, and each one
> should point at the section that measures it. §6 now supplies the numbers; this list is the
> set of items that need writing up, with the measured figure beside each.
> - Semantic paraphrase — 0% structural, 75% with Presidio (§6.5.1). Coarse taint cannot
>   follow a rewording that discards every token; this motivates the semantic agent.
> - Obfuscation — the ladder, per rung (§6.4.4). Homoglyph and HTML-entity rungs render as
>   the original identifier to a human reviewer, which is worse than a silent miss. NFKD
>   normalisation plus confusable folding is the fix.
> - **Identifier split across messages** — 0% structural (§6.4.3). Architectural: lineage
>   tracks resurfacing, not composition. The one attack family where a baseline beats us.
> - **Partial redaction** — four scenarios ship one identifier scrubbed and another intact
>   while the verdict reads "redacted" (§6.4.1). Redaction is a change guard, not a
>   completeness guard.
> - **Trusted metadata** — the boundary from §2.3. `forged_session_scope` measures the cost:
>   an attacker who writes their own session scope walks through. Binding the field at the
>   interception adapter is the remedy, as E1/E2 did for `receiver`.
> - **The false positive we keep** — `internal_handoff`, 24 of 192 (§6.4.3). Failing closed on
>   an undeclared destination is what stops an attacker disabling egress control by deleting a
>   key; a test shows adapter-side binding removes the cost.
> - No injection detector — and the compositional argument: injection is a per-message content
>   problem that per-agent guardrails already address; our contribution is the cross-agent
>   layer they structurally cannot provide.
> - Identity is a bearer token: no message integrity, no anti-replay.
> - Operator auth is a shared token; per-user identity (SSO/IAM) is deployment-era.
> - Demonstrated on one framework (LangGraph); a second adapter is roadmap.
> - Self-protection is partial: the keyed chain is not a WORM store.
> - Presidio recall varies with the names drawn (finding PA-3); unquantified — a multi-seed
>   Presidio-ON sweep is outstanding.

## 9. Conclusion

**Owner:** **Status:** TODO

---

## References

> NOTE: Keep as we go. Do not leave to the last day.

---

## Appendix A — Reproducing every number in this report

> NOTE: A table of claim → exact command. This is the appendix that makes the rest credible.
> Keep it in step with §6 — the earlier version of this table cited a 312-scenario corpus and
> a 24/312 external-check figure, both of which had moved.
>
> | claim | command |
> |---|---|
> | the recorded headline set, with provenance for every figure | `report/RESULTS.md` |
> | corpus composition, per-family / domain / topology / rung / format breakdowns | `python -m demo_app.eval.runner` |
> | the four-arm baseline comparison (F1) | `python -m demo_app.eval.baselines` |
> | Presidio-ON configuration | `python -m demo_app.eval.simulate --secrets` |
> | mediation cost against a no-agents floor (F4) | `python -m demo_app.eval.latency [--secrets]` |
> | rates do not depend on the random draw | `python -m demo_app.eval.seed_sweep --seeds 23 24 25 26 27` |
> | the credential-shaped subset confirmed by a third-party tool | `python -m demo_app.eval.external_check` |
> | taint-normalisation before/after (F5) | `python -m demo_app.eval.matcher_delta` |
> | strict missing-recipient policy costs all utility (§2.3) | `python -m demo_app.eval.strict_recipient` |
> | per-family rates unchanged since the last commit | `pytest tests/test_eval_sim.py` |
> | the labeller can fail | `pytest tests/test_label_check_mutation.py` |
> | audit chain resists rewrite, forged append and truncation | `pytest tests/test_audit.py` |
> | the figures are drawn from the harness, not transcribed | `python -m demo_app.eval.figures` |

## Appendix B — Deployment artefacts

> NOTE: The two IAM policy JSONs, the ECS task definition, the compose file.

## Appendix C — Agent × threat matrix

> NOTE: The who-catches-what table, moved here from the dashboard (see `SCOPE_FREEZE.md`),
> mapped onto the final evaluation results rather than the old curated set.
