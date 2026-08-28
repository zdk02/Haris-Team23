# Haris — Real-Time Security Middleware for Multi-Agent AI Systems

**Team Haris · Amazon Mentorship Program · American University of Beirut**
Submission: 31 August 2026

## Abstract

Multi-agent LLM applications decompose a task across specialised agents that exchange messages
and act without a human reading each internal exchange. Existing guardrails filter one agent's
input and output in isolation, holding no model of the communication graph and no history of how
data has moved — so a summary derived from a record read four hops earlier, and a message
addressed to an authorised partner but concerning the wrong person, are both invisible to
them. We present Haris, security middleware that mediates every inter-agent message and
decides on the sender–receiver relationship and a per-session lineage graph rather than on
content alone. We evaluate on 576 generated scenarios across four domains and twenty-four threat
families, scored by what each configuration actually delivered rather than what its detector
concluded, against three reference baselines. Haris prevents 73% [67–78] of exfiltration and
100% [94–100] of boundary crossings at a 12% [8–17] false-positive rate. A six-line metadata
heuristic prevents more exfiltration — 100% — by blocking every external send, but catches none
of the 48 boundary crossings and doubles the false positives. The limitation is semantic: a
paraphrase that discards every token defeats lineage matching, and closing it requires a
semantic agent we deliberately did not ship untested.

---

## 1. Introduction — problem and motivation

Production LLM applications are no longer one model behind one prompt. A task is decomposed
across a team of specialised agents — a retriever that reads records, a summariser that
condenses them, a mailer that sends the result — which exchange messages, call tools and act
without a human reading each internal exchange. The frameworks that assemble these systems
(LangGraph, AutoGen, CrewAI) make the composition cheap, and the traffic between agents is
correspondingly high-volume and unobserved. A deployment that reviews every model output before
it reaches a user still reviews none of the messages its agents send each other.

**The risk has moved into the channel between agents.** It is not primarily that one agent
behaves badly in isolation; it is that a message crossing from one agent to the next carries
data, provenance and authority that no single agent is positioned to judge. Three failures
follow directly. Sensitive data leaks outward across hops, often in *derived* form — a summary
that reproduces no verbatim identifier while still being about the record it was written from.
An agent acts outside its authority, addressing a recipient it should never hold a
conversation with, or claiming to be an agent it is not. And data belonging to separate
subjects mixes inside one session, so that one person's record is delivered in a message
declared to be about another. We assume throughout that **one agent in the system is
compromised**, and that everything it emits — including the metadata stating who it is and
where its message is going — is attacker-controlled (§2).

**Existing guardrails are built for a different shape of problem.** Bedrock Guardrails and NeMo
Guardrails filter one agent's input and output in isolation: they see a message, evaluate it
against content policy, and return a verdict. They hold no model of the communication graph, no
notion of which sender–receiver pairs are permissible, and no history of how the data in front
of them arrived. That architecture is a poor fit for all three failures above. A derived summary
is innocuous on its face and only suspicious given what the session read four hops earlier. A
message to a genuinely authorised partner clinic is unobjectionable in content and wrong only
because of the patient it concerns. A forged sender is undetectable from the message body,
because the body is exactly what the forger controls.

**This gap is documented rather than assumed.** The source paper on multi-agent privacy leakage
demonstrates that sensitive data propagates across agent hops in ways single-agent controls do
not observe [1]. MAScope reports that per-message guardrails miss cross-agent attacks
specifically because the attack is distributed across messages that are individually clean [2].
G-Safeguard argues for modelling agent interaction as a graph and reasoning over that structure
rather than over isolated messages [3]. And BreachSeek shows the pressure from the other
direction: multi-agent systems are already automating offensive security work, so the
adversary composing these attacks is itself becoming cheap to build [4].

**Haris is security middleware that sits on the channel.** It intercepts every inter-agent
message before delivery and returns one of four actions — allow, flag, redact or block — from
five cooperating security agents. Two properties distinguish it from a per-agent filter.
*Relationship awareness*: policy is evaluated over the sender–receiver pair and the trust
boundary, so who is talking to whom is a first-class input rather than something inferred from
text. *Trajectory awareness*: a lineage graph records what each session has read, so a message
can be judged on what it is derived from and not only on the characters it contains. Together
these let Haris answer the derived-summary, wrong-patient and forged-sender cases that a
stateless content filter cannot reach.

**The claim we make is measured, not asserted.** We evaluate on a generated corpus of 576
scenarios spanning four domains, three topologies and twenty-four threat families, scored by an
outcome-based leak metric that reads what each configuration actually *delivered* rather than
what its detector concluded (§6). We compare against three reference baselines, including one
deliberately unflattering to us.

**That comparison is the honest headline, and we state it here rather than let a reader
discover it in §6.** A six-line metadata heuristic that blocks every external recipient
prevents more exfiltration than Haris does — 100% against 73%. It does so by never reading a
payload, which is why no amount of paraphrase or encoding defeats it. But it catches **none** of
the 48 boundary crossings, where Haris catches all of them, and it pays for its egress record
with a 25% false-positive rate against Haris's 12%: it cannot permit a legitimate partner
referral, a form template, or a multi-patient ward round. The contribution is not a single
dominating number. It is a defence that covers a class of violation the blunt instrument is
structurally blind to, at half the cost in false alarms, with the trade measured in both
directions.

### 1.1 Contributions

- **Relationship- and trajectory-aware mediation for inter-agent traffic.** Security decisions
  are evaluated over the sender–receiver pair, the trust boundary and a per-session lineage
  graph, rather than over message content alone. The core (`haris/`) carries no framework
  dependency; the LangGraph binding is a single adapter. §3 specifies the design; §6.1 tests
  the app-agnostic claim concretely, by running four different domains on the same agent
  classes with no per-domain forking.

- **A 576-scenario benchmark with deterministic ground truth and no LLM judge.** Scenarios are
  generated from declarative descriptions of four multi-agent systems under a fixed seed, so
  every figure in this report reproduces exactly. Because each secret is synthesised with known
  values, labels are derived rather than annotated, and no scored result anywhere in §6 depends
  on a model's opinion. §6.1 describes the generator; §6.2 states where the labels can still be
  wrong.

- **An outcome-based leak metric that scores delivered content, not verdicts.** A scenario
  counts as a leak when an identifier reaches an unauthorised recipient in what the arm
  actually shipped. The distinction is load-bearing rather than pedantic: four scenarios are
  recorded as stopped and still leak, because partial redaction ships a partially scrubbed
  message under a "redacted" verdict. A verdict-based metric would have scored all four as
  successes (§6.4.1).

- **A measured comparison against three reference baselines, including one that beats us.** The
  four-arm table reports no defence, a content scanner, a metadata heuristic and Haris on the
  same corpus (§6.4.2). Haris prevents 73% [67–78] of exfiltration against the heuristic's 100%
  [99–100], and 100% [94–100] of boundary crossings against the heuristic's 0% [0–6], at 12%
  [8–17] false positives against 25% [19–31]. Boundary crossings are the class no baseline
  scores above zero on, and they are the differentiator.

- **Every miss accounted for, with no unexplained residue.** All 72 of Haris's exfiltration
  misses are attributed to a named mechanism — semantic paraphrase, encoding rungs, an
  identifier split across two messages, degraded rewrite chains, partial redaction — and all 24
  false positives to a single family kept on purpose, because treating an undeclared
  destination as untrusted is what stops an attacker disabling egress control by deleting one
  metadata key (§6.4.3).

- **The trusted-metadata boundary stated, bound where it can be bound, and priced where it
  cannot.** Metadata arrives from the party this threat model treats as compromised; §2.3 gives
  the field-by-field table of what the adapter binds and what remains sender-supplied, and
  charges the residual to the results rather than a footnote. We implemented and measured the
  strict alternative — treat an absent recipient as external — and report it at 100% prevention,
  100% false positives and 0% utility. The measurement is itself part of the contribution: it is
  what shows the permissive default to be a considered position rather than an oversight.

- **Mediation cost measured against a mediation-free floor.** Structural agents add 0.034 ms
  per hop and the full configuration with Presidio adds 12.5 ms, measured against a no-agents
  arm that isolates the orchestrator's own overhead from ours (§6.5), with the accuracy that
  buys quantified in §6.5.1.

---

## 2. Threat model

**Owner:** Zeinab · Batoul **Status:** DRAFT

Source: `THREAT_MODEL.md`, which is maintained alongside the code and is the authority where
this section and it disagree.

### 2.1 Assets, adversary, and scope

**What we are protecting.** In the hospital reference application: private health information
(name, date of birth, condition); the *data subject* a message concerns, since correct data in
the wrong patient's session is still a breach; credentials that appear in message bodies; and
the audit log itself, which is the record of what Haris decided.

**The adversary.** A compromised or misbehaving agent *inside* the system. It can compose
messages, address them anywhere, and set the metadata it attaches. It cannot read Haris's
process memory or write to the audit file directly — those are the deployment-era concerns in
§2.4. This is the interesting adversary for our purposes because it is the one existing
guardrails cannot see: every message it sends is individually well-formed.

**Scope.** The messages agents exchange, in ENFORCE mode. Network and host attacks, and anyone
with direct machine access, are out of scope by design.

### 2.2 Threats and how Haris answers them

Six problems, each handled by a different agent, each staged as an attack that must be stopped
and paired with a benign control that must be delivered. A security tool that cripples ordinary
work is not useful, so both halves are measured.

| | Threat | Mechanism | Staged as |
|---|---|---|---|
| **A** | **Direct leak.** A record leaves the system as-is — a patient file emailed outside. | Secrets & PII scanner on content, Authorization on egress. | TC2, CRED |
| **B** | **Hidden leak.** The data is reworded or summarised so it no longer matches the original but still identifies the subject. A text search misses it; only knowing where the data came from catches it. | Information-flow agent: taint over a lineage graph. | TC3 |
| **C** | **Wrong recipient.** The message is fine in itself but not for this sender and receiver — a summary the internal doctor may see and an outside address may not. | Authorization agent plus policy rules. | TC5 |
| **D** | **Mixed subjects.** One patient's data appears while another patient is being handled, with every agent behaving correctly. | Subject-binding: a session is bound to its first data subject. | TC4 |
| **E** | **Hidden instructions.** Harmful instructions embedded in data to steer a later agent. | *Roadmap.* See §2.5. | TC6, named not scored |
| **F** | **Spoofed identity.** A message claims to come from an agent it did not. Without verifiable identity every relationship rule is void. | Identity agent: per-agent bearer token, verified against a registry. | SPOOF |

**B and D are the reason this project exists.** A per-message guardrail sees each message
alone, so it cannot know that this summary derives from a record read three hops ago, nor that
this correctly-formed record belongs to a different patient than the session is about. §6.4.2
measures exactly that: two families no reference baseline catches, for two different reasons.

### 2.3 The trusted-metadata boundary

**This is the most important assumption in the system, and we state it rather than bury it.**

Every message reaching Haris carries metadata — `session_id`, `sender`, `receiver`,
`data_type`, `data_subject`, `recipient`, `auth_token` — and most security decisions key off
those fields. But metadata arrives *from the sender*, which is the exact party this threat
model treats as possibly compromised. An agent that edits one key changes what Haris concludes
without changing a byte of content.

**Where the enforcement point sits decides whether a check is authoritative.** Haris enforces
at the interception adapter. Where that adapter is on the data path — it performs or gates the
send — its decision is authoritative: the message does not move unless Haris allows it. Where
the application sends first and merely tells Haris afterwards, the metadata is a claim by the
party being judged, and the check is advisory. Moving the enforcement point onto the transport
is a deployment requirement, not a code change.

**What is bound, and what is still trusted.** The LangGraph adapter binds transport-derived
metadata at `wrap()` time — when the graph is assembled, before any agent runs — and applies
those values *after* copying anything from shared graph state, so a message body cannot
override them.

| field | source | can a compromised agent change it? |
|---|---|---|
| `sender`, `receiver`, `data_type` | `wrap()` argument | no |
| `recipient`, where the destination is known at wiring time | `wrap(recipient=…)` | no |
| `recipient`, where the destination is dynamic | shared graph state | **yes** |
| `session_id`, `data_subject` | shared graph state | **yes** |
| `auth_token` | the sending agent | yes, but it must match the registry |

Both halves are pinned by tests, including one that deliberately asserts the *remaining*
exposure so that it stays visible rather than drifting shut unnoticed.

**An absent `recipient` is ambiguous and we do not pretend otherwise.** A message with no
recipient is both the ordinary internal handoff and what a compromised sender produces by
deleting the key; nothing in the message separates them. We implemented and measured the
strict reading — treat absent as external — and it returns **leak prevention 100%, false
positives 100%, utility 0%**: every session dies at its first hop, because that hop is a
legitimate internal PHI handoff with no recipient. The defaults therefore keep the permissive
reading, and the strict reading becomes correct only once the adapter binds `recipient` from
the transport, at which point absence really does mean "no destination was declared". Those
numbers are reproducible — `python -m demo_app.eval.strict_recipient` runs both configurations
over the same corpus — and they are the clearest illustration of why prevention is never
reported alone: the strict row prevents everything *because* it delivers nothing.

**The cost of this boundary is measured, not asserted.** §6.4.3 reports `forged_session_scope`:
24 scenarios in which an attacker supplies a session-scope declaration of their own, and walks
through. That is the price of honouring a sender-supplied field, and it is in the results table
rather than a footnote.

**The deployment requirement, stated plainly.** Bind `session_id`, `sender`, `receiver` and
`recipient` at the interception adapter from the transport, not from the message body. Where an
application lets a compromised agent set these itself, the corresponding checks are bypassable
and Haris's guarantees are correspondingly weaker. We did not close this by making the agents
more suspicious — we measured that approach and it costs the system all of its utility. We
closed the part a binding point can close, and named the rest.

### 2.4 Protecting Haris itself

Haris sees every message, so a breach of Haris is worse than any single leak it prevents.

**Minimise what it holds.** The audit log stores a SHA-256 reference to message content rather
than the body. Delivered content is retained only when `store_delivered_content` is explicitly
enabled, and **never for a blocked message** — an earlier version wrote the plaintext of every
secret Haris had ever refused into the log, and the dashboard rendered it under the heading
"delivered payload" for a message that was never delivered.

**Make the log tamper-evident.** Records are hash-chained, and with an operator key configured
(`HARIS_AUDIT_KEY`) each link is an HMAC, so an attacker who reaches the file cannot rewrite it
or forge entries undetected. Two limits, both honest: dropping records from the *end* leaves a
valid shorter chain, so truncation is caught only against a reference held outside the log —
`checkpoint()` returns the chain head and record count, and the pipeline emits it to the
operational log stream, a different destination from the audit file. And an attacker who can
execute code inside Haris can read the key. Write-once storage is the deployment answer to
that; the dashboard badge distinguishes "chain verified" from "tamper-evident" precisely so it
cannot claim a property an unkeyed deployment does not have.

**Treat inspected content as untrusted.** Haris's checks are deterministic detectors, not an
LLM being handed the content as instructions, so a message cannot prompt-inject Haris.

**Gate the log.** The dashboard requires an operator token to read the audit trail.

**Surface failures actively.** A detector crash, a fail-closed event, a blocked leak or a
failed health check raises a notification — operational log, dashboard banner, webhook — so a
broken guard reaches a person rather than sitting in a file. Alerts carry a content reference
and sanitised text, never the secret, so the alert channel cannot become the leak.

**One thing this does not do, corrected here because an earlier docstring claimed otherwise.**
Agents *can* see each other's tokens in transit: the state store records whole messages
including metadata, and hands session history to every agent on every hop, so a downstream
agent can read an upstream token out of the history it is given. There is also no nonce or
timestamp anywhere, so a captured message replays indefinitely. Both are in §8.

### 2.5 What is deliberately not built

**Prompt injection (Problem E) is out of scope, and that is a design decision rather than an
omission.** Injection is a per-message content problem, and per-agent guardrails already
address it: Bedrock Guardrails and NeMo Guardrails both filter an agent's input and output.
Our contribution is the cross-agent layer those tools structurally cannot provide, because they
hold no model of the communication graph or of how data has moved. Composing Haris with an
input guardrail is the correct architecture, and building a weak injection detector in the time
available would have replaced a documented boundary with an undefended claim.

---

## 3. System design

**Owner:** Zeinab · Batoul **Status:** DRAFT

### 3.1 Architecture overview

Haris is middleware. It sits on the channel between agents rather than inside any of them, and
every message crosses it. That position is what the design buys: an agent-level guardrail sees
one message and one agent, while Haris sees the whole session — who has sent what to whom, and
where each piece of data came from.

Three properties follow from it, and each maps to a threat in §2.2.

**Relationship awareness.** Decisions are made per sender/receiver pair and per destination
rather than per message. The same summary is allowed to the internal doctor and refused to an
outside address; the message is identical and the answer differs.

**Trajectory awareness.** A lineage graph records what each session has read, so a message can
be judged against the history of the data in it rather than only against its own text. This is
what catches a leak that no longer resembles the record it came from.

**Application independence.** Haris knows nothing about hospitals. A deployment is described by
configuration — trust boundary, sensitive data types, identity registry, data-sharing
agreements — and the same agent classes run against it unchanged. §6.1 exercises this with four
different domains that share no code.

### 3.2 The message pipeline

Every message follows the same six steps, and the ordering carries security properties that are
easy to lose.

**1 · Intercept.** The adapter wraps the agent boundary and constructs the `Message` in the
frozen schema, binding transport-derived metadata as described in §2.3.

**2 · Context.** The orchestrator asks the state store for the session's history *before* any
agent runs. Every agent therefore judges the current message against everything the session has
already done.

**3 · Check.** Each security agent returns a `Verdict` — a label, a score, a human-readable
reason, and optionally redacted content. Agents do not act; they report. Each runs inside a
reliability guard, so a detector that crashes cannot take the pipeline with it (§4.1).

**4 · Resolve.** The policy engine combines the verdicts into a single `Decision` (§3.4).

**5 · Enforce.** In ENFORCE mode a blocking decision stops the message; in MONITOR mode
everything is recorded and nothing is stopped.

**6 · Record.** The message is written to the lineage store **only if it was not blocked**, and
the decision is written to the audit log either way. That asymmetry matters: a refused hop
leaves no trace in lineage, so an attacker who cannot get a single message through cannot bind
a session to their own data subject and deny service to everyone after them. The audit log
records the block, because retaining refusals is exactly its job.

### 3.3 The security agents

Five agents, each answering a different question. What follows gives the technique and, for
each, what it structurally cannot catch — the limits are measured in §6 rather than assumed.

**Secrets & PII.** Presidio (spaCy NER) for personal data, `detect-secrets` for credentials.
Both are integration rather than invention: no bespoke regexes or entity models. Two design
choices carry weight. Entity types are *weighted* — Presidio reports `DATE_TIME` for "in two
weeks", which would false-positive on every clean summary — and findings are combined with a
noisy-OR so weak signals corroborate rather than the strongest deciding alone. And government
identifiers and payment instruments flag at egress regardless of score, because a detected SSN
leaving the trust boundary is not a judgement call. *Cannot catch:* anything the detectors do
not recognise, and recall varies with the names drawn (§6.6).

**Authorization.** A deterministic relationship table plus egress control on sensitive data
types. Data-sharing agreements are scoped per data subject, so "may we send to this address"
and "may we send *this person's* data to this address" are separate questions — a distinction
that turns out to be one of the two cases no reference baseline handles (§6.4.2). *Cannot
catch:* anything whose metadata is well-formed and whose destination is legitimate.

**Information-flow.** Taint over the lineage graph. A source read tags the session with the
identifiers it contains; a later message is checked for whether any of them resurface on their
way somewhere they should not go. Matching is normalised — lower-cased, separators collapsed,
with a token pass that respects word boundaries — because the original exact-substring
comparison was defeated by a double space. Extraction reads structured `Key: value` records,
JSON, and free prose, after we measured that a corpus written only in the first shape was
scoring the parser rather than the threat (§6.4.4). *Cannot catch:* a rewording that discards
every token, an encoded identifier, or a value split across two messages — all three measured
in §6.4.3.

**Subject-binding.** Instance-level authorisation: a session binds to its first data subject,
and a later message about a different one is refused. Two further bindings were added as the
evaluation exposed the need. *Content binding* compares a record's own assertion of whose it is
against the label the message declares, which catches a payload that contradicts its own
metadata. *Declared scope* lets the calling application state up front which subjects a session
legitimately covers, because session binding alone refuses a ward round — a clinician handling
two patients — and that traffic is indistinguishable from an attack. §6.4.3 reports what
honouring that declaration costs.

**Identity.** A per-agent bearer token, compared in constant time against a registry supplied at
construction. Without it every relationship rule is void, since a spoofer simply labels their
message as coming from someone else. *Cannot catch:* replay, since there is no nonce or
timestamp; and the token is visible in session history to later agents (§2.4).

### 3.4 The policy engine

Verdicts are advice; the policy engine turns them into one decision, in four steps and in this
order.

**1 · Threshold.** Each verdict's score is compared against a configured per-agent threshold,
so a low-confidence flag does not become an action.

**2 · Most restrictive wins.** Across the surviving verdicts, the strongest action is selected.
A single agent's block is not overridden by four agents' allow — an important property when the
agents are deliberately independent and only one of them may understand a given threat.

**3 · Union of redaction spans.** Where several agents want to redact, their spans are combined
rather than one rewrite replacing another. Composing rewrites naively loses redactions.

**4 · Mode gate, last.** MONITOR clamps any action above FLAG. This is last on purpose: every
agent still runs, every verdict is still recorded, and the audit log in monitor mode shows what
*would* have been blocked. Gating earlier would make monitor mode a different system rather
than the same system with enforcement withheld.

### 3.5 Product shape

The same core ships two ways. As a **library**, wrapping an existing agent graph through an
adapter — this is the primary shape, and the one the evaluation exercises. And as a
**dashboard**, the operator view of the audit log, the lineage graph and the live notification
banner: read-only, token-gated, and reading the audit log directly rather than calling a
separate process.

A third shape — a standalone HTTP service exposing `POST /v1/inspect` and `GET /health` — was
scoped out, and the reason is architectural rather than a matter of time. The health endpoint
has no caller: the ALB target group already polls the dashboard's own `/_stcore/health`.
And putting mediation behind a network hop weakens the property §2.3 turns on. Haris's
decision is authoritative only where the enforcement point is on the data path; a remote
inspect API is authoritative only if every caller gates its send on the response, and a caller
that sends first and reports afterwards has reduced the check to advice. The library binding
puts the decision where the message actually moves.

---

## 4. Reliability, logging, audit, and notification

A security guard that fails silently is worse than no guard, because the system continues to
look protected. This section covers what Haris does when something inside it breaks, what it
writes down and where, and how a failure or a caught attack reaches a person.

### 4.1 Failure semantics — fail-open in monitor, fail-closed in enforce

Detectors crash. Presidio may raise on a pathological input, a matcher may hit an unexpected
type, and a security layer whose own bug takes down the protected application has caused more
damage than the attack it was watching for. Every agent therefore runs inside a reliability
guard (`Orchestrator._safe_check`), and a raised exception becomes a *synthetic verdict* rather
than an exception the application sees.

**The direction of failure follows the mode, and this is the whole point of the design.** In
ENFORCE, a crashed detector returns `BLOCK`: the message is stopped, because a check that did
not run cannot be said to have passed. In MONITOR, it returns `FLAG`: the message is delivered
and the failure is recorded, because monitor mode's contract is that it never stops traffic —
including when Haris itself is the thing that is broken. Failing closed in monitor mode would
make monitor a different system rather than the same system with enforcement withheld (§3.4).

**The crash is recorded as that agent's verdict**, so it appears in the audit trail and on the
dashboard exactly where a real verdict would. A detector that is down is visible as a down
detector rather than as a silently reduced set of checks — the failure mode where a guard keeps
returning "allow" because one of its five agents quietly stopped running.

**Coverage, stated precisely, because the guard does not wrap everything.** `_safe_check` wraps
one agent's `check()` call and nothing else. The rest of the pipeline runs outside it: the
context fetch from the state store, the policy engine's resolution of verdicts into a decision,
the lineage write, the audit append, and the interception adapter itself. An exception raised in
any of those propagates to the calling application. The reasoning is that those components are
Haris's own control path rather than pluggable detectors — a corrupted audit append or a failed
policy resolution is not a condition that should be converted into a verdict and continued
past — but the consequence is worth naming: **agent failures are contained, framework failures
are not.** Extending the guard to the write path, with a defined behaviour for a failed audit
append, is outstanding work.

### 4.2 Two-tier logging — operational versus security-audit

Haris keeps two logs, deliberately separate, answering two different questions.

**Tier 1, operational** (`haris/logging_config.py`) answers *is anything going wrong inside
Haris?* Startup, configuration, agent crashes from the guard above, and unexpected errors. It is
written for whoever is debugging Haris, so it can be verbose and widely readable — and it
therefore records **metadata only**: sender, receiver, action, an agent's error type. Never a
message body, never a secret. That constraint is what makes it safe to ship to ordinary log
infrastructure; on Fargate it goes to stderr and the awslogs driver forwards it to CloudWatch.

**Tier 2, security-audit** (`haris/audit.py`, §4.3) answers *what did Haris decide, and why?* It
is the hash-chained record of every inter-agent decision. It concerns the protected traffic, so
it is minimised, tamper-evident, and gated behind the dashboard's operator token.

**The split is a security property, not tidiness.** The two logs have opposite handling
requirements: one should be widely readable, the other should not, and merging them would force
the permissive treatment onto the sensitive record. It also gives the audit log's truncation
defence somewhere to stand — the chain checkpoint is emitted to the operational stream (§4.3),
a destination controlled separately from the audit file, so an attacker who can truncate one
cannot silently rewrite the reference that would expose it.

### 4.3 The audit log

The audit log is the record of what Haris decided. It is a separate tier from the operational
log because it answers a different question — not "is the system healthy" but "what was allowed
through, and on what grounds" — and it is the artefact an incident review reads.

**Append-only and hash-chained.** Each record carries the hash of the record before it, so the
log is a chain rather than a set of independent lines. With an operator key configured
(`HARIS_AUDIT_KEY`) each link is an HMAC rather than a plain hash, and the difference matters:
unkeyed, the chain is *corruption-evident*, because anyone who can write the file can also
recompute every hash after the line they changed. Keyed, it is *tamper-evident*, because
recomputing the chain requires the key. The dashboard badge distinguishes the two states rather
than claiming the stronger property for an unkeyed deployment.

**Content is stored as a reference, not a body.** Each record holds a SHA-256 hash of the
message content and its metadata. A breach of the log therefore yields hashes and decisions
rather than the secrets those decisions were about. Delivered content is retained only when
`store_delivered_content` is explicitly enabled, and **never for a blocked message**. That
asymmetry is deliberate and was learned rather than designed: an earlier version wrote the
plaintext of every secret Haris had ever refused into the log, and the dashboard rendered it
under the heading "delivered payload" for a message that was never delivered. A guard that
archives what it blocks is a collection point, not a control.

**A blocked hop is recorded here and nowhere else.** Refused messages are never written to the
lineage store (§3.2), so an attacker who cannot get a single message through cannot bind a
session to their own data subject and deny service to everyone after them. The audit log still
records the block, because retaining refusals is exactly its job.

**Precisely which tampering this detects.** A silent rewrite of an existing record is caught,
because every subsequent link no longer verifies. A forged append is caught, because producing a
valid next link requires the key. Truncation — dropping records from the *end* — is **not**
caught by the chain alone, since a shorter chain is still internally valid; it is caught only
against a reference held outside the log. `AuditLog.checkpoint()` returns that reference, the
chain head and the record count, and the shipped pipeline emits it to the operational log
stream, a different destination from the audit file, so whoever can truncate the file cannot
also rewrite the reference. `verify_checkpoint()` compares them. An attacker who can execute
code inside the Haris process can read the key, and nothing in this design prevents that;
write-once storage is the deployment-era answer.

**The chain verifies a replay, not a durable store.** The badge shown in the dashboard confirms
that the records the running process holds form an unbroken chain. It is not a statement about
persistence: a persisted audit volume was scoped out of this submission, and a Fargate container
filesystem is ephemeral, so a task replacement takes the log with it. What the keyed chain buys
is evidence of modification rather than a guarantee of retention. Durability requires an
external append-capable store, and it is listed in §8 as such.

### 4.4 The notification system

An audit log that nobody opens is not detection. The notifier exists so that a caught attack or
a broken guard reaches a person rather than sitting in a file.

**Triggers.** Notifications are raised at named points in the pipeline rather than by scanning
the log afterwards. A detector crash raises `CRITICAL` from the reliability guard (§4.1),
carrying which agent failed, the error type, and whether the pipeline failed closed or open. A
blocked security decision raises `WARNING`. Health-check failures raise `CRITICAL`. Each event
is a `NotificationEvent` with a severity, a category, a source, a session id, and a summary.

**Dispatch.** The `Notifier` fans one event out to its configured channels. Two mechanisms sit
between the trigger and the channels. *Severity routing:* each channel declares a
`min_severity`, ranked `INFO < WARNING < CRITICAL`, so a channel meant for genuine incidents is
not woken by routine flags. *De-duplication:* repeat events are suppressed on a key derived from
the event, so a detector crashing on every hop of a long session produces one alert rather than
one per message. The de-dup table is capped at 1,000 keys, which is a deliberate choice rather
than an arbitrary one: the notifier lives for the life of the process — days, in the deployed
dashboard — and an unbounded dictionary keyed by summary text is a slow memory leak in the one
component whose job is to still be working when everything else is not.

**One sanitisation choke point.** Alerts carry a content *reference* — a hash — and sanitised
text, never the message body and never the secret. The stripping happens in one place on the way
out to the channels rather than in each channel, so a new channel cannot introduce a leak by
forgetting to sanitise. The rule this enforces is simple and worth stating plainly: **the alert
channel must not become the leak.** A guard that emails the secret it just blocked has moved the
data rather than stopped it.

**Per-channel isolation.** Each channel's `send()` runs behind its own guard, in the same spirit
as the orchestrator's. A webhook that times out must not take down the protected application and
must not suppress the other channels — a broken alerter is not permitted to become an outage.
The shipped configuration pairs a `BufferChannel`, which is zero-config and feeds the
dashboard's alert banner, with a `WebhookChannel` for a team chat destination.

**Who is notified when the integration tests fail.** This was asked directly, and the answer is
three-layered. GitHub emails whoever pushed the failing commit — built in, no configuration.
The workflow then posts the failure to the team channel using Haris's own `WebhookChannel`, so
the CI alert is formatted identically to a runtime alert and exercises the same code path; if
the repository secret is unset the post is a silent no-op and never fails the job, so a missing
webhook cannot manufacture a red build. And `CODEOWNERS` records who owns which part of the
tree, so *whose job it is* to fix a red build is written down rather than assumed.

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

**One denominator needs explaining, because it looks like an inconsistency and is not.**
`forged_session_scope` appears with n=24 in the per-family table and contributes 0 to the
exfiltration denominator in §6.4.2. Both are right: the family is a policy violation with no
leak path, so its 24 scenarios sit in the 72 counted under that heading in §6.1 rather than in
the 264 exfiltration scenarios. It therefore has a detection rate and no prevention rate —
there is nothing to prevent, because nothing in it would leave the system unmediated. The same
reading applies to every family the runner prints with a dash in the prevention column.

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
machine-specific and should be quoted with the hardware. They are also measured on a different
platform from the one we ship: the deployed artefact is Linux on Python 3.11 inside a
container. We did not re-measure there, so read these as the *shape* of the mediation cost —
structural agents negligible, Presidio dominant — rather than as the deployed number.

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
are invariant across seeds 23–27 with the structural agents, and move only slightly with
Presidio enabled — prevention 79.2–81.1% across three seeds, because named-entity recall
depends on which names were drawn — so they are not an artefact of one random draw. And the
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
limitations in §8 from open problems into deployment requirements; and widen the seed sweep,
since three seeds establish that named-entity recall varies with the names drawn without
bounding how far it can vary.

## 7. Related work

Four pieces of prior work locate this project, and one class of product defines what it is not.
We position rather than summarise: for each, what it establishes, and where Haris sits relative
to it.

**The source paper on multi-agent privacy leakage** establishes the problem and supplies the
method [1]. It demonstrates that sensitive data propagates across agent hops in ways that
single-agent controls do not observe, and it does so by simulation over synthetic records with
known injected secrets. Our evaluation follows that method directly — synthetic secrets with
exactly known values, so ground truth is derived rather than annotated and no model judges any
scored result (§6.1). Where we differ is what the simulation is for. That work measures leakage
to characterise the problem; we measure it to compare a defence against alternatives on the same
corpus, which is why §6.3 exists and why one of its arms outperforms us.

**MAScope** establishes why a per-message guardrail is the wrong shape of tool [2]. Its finding
is that cross-agent attacks are missed precisely because the attack is distributed across
messages that are each individually clean — there is no single message a content filter could
object to. That is the argument for provenance, and it is the reason Haris carries a lineage
graph rather than a larger pattern list. Our contribution relative to it is a measured cost:
§6.4.3 reports what lineage catches and what it does not, family by family, including the family
where a trivial baseline beats it.

**G-Safeguard** establishes the graph as the right object to reason over [3]. It models agent
interaction topologically and defends at that level, which is the same insight Haris's
relationship awareness rests on. The two are complementary rather than competing: G-Safeguard
reasons about the shape of the interaction, while Haris reasons about what data has travelled
along it. A deployment could sensibly run both, and the topology axis in our corpus — chain,
star and branch (§6.1) — exists because that work made it a variable worth holding.

**BreachSeek** establishes the pressure from the other direction [4]. Multi-agent systems are
already being assembled to automate offensive security work, which means the adversary composing
the attacks in §6.1 is itself becoming cheap to build. We take from it the posture rather than a
technique: an attacker who can generate attack variants at scale is the reason the obfuscation
and rewrite ladders in §6.4.4 are graded rather than binary, and the reason we report where the
ladders defeat us.

**Per-agent guardrail products — Bedrock Guardrails, NeMo Guardrails — are the thing Haris
composes with, not the thing it replaces.** They filter an agent's input and output against
content policy, and they do that well. Haris holds no opinion on whether a prompt is adversarial
and does not try to; the two operate at different layers, and the correct architecture runs both.
This framing is also our answer to the most obvious question about our scope: we ship no
injection detector (§2.5) because injection is a per-message content problem those products
already address, and building a weak one in the time available would have replaced a documented
boundary with an undefended claim. What no per-agent guardrail can provide, at any quality of
implementation, is the cross-agent layer — a model of who may talk to whom, and of where the data
in front of it came from. That gap is what this work occupies.

---

## 8. Limitations and future work

Every limitation below is either measured in §6 or is a design boundary stated in §2. We give
the number where one exists and name the mechanism where one does not, in the order a reader
should weigh them rather than the order that flatters us.

### What the detector does not catch

**Semantic paraphrase is the ceiling of a token-based taint matcher.** A message that restates
a record in words sharing no tokens with it carries the information and none of the strings,
and lineage matching has nothing to compare. The structural configuration prevents 0% of the
`external_paraphrase` family; enabling Presidio takes it to 75%, because named-entity
recognition finds the person where a literal matcher finds nothing (§6.5.1). Neither figure is
a solution. Closing this properly requires a semantic agent that reasons about meaning rather
than characters, which is the largest single item of future work and the one we deliberately
did not attempt in the time available (§2.5).

**Encoding defeats matching, and the failure mode is worse than a miss.** The obfuscation ladder
in §6.4.4 separates cleanly: rungs that change layout are recovered by the matcher's
normalisation, and rungs that change the characters — reordering, Cyrillic homoglyphs, HTML
entities, base64 — are not, at 33% prevention across the ladder with either configuration. The
part that deserves emphasis is not the rate. A homoglyph substitution and an HTML entity both
render as the original identifier in any browser or mail client, so a human reviewing the
flagged message sees the real value while the detector saw a different string. A silent miss
leaves a reviewer uninformed; this leaves a reviewer actively misled. The fix is a decoding and
normalisation pass — NFKD plus confusable folding, entity and base64 decoding — before matching,
and it is well-understood work we did not have time to do.

**An identifier split across two messages is an architectural miss, not a tuning problem.**
Lineage records what a session read and whether it *resurfaces*; it does not record whether
fragments distributed across separate messages *compose* into something identifying. The
`split_identifier` family is prevented 0% of the time structurally and 92% with Presidio, and
it is the one attack family where a reference baseline outperforms Haris (§6.4.3). Closing it
requires the matcher to consider a session's egress traffic jointly rather than message by
message, which is a different design rather than a parameter.

**Redaction is a change guard, not a completeness guard.** Where a message carries two
identifiers and only one is recognised, the message ships partially scrubbed under a verdict
that reads "redacted". Four scenarios in the corpus do exactly this — recorded as stopped, and
still leaking (§6.4.1). We surfaced it by scoring delivered content rather than verdicts, which
is why it appears here as a limitation rather than as four successes.

### What the design trusts

**Metadata arrives from the party we treat as compromised, and one field is still load-bearing.**
§2.3 gives the field-by-field account of what the adapter binds and what it cannot. The residual
is measured rather than described: `forged_session_scope` is 24 scenarios in which an attacker
supplies a session-scope declaration of their own and walks through, and that family cannot be
labelled from its traffic at all, because a convincing forged declaration is byte-for-byte
identical to a legitimate one (§6.2). Binding `session_scope` and `recipient` at the interception
adapter converts this from an open problem into a deployment requirement, exactly as it already
did for `receiver`.

**We keep a false positive on purpose, and it is 12%.** Every one of the 24 false positives in
192 benign scenarios is `internal_handoff`: a derived agent-to-agent message with no declared
recipient (§6.4.3). Treating an undeclared destination as untrusted is what stops an attacker
disabling egress control by deleting a single metadata key, so the cost buys a property we want.
A test demonstrates that binding `recipient` at the adapter removes the cost without giving up
the property. The number stays in the headline table rather than being tuned away.

**No injection detector, by decision.** Prompt injection is a per-message content problem, and
per-agent guardrails address it today. Our contribution is the cross-agent layer those products
structurally cannot provide, because they hold no model of the communication graph or of how
data has moved. Composing Haris with an input guardrail is the correct architecture; shipping a
weak injection detector would have replaced a documented boundary with an undefended claim
(§2.5).

### What the identity and audit layers do not provide

**Identity is a bearer token and nothing more.** There is no message integrity and no
anti-replay: no nonce, no timestamp, so a captured message replays indefinitely. The token is
also visible in transit to later agents, because the state store hands session history to every
agent on every hop and the history includes metadata (§2.4). Both are protocol-level gaps that a
signed envelope with a nonce would close, and neither is closed today.

**The audit log is tamper-evident, not durable.** The chain badge verifies an in-process replay
of the records the running system holds; it is not a persisted store. A container filesystem is
ephemeral, so a task replacement takes the log with it. Durability requires an external
append-capable store — the deployment answer to the same question that write-once storage
answers for the tamper case — and what the keyed chain buys in the meantime is evidence of
modification rather than a guarantee of retention. Two limits on the evidence itself, restated
from §2.4 because they belong in any list of what we do not have: dropping records from the end
leaves a valid shorter chain, so truncation is caught only against a head hash held outside the
log, and an attacker who executes code inside Haris can read the key.

**Operator authentication is a shared token.** The dashboard gate is a single secret rather than
per-user identity, so it establishes that a reader is authorised and not *which* reader. SSO or
IAM-backed access is deployment-era work and is not built.

**One framework is demonstrated.** The core carries no framework dependency and the LangGraph
binding is a single adapter, which is the design that makes a second adapter cheap — but cheap
is not the same as written. Until a second one exists, "framework-agnostic" is an argument from
structure rather than a demonstrated property.

### What we have not measured

**Presidio recall varies with the names drawn, and we have not bounded it.** Across seeds 23–27
the structural rates are invariant; with Presidio enabled, prevention moves between 79.2% and
81.1% across three seeds, because named-entity recognition performs differently on different
names (§6.6). Three seeds establish that the variation exists. They do not establish how far it
can go, and a full multi-seed Presidio-on sweep is outstanding.

**The benign traffic is our own.** §6.6 states this as the first threat to validity and it is
repeated here as a limitation because it bounds the number most likely to be quoted: 12% false
positives means 12% on traffic this team wrote. The single largest improvement available to this
work is an evaluation over message logs from a system we did not build.

### Future work, in the order we would do it

Run the evaluation over traffic from a system we did not write, which is the only item that
bounds the validity of everything above. Add a decoding and normalisation pass to the matcher,
so that encoded identifiers stop rendering as the original value to a human reviewer. Bind
`session_scope` and `recipient` at the interception adapter, converting two of the limitations
above into deployment requirements. Move the audit log to an external append-capable store, and
the operator gate to per-user identity. Then the two agents named as roadmap throughout — a
semantic agent for paraphrase, and an injection detector only if the compositional argument in
§2.5 stops holding. Widening the seed sweep runs alongside all of these and gates none of them.

## 9. Conclusion

The security problem in a multi-agent system is not located inside any one agent. It is in the
channel between them, where a message carries data, provenance and authority that no single agent
is positioned to judge, and where no human is reading. Haris takes that channel as the enforcement
point: it mediates every inter-agent message and decides on the sender–receiver relationship, the
trust boundary and a per-session lineage graph, rather than on the characters in front of it.

Measured on 576 generated scenarios spanning four domains and twenty-four threat families, and
scored by what each configuration actually delivered rather than by what its detector concluded,
Haris prevents 73% [67–78] of exfiltration attempts and 100% [94–100] of boundary crossings, at a
12% [8–17] false-positive rate and a mediation cost of 0.034 ms per hop structurally.

Those numbers only mean something against alternatives, so we built three. The result that matters
most is the one that does not flatter us: a six-line metadata heuristic that never reads a payload
prevents *more* exfiltration than Haris does — 100% against 73% — because content it never reads
cannot be paraphrased or encoded past it. It also catches none of the 48 boundary crossings, and
carries double the false-positive rate, because it cannot distinguish a legitimate partner referral
from an illegitimate one, or a ward round from an attack. That is the trade this work makes legible
in both directions: reading payloads and tracking provenance is what buys the violations that never
leave the building, and reading payloads is exactly what encoding defeats.

The honest limitation is semantic. A message that restates a record in words sharing no tokens with
it carries the information and none of the strings, and a token-based lineage matcher has nothing
to compare — 0% prevented structurally, 75% with named-entity detection enabled, and neither figure
is a solution (§8). Closing it needs an agent that reasons about meaning. We did not build one,
because an untested detector at submission would have invalidated every number above and replaced a
documented ceiling with a claim we could not defend. The ceiling, measured and named, is the
stronger result.

---

## References

> NOTE: Keep as we go. Do not leave to the last day.

---

## Appendix A — Reproducing every number in this report

Every figure and rate in this report is produced by one of the commands below. Run from the repo
root with the environment described in the README; the corpus is generated deterministically under
seed 23, so results are reproducible exactly rather than approximately.

| claim | command |
|---|---|
| the recorded headline set, with provenance for every figure | `report/RESULTS.md` |
| corpus composition, per-family / domain / topology / rung / format breakdowns | `python -m demo_app.eval.runner` |
| the four-arm baseline comparison (F1) | `python -m demo_app.eval.baselines` |
| Presidio-ON configuration | `python -m demo_app.eval.simulate --secrets` |
| mediation cost against a no-agents floor (F4) | `python -m demo_app.eval.latency [--secrets]` |
| rates do not depend on the random draw | `python -m demo_app.eval.seed_sweep --seeds 23 24 25 26 27` |
| the credential-shaped subset confirmed by a third-party tool | `python -m demo_app.eval.external_check` |
| taint-normalisation before/after (F5) | `python -m demo_app.eval.matcher_delta` |
| which agent objects in which family (Appendix C) | `python -m demo_app.eval.agent_matrix [--secrets]` |
| strict missing-recipient policy costs all utility (§2.3) | `python -m demo_app.eval.strict_recipient` |
| per-family rates unchanged since the last commit | `pytest tests/test_eval_sim.py` |
| the labeller can fail | `pytest tests/test_label_check_mutation.py` |
| audit chain resists rewrite, forged append and truncation | `pytest tests/test_audit.py` |
| the figures are drawn from the harness, not transcribed | `python -m demo_app.eval.figures` |

If a claim in this report has no command beside it here, it should not be in the report.

---

## Appendix B — Deployment artefacts

> NOTE: The two IAM policy JSONs, the ECS task definition, the compose file.

## Appendix C — Agent × threat matrix

    python -m demo_app.eval.agent_matrix              # structural agents
    python -m demo_app.eval.agent_matrix --secrets    # with Presidio

Earlier versions of this project carried a hand-written version of this table over the nine
curated hospital cases, asserting which agent was *supposed* to catch each threat. What
follows is measured instead: every one of the 576 generated scenarios is replayed through the
full line-up, and the table records which agents actually objected — FLAG, REDACT or BLOCK —
at the scenario's **decisive hop**, the same scoping §6 uses.

The runs are in MONITOR. A block in ENFORCE halts the flow, which would leave no decision to
inspect on exactly the hops Haris catches hardest; monitor runs every agent and records every
verdict while stopping nothing, and the mode gate is applied last, so the verdicts are
identical (§3.4).

**Objecting is not the same as acting.** A cell counts an agent raising a concern, not the
final decision. Whether an objection becomes a block, a redaction or a logged flag is the
policy engine's business, and it depends on the trust boundary: the Secrets & PII agent
flagging PHI on an *internal* hop is correct behaviour that is logged and delivered unchanged.
That is why several benign families below show objections while their false-positive rate in
§6.4.3 is zero. Read this table as *who saw something*, and §6.4.3 as *what happened next*.

### C.1 Structural agents (Presidio off — the configuration §6.4 reports)

| family | n | Secrets & PII | Authorization | Data-Subject | Info-Flow | Identity |
|---|---|---|---|---|---|---|
| `authorized_external` | 24 | — | — | — | — | — |
| `deep_chain` | 24 | — | — | — | 24/24 | — |
| `external_credential` | 24 | — | — | — | 24/24 | — |
| `external_derived` | 24 | — | — | — | 24/24 | — |
| `external_obfuscated` | 24 | — | — | — | 8/24 | — |
| `external_paraphrase` | 24 | — | — | — | — | — |
| `external_verbatim` | 24 | — | — | — | 24/24 | — |
| `forged_session_scope` | 24 | — | — | — | — | — |
| `internal_clean` | 24 | — | — | — | — | — |
| `internal_derived` | 24 | — | — | — | — | — |
| `internal_handoff` | 24 | — | — | — | 24/24 | — |
| `multi_subject_workflow` | 24 | — | — | — | — | — |
| `near_miss_benign` | 24 | — | — | — | — | — |
| `partner_scope_violation` | 24 | — | — | — | 24/24 | — |
| `policy_egress` | 24 | — | 24/24 | — | 24/24 | — |
| `public_reference` | 24 | — | — | — | — | — |
| `record_format` | 24 | — | — | — | 24/24 | — |
| `rewrite_chain` | 24 | — | — | — | 20/24 | — |
| `same_subject` | 24 | — | — | — | — | — |
| `split_identifier` | 24 | — | — | — | — | — |
| `spoof` | 24 | — | — | — | — | 24/24 |
| `stored_then_forwarded` | 24 | — | — | — | 24/24 | — |
| `subject_forgery` | 24 | — | — | 24/24 | — | — |
| `subject_mismatch` | 24 | — | — | 24/24 | — | — |

### C.2 With Presidio enabled

| family | n | Secrets & PII | Authorization | Data-Subject | Info-Flow | Identity |
|---|---|---|---|---|---|---|
| `authorized_external` | 24 | 23/24 | — | — | — | — |
| `deep_chain` | 24 | 23/24 | — | — | 24/24 | — |
| `external_credential` | 24 | 24/24 | — | — | 24/24 | — |
| `external_derived` | 24 | 24/24 | — | — | 24/24 | — |
| `external_obfuscated` | 24 | — | — | — | 8/24 | — |
| `external_paraphrase` | 24 | 18/24 | — | — | — | — |
| `external_verbatim` | 24 | 22/24 | — | — | 24/24 | — |
| `forged_session_scope` | 24 | 19/24 | — | — | — | — |
| `internal_clean` | 24 | — | — | — | — | — |
| `internal_derived` | 24 | 23/24 | — | — | — | — |
| `internal_handoff` | 24 | 23/24 | — | — | 24/24 | — |
| `multi_subject_workflow` | 24 | 24/24 | — | — | — | — |
| `near_miss_benign` | 24 | — | — | — | — | — |
| `partner_scope_violation` | 24 | 23/24 | — | — | 24/24 | — |
| `policy_egress` | 24 | 22/24 | 24/24 | — | 24/24 | — |
| `public_reference` | 24 | — | — | — | — | — |
| `record_format` | 24 | 19/24 | — | — | 24/24 | — |
| `rewrite_chain` | 24 | 23/24 | — | — | 20/24 | — |
| `same_subject` | 24 | 22/24 | — | — | — | — |
| `split_identifier` | 24 | 13/24 | — | — | — | — |
| `spoof` | 24 | 22/24 | — | — | — | 24/24 |
| `stored_then_forwarded` | 24 | 22/24 | — | — | 24/24 | — |
| `subject_forgery` | 24 | 17/24 | — | 24/24 | — | — |
| `subject_mismatch` | 24 | 22/24 | — | 24/24 | — | — |

### C.3 What the measured table says

**The structural configuration is sharply specialised, and that is the design working.** In
C.1 every objection is attributable: Info-Flow answers the exfiltration families, Data-Subject
answers the two boundary-crossing families, Identity answers `spoof`. No agent objects outside
its remit, and no benign family draws an objection at all. A hand-written matrix would have
predicted roughly this shape — the point is that it was measured rather than asserted.

**The content detector is broad and the structural agents are what discriminate.** Enabling
Presidio adds an objection in almost every family, including benign ones: `authorized_external`
23/24, `multi_subject_workflow` 24/24, `same_subject` 22/24. Those families have a 0%
false-positive rate (§6.4.3), because a PII flag on a legitimate internal hop is logged and
delivered, not blocked. Named-entity recognition finds people in messages that are *about*
people, which is nearly all of them; what makes a decision is the trust boundary and the
lineage. This is the clearest single piece of evidence for the argument in §1: a content filter
alone cannot separate the traffic, because it objects to almost all of it.

**Three families draw no PII objection even with Presidio on**, and they are the right three.
`internal_clean` and `public_reference` contain nothing identifying. `near_miss_benign` is the
referral-form template whose identifier-shaped values belong to nobody — the case built to
catch a detector that reasons from shape rather than provenance, and the detector does not take
it. `external_obfuscated` is a fourth, for the opposite reason: encoding defeats named-entity
recognition exactly as it defeats a literal matcher (§6.5.1).

**Two rows contradict our own design documents, and the measurement wins.** §2.2 credits the
Authorization agent with egress control on the direct-leak families, and §3.3 credits it with
the per-subject data-sharing agreement that makes `partner_scope_violation` catchable. The
table shows Authorization objecting in exactly one family — `policy_egress` — and Info-Flow
carrying `external_verbatim`, `external_derived`, `external_credential`,
`stored_then_forwarded` and `partner_scope_violation` on its own. The outcome is unchanged:
those families are still prevented at the rates §6.4.3 reports. What is wrong is the
attribution, and it was wrong in the direction that flatters a tidy architecture diagram —
each threat handled by the agent named after it. In the shipped system the information-flow
agent's egress check is doing more of the work than the design intended, and Authorization is
narrower than described. **§2.2 and §3.3 should be read as corrected by this table.**

**One number here should be reconciled before it is quoted.** `split_identifier` draws a PII
objection in 13 of 24 scenarios with Presidio on, while §6.5.1 reports that family at 92%
prevented in the same configuration. Objection at the decisive hop and prevention of the leak
are different measurements — a redaction on an earlier hop can prevent without objecting at
the last one — but the gap is wide enough that we flag it rather than explain it away. The
prevention figure is the one produced by the scored harness and is the one to quote; this cell
is a census of objections and should not be read as a prevention rate.

**What the table cannot show.** It records objections, not their strength, and a family caught
24/24 by one agent has no redundancy: remove Info-Flow and eleven families lose their only
structural detector. That concentration is a design property worth naming — the agents are
deliberately independent, and the policy engine takes the most restrictive verdict (§3.4), so
a single agent's block stands alone. It is also why a detector crash fails closed in enforce
(§4.1): with this much concentration, a missing agent is a missing defence rather than a
degraded one.