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

**Owner:** Zeinab **Status:** TODO — **this is the heart of the report; give it the most care**

### 6.1 Method

> NOTE: Why a generated corpus rather than curated cases. The domain configs, the families,
> Faker secret injection, the arms. Be exact about scenario counts and the seed.

### 6.2 Ground truth and its limits

> NOTE: **Write this honestly.** The generator constructs the labels; the consistency check
> confirms the generated traffic realises the intended label — it is a self-consistency test,
> not independent adjudication. Report separately the subset externally confirmed by
> `detect-secrets`. Do not use the word "independent" for the consistency check.

### 6.3 Reference baselines

> NOTE: No-op, per-message content scanner, metadata heuristic. All arms run through the
> identical orchestrator, policy engine and enforcement path — only the detector differs, so
> the difference between arms is attributable to the detector alone. Explain what each arm
> stands for and why the metadata heuristic is a control rather than a proposal.

### 6.4 Results

> NOTE: **Lead with the four-arm table.** Then per-family rates with confidence intervals.
> Then the obfuscation ladder. A single number with no comparison is not a result.
> Figure list (→ `report/figures/`):
> - F1 four-arm comparison — prevention and false-positive by arm  ← the centrepiece
> - F2 per-family rates with bootstrap CIs
> - F3 obfuscation ladder, per rung
> - F4 latency: structured-only vs Presidio-on vs no-agent baseline
> - F5 before/after of the taint-normalisation fix

### 6.5 Latency

> NOTE: Report BOTH configurations and the no-agent baseline. Median ± IQR over three runs.
> State the CPU. A single figure from the Presidio-off configuration is not the deployed
> system's latency and must not be presented as such.

### 6.6 Threats to validity

> NOTE: Write this yourself, before anyone asks. The corpus is generated by us; the
> consistency check is not an independent adjudicator; content diversity is bounded by N
> authored templates; the measured configuration differs from the deployed one; aggregate
> rates depend on the family mix, so the per-family breakdown is the real result.
> A limitation we name first cannot be used against us.

---

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
> should point at the section that measures it.
> - Semantic paraphrase — the measured miss rate and why coarse taint cannot close it
> - Trivial obfuscation — the ladder result, per rung
> - **Trusted metadata** — the boundary from §2.3, and what binding at the adapter requires
> - No injection detector — and the compositional argument: injection is a per-message
>   content problem that per-agent guardrails already address; our contribution is the
>   cross-agent layer they structurally cannot provide
> - Identity is a bearer token: no message integrity, no anti-replay
> - Operator auth is a shared token; per-user identity (SSO/IAM) is deployment-era
> - Demonstrated on one framework (LangGraph); a second adapter is roadmap
> - Self-protection is partial: the keyed chain is not a WORM store

---

## 9. Conclusion

**Owner:** **Status:** TODO

---

## References

> NOTE: Keep as we go. Do not leave to the last day.

---

## Appendix A — Reproducing every number in this report

> NOTE: A table of claim → exact command. This is the appendix that makes the rest credible.

## Appendix B — Deployment artefacts

> NOTE: The two IAM policy JSONs, the ECS task definition, the compose file.

## Appendix C — Agent × threat matrix

> NOTE: The who-catches-what table, moved here from the dashboard (see `SCOPE_FREEZE.md`),
> mapped onto the final evaluation results rather than the old curated set.
