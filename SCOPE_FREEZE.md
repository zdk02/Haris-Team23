# Scope freeze — agreed 2026-08-21, valid until submission

Two people, nine working days, four graded deliverables (demo · code · report · deployed
system). This file exists so that nothing on the CUT list gets reopened on Aug 28 because
it "would only take an afternoon." If you want to change something here, both of us have
to agree, in writing, in this file, with the date.

---

## Who does what

**Zeinab** — evaluation, security fixes, the evaluation and limitations sections.
She wrote the eval harness and the security agents, so the numbers and the mechanisms are
hers to defend.
**Batoul** — AWS and deployment, notifications, the design / threat-model / related-work
sections. She already wrote the Dockerfile, compose and `.env.example` (Steps 13–15), the
notification system, and the dashboard's first version — so deployment and alerting follow
what she has already built rather than starting cold.

| Day | Zeinab | Batoul |
|---|---|---|
| Fri 21 | Scope freeze · report skeleton · **started the baselines early** | Fire the AWS waits: domain · ACM · SES production request · ECR |
| Sat 22 | Security fixes A–E (audit log, hash chain, taint normalisation, credibility fixes, trust boundary) | AWS day 1: ECR push · Docker hardening (non-root, healthcheck, digest pin) · VPC/SG · ALB |
| Sun 23 | Eval rework 1: remove the tautologies · rescope the oracle · fix the manufactured FP | AWS day 2: task definition · two scoped IAM roles · deploy · **screenshot both policy JSONs** |
| Mon 24 | Eval rework 2: lineage-only attack families · baselines wired in · obfuscation ladder | AWS finish — **TIMEBOX ENDS TODAY**, or fall back to the ALB DNS name over HTTP |
| Tue 25 | Re-run the eval · Presidio-ON snapshot · the five figures | Persisted audit log (needs the chain-seeding fix first) · minimal `/v1/inspect` + `/health` service |
| Wed 26 | Report §6 — evaluation. The heart of the grade | Notifier fixes (dedup key, severity routing, logging) · SES channel · `NOTIFICATIONS.md` |
| Thu 27 | UI Tier A — shared. README first, then the redact scenario, incidents page, lineage view | UI Tier A — shared |
| Fri 28 | Report §1–5, §7–9 · appendices · export to Word | Report §5 deployment · appendices B |
| Sat 29 | Full test pass · clean-machine reproduce · demo rehearsal · hostile-question prep | Same — both |
| Sun 30 | Freeze | Freeze |
| Mon 31 | **Submit** | |

**Report section ownership** — copy these into the `**Owner:**` lines in `report/report.md`
so no section is orphaned:

| Section | Owner | Why |
|---|---|---|
| §1 Introduction & motivation | Zeinab | Closest to the research grounding and the contribution claim |
| §2 Threat model | Batoul | Refresh of `THREAT_MODEL.md`; §2.3 trust boundary written with Zeinab |
| §3 System design | Batoul | Lifts from the Phase 3 deck; §3.3 info-flow reviewed by Zeinab after the taint fix |
| §4 Reliability, logging, audit, notification | Batoul | She built the notifier, the CI alerting and the audit-log wiring |
| §5 Deployment | Batoul | Written while the AWS work is fresh; appendix B is her screenshots |
| §6 Evaluation | **Zeinab** | The heart of the grade. She owns every number in it |
| §7 Related work | Batoul | |
| §8 Limitations & future work | Zeinab | Must be quantified from §6, so it follows the evaluation |
| §9 Conclusion + abstract | Zeinab | Written last, after §6 is final |

---

## IN — committed for the Aug 31 submission

**Evaluation rework** (owner: Zeinab)
- Reference baselines: no-op · per-message content scanner · metadata heuristic, reported
  alongside Haris on the same corpus.
- New attack families that a metadata heuristic cannot catch: internal-recipient/wrong
  subject · multi-hop rewrite chain · no-recipient-then-forwarded.
- Remove the no-Haris "100% leaks" arm (it is an empty agent list in monitor mode — a
  constant, not a measurement).
- Rename the "independent oracle" to a label-consistency check and describe it honestly;
  add `detect-secrets` as a genuinely external labeller on the credential/verbatim classes.
- Per-domain facts; configure the trusted partner properly; split leak-prevention from
  policy-violation detection; deterministic obfuscation ladder replacing `fake.boolean()`;
  bootstrap CIs on every rate.

**Security / correctness fixes** (owner: Zeinab)
- Audit log never retains the content of a blocked message.
- HMAC-keyed chain + persisted head hash + chain seeding on restart + a lock.
- Normalized taint matching (currently defeated by a double space).
- Quadratic redaction guarded and capped; latency timer covers all of `process()`.
- Missing recipient counts as external; a `data_type` label cannot short-circuit info-flow;
  blocked hops are not recorded into lineage.
- Trusted-metadata boundary documented explicitly in `THREAT_MODEL.md`.

**Deployment** (owner: teammate)
- Docker hardening: non-root user, healthcheck, pinned base digest.
- Persisted audit log the dashboard reads.
- Minimal Haris service: `POST /v1/inspect` + `GET /health`.
- AWS ECS/Fargate, one task, ALB + TLS, two minimally-scoped IAM roles.
- SES email channel (SMTP fallback if production access does not land).

**UI — Tier A only** (Aug 27)
- README rewritten so a grader reaches the dashboard.
- One scenario that actually produces a REDACT (currently zero redactions occur).
- Blocked messages stop displaying their payload.
- Incidents & Health page.
- Real data-lineage view replacing the duplicate page.
- KPI grid wraps; verdicts get glyphs, not colour alone.

**Report** — all sections. This is the grade.

---

## CUT — not doing these, do not reopen

| Cut | Reason |
|---|---|
| Real-LLM realism slice (Step 19) | Days of work, and it introduces an LLM judge we would then have to defend. The deterministic core is the stronger claim. |
| Deepening the topologies (Step 20b) | Instead we delete the topology axis from the report. Three labels over two shapes is not defensible. |
| Simulation runs rendered in the dashboard (Step 25) | Graph node positions are hardcoded pixels; adding domains collides them. A day of work for twenty seconds of attention. |
| Who-catches-what matrix in the UI (Step 26) | Goes in the report as a static table. Same information, 5% of the cost. |
| Semantic / paraphrase agent prototype (Step 37) | Would be untested at submission and would invalidate every number. The documented ceiling is a stronger story than a half-built detector. |
| Full fix for attacker-controlled metadata | Real architectural work. We do the cheap 80% and document the trusted-metadata boundary as a stated assumption. |
| Dashboard Tier-B polish | Only if Aug 29 is genuinely clear. |
| Docker image size optimisation | ~1.4 GB is irreducible without multi-stage. Not worth an hour. |
| Rewiring the dashboard to call the Haris service | The dashboard keeps reading the persisted log. Halves the work, no judge-visible loss. |

---

## Hard timebox

**AWS TLS/ALB: end of Mon Aug 24.** If the HTTPS URL is not working by then, we deploy on
the ALB's own DNS name over HTTP and document it as a limitation. Losing three days of
report-writing to certificate validation is the worst outcome available to us.

---

## Changes to this file

| Date | Who | What changed | Why |
|---|---|---|---|
| 2026-08-21 | Zeinab + teammate | Created | Nine days, two people |
