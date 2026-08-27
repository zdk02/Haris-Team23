# Haris — Team Work Plan (finalization → Aug 31 submission)

> **HISTORICAL DOCUMENT — written 2026-08-04. Kept, not corrected.**
>
> This is the plan as we wrote it at the start of finalization. It is preserved because the
> step numbers it defines (Step 4, Step 8, Step 12, …) are referenced from comments and
> docstrings across the codebase, and because the difference between what we planned and
> what we shipped is itself part of the record.
>
> **It is superseded wherever it conflicts with `SCOPE_FREEZE.md` (2026-08-21) and
> `EVAL_DESIGN.md`.** Two claims in particular were retracted after we measured them, and
> both are flagged inline below:
>
> * **Decision 4 / Step 8 — "the ground-truth oracle is independent of Haris."** Retracted
>   2026-08-23. It re-derives every label from metadata the generator itself writes and
>   disagrees with the generator 0 times in 312 — it is structurally incapable of
>   disagreeing. It is now `label_consistency_check`. Genuine independence is bought
>   separately in `demo_app/eval/external_check.py` (`detect-secrets`, 24/312 confirmed).
> * **Decision 8 / Step 9 — the "no-Haris" baseline arm.** Removed 2026-08-23. That arm ran
>   an empty agent list in monitor mode, where the result is fixed before the run starts —
>   a constant, not a measurement. Replaced by a measured unmediated reference over the
>   corpus (120 of 192, not 100%).
>
> Several steps were also **cut** on 2026-08-21 under the scope freeze. Those are flagged
> inline too. `SCOPE_FREEZE.md` is the authority on what is in and out.

**This week (Aug 4–10):** simulation-based evaluation + deployment starting point + Streamlit organization.
**Next week & buffer (Aug 11–31):** complete deployment, finalize the evaluation, finish the UI, write the
report, harden, and do the final reproducibility check.

Every step is written as **Approach** (how to do it — follow this so we stay consistent) and **Done when**
(how to know it's finished). Read the "Decisions locked" section first — those are settled; please don't
re-open them mid-build.

---

## Decisions locked (do not deviate)

1. **The simulation generates many DIFFERENT systems, not more hospital cases.** Hospital stays only as the
   fully-wired reference/demo. Other domains (education, finance, HR) are distinct multi-agent systems the
   generator produces. This is the "it generalizes across agents" result.
2. **We specify the domains and the secret/leak recipes; the generator automates everything else** — secret
   values, scenario combinations, message traffic, ground-truth labels, the runs, and the scoring.
3. **Haris is app-agnostic already.** To run a new domain we only pass that domain's config (internal trust
   boundary + authorization allow-list) to the existing agents. We do NOT fork or rewrite agents per domain.
4. **The ground-truth oracle is independent of Haris.** It labels leak/no-leak from the injected facts (did
   the known secret reach an unauthorized sink?), NEVER from Haris's own decision logic. If the oracle
   reuses Haris's rules, the results are worthless.

   > **RETRACTED 2026-08-23.** We wrote this rule and then broke it. The labeller reads the
   > same facts the generator wrote, and its checks mirror Haris's own agents — measured, it
   > disagrees with the generator 0 times in 312. The last sentence above is correct and it
   > convicts the implementation, not the rule. What the check *is* good for is confirming
   > that the generated traffic realises the intended label, so it is now named
   > `label_consistency_check` and described that way in `EVAL_DESIGN.md`. Its checks are
   > proven live by mutation tests (`tests/test_label_check_mutation.py`), and independent
   > confirmation is bought from a third-party tool that knows nothing about this project
   > (`demo_app/eval/external_check.py`).

5. **We do NOT aim for 100% detection / 0% false positives.** A perfect score on a broad eval reads as
   rigged. We deliberately build a difficulty spectrum and report per-domain / per-class breakdowns so the
   numbers are high but realistic, with visible, explainable edges.

   > **Note 2026-08-23.** This decision was right in intent and wrong in execution: the
   > `authorized_external` false positives came from withholding configuration from Haris
   > (the trusted partner was never passed to `internal_domains`), not from a genuine
   > detector limit. Manufacturing a weakness to avoid a suspicious score is the same
   > failure as manufacturing a strength. Fixing it is tracked in `SCOPE_FREEZE.md`.

6. **Semantic/paraphrase AGENT (the defense) is out of scope for this submission.** BUT we INCLUDE a
   paraphrase leak class in the evaluation as a *measured miss* — because we author those leaks, their
   ground truth is still deterministic, so Haris missing them gives us an honest false-negative number and
   motivates the semantic agent as future work. "Paraphrase agent" and "semantic agent" are the same
   planned component — not building it now.

   > **Qualified 2026-08-24.** The paraphrase family as generated carries no injected
   > identifier at all, so there is nothing in those messages to detect and a correct
   > detector *should* pass them. Scoring them as missed leaks overstated the corpus's
   > difficulty. The class stays, but it needs paraphrases that genuinely retain the secret
   > before it measures anything.

7. **The core evaluation is fully deterministic — no LLM judge.** The only place an LLM judge appears is the
   small, optional real-LLM realism slice next week. *(That slice was cut — see Step 19.)*
8. **Every scenario runs in three arms:** no-Haris (baseline leak rate) / Haris-monitor (detect only) /
   Haris-enforce (prevent).

   > **AMENDED 2026-08-23 — two arms, not three.** The no-Haris arm was an empty agent list
   > in monitor mode: `most_restrictive([])` is ALLOW and monitor clamps anything above
   > FLAG, so it could not have stopped anything and its "100% leaks" headline was a
   > constant we reported as a finding. Removed. The corpus's unmediated leak rate is now
   > *measured* by outcome (`demo_app/eval/leak_check.py`) and comes out at 120 of 192, not
   > 192 of 192 — 48 scenarios never egress and 24 carry no identifier. Comparison arms that
   > are genuinely not Haris (a content scanner, a metadata heuristic) are a separate piece
   > of work; see `SCOPE_FREEZE.md`.

9. **Do NOT rebuild what already exists:** the five agents, orchestrator, policy engine, enforce mode,
   reliability guard, two-tier logging, tamper-evident audit log, notification system (Notifier + webhook +
   health check + CI alerts + dashboard banner), the dashboard, and the 124 tests are all done.
10. **Deployment is fully finished by Aug 31; this week is only its starting point (Docker).**
11. **Product shape = library + service + dashboard.** Developers protect their system by adding Haris as
    middleware (or calling the Haris service); the deployed URL is the operator dashboard for *observing*
    Haris, not for running anyone's agents.

---

# THIS WEEK (Aug 4–10)

## Workstream 1 — Simulation-based evaluation

### Step 1 — Write the evaluation design note (`EVAL_DESIGN.md`)
- **Approach:** put the whole design in one file before coding — the scenario axes, the three arms, the
  independent-oracle rule, the difficulty spectrum, the paraphrase-as-measured-miss rule, and the metrics.
  Copy the locked decisions above so everyone builds to the same shape.
- **Done when:** committed and the team has read it.

> **Superseded.** `EVAL_DESIGN.md` has since been rewritten and is the current authority.
> Read it, not this step: the arms, the labeller and the paraphrase rule all changed.

### Step 2 — Build the `Domain` template structure
- **Approach:** a small dataclass holding a domain's fields — agent roles, internal trust boundary (e.g.
  `hospital.internal`), authorization allow-list (allowed sender→receiver per data type), data type(s),
  data subjects, and internal vs external recipients. Config only, no app logic.
- **Done when:** the `Domain` type exists and hospital is expressed as one instance.

### Step 3 — Author the domain specs (hospital + education + finance + HR)
- **Approach:** write 3–4 domains as `Domain` instances (~15 lines each). Different roles/data types per
  domain; keep them realistic but abstract. These are the "different systems" we prove Haris generalizes to.
- **Done when:** at least 3 domains are defined and validate against the `Domain` schema.

### Step 4 — Build the scenario generator
- **Approach:** take the cross-product of domain × topology (linear / star / branch) × secret type × leak
  style × attack-vs-benign × recipient(internal/external), with a fixed random seed. Each scenario = an
  agent graph + a message sequence + a ground-truth record (injected secret, subject, authorized
  recipients). Reuse the existing `Message` shape.
- **Done when:** `python -m demo_app.eval.generate` deterministically produces N scenarios across ≥3
  domains and all axes.

### Step 5 — Add secret injection
- **Approach:** generate synthetic secret *values* with Faker (like the source paper), one per scenario,
  tagged with its type and subject. Store the exact token so the oracle can check it later.
- **Done when:** every scenario carries a known injected secret the generator can reference.

### Step 6 — Add a deliberate difficulty spectrum
- **Approach:** intentionally include hard cases so numbers are realistic (see locked decision 5). For false
  positives: near-miss benign flows (legitimate internal sharing that looks risky, de-identified/aggregated
  data that pattern-matches PII, rare-but-authorized flows) — Presidio will naturally trip on some, which we
  want. For detection: hard attacks (partial identifiers, unusual routing, obfuscation).
- **Done when:** the generated set contains labeled easy AND hard cases on both sides.

> **Partly invalidated 2026-08-23.** The obfuscation tier was not a difficulty tier — it
> defeated our *matcher*, not our design. Normalizing taint matching took it from 42% to
> 100%, which means the "medium" rung was measuring a brittle substring comparison. A real
> graded ladder still has to be built.

### Step 7 — Add the paraphrase leak class as a measured miss
- **Approach:** generate reworded leaks from known secrets (no literal token). Because we author them, they
  are labeled leaks by construction — ground truth stays deterministic, no LLM judge. We expect Haris to
  MISS most of these; that miss is the honest false-negative that motivates the future semantic agent. Do
  NOT build a semantic detector.
- **Done when:** paraphrase-class scenarios exist and are labeled, and the runner records Haris's (mostly
  missing) result on them.

> **See the note on decision 6.** As built, these messages contain no secret to miss.

### Step 8 — Build the independent ground-truth oracle
- **Approach:** label each scenario leak/no-leak purely from the injected facts + observed sink traffic —
  did the known secret (or a reworded form we authored) reach a recipient outside the domain's allow-list,
  or a wrong subject's session? Never consult Haris's decision.
- **Done when:** the oracle labels every scenario, verified independent by running it with Haris disabled.

> **RETRACTED 2026-08-23 — see decision 4.** The "Done when" was unachievable as written:
> running the labeller with Haris disabled proves it does not consult Haris's *runtime
> decision*, which was never the risk. The risk was that it re-implements Haris's *rules*
> over the generator's own metadata — which it does. Renamed `label_consistency_check`
> (`demo_app/eval/oracle.py`). External confirmation lives in
> `demo_app/eval/external_check.py`. This is the single most important correction in the
> project and it belongs in the report, not just here.

### Step 9 — Build the three-arm runner
- **Approach:** for each scenario run it through (1) no-Haris, (2) Haris-monitor, (3) Haris-enforce, feeding
  messages through the existing `Orchestrator` exactly like `eval_harness.py` does. Write every decision to
  the tamper-evident audit log.
- **Done when:** one command runs all scenarios through all three arms and outputs a results table.

> **AMENDED 2026-08-23 — two arms.** See decision 8. `demo_app/eval/runner.py` documents at
> the top why the third arm is absent.

### Step 10 — Parameterize per-domain agent config
- **Approach:** when building the orchestrator for a scenario, pass that domain's internal boundary and
  allow-list into the agents (e.g. `InformationFlowAgent(internal_domains={dom.internal})`,
  `AuthorizationAgent(policy_table=dom.allowed)`). Same agents, domain-specific config — this IS the
  generalization proof. Add constructor params if an agent doesn't accept config yet.
- **Done when:** all in-scope agents run correctly on every domain via config, no hardcoded hospital values.

### Step 11 — Compute metrics + breakdowns
- **Approach:** compute leak-prevention rate (enforce), detection rate (monitor), false-positive rate
  (benign), utility (benign delivered unharmed), latency (avg + p95). Break every number down by domain,
  topology, and leak class — including the paraphrase class shown separately as the known gap.
- **Done when:** a results report (JSON + console) shows overall numbers AND breakdowns, with realistic
  (not perfect) figures.

> **Amended.** Leak prevention is now reported over the scenarios that *actually leak*
> unmediated, separately from policy violations that never egress — they are different
> claims and merging them inflated the denominator. The topology breakdown is being dropped
> from the report (see Step 20b).

### Step 12 — One-command reproducibility
- **Approach:** wire a single entry point (`python -m demo_app.eval.simulate`) with a fixed seed so the same
  command reproduces the same numbers every time.
- **Done when:** two clean runs produce identical results.

## Workstream 2 — Deployment (starting point only)

### Step 13 — Pin `requirements.txt`
- **Approach:** resolve the working set in a clean venv, pin exact versions, commit. Unpinned deps that
  break on a grader's machine are an avoidable failure.
- **Done when:** a fresh `pip install -r requirements.txt` reproduces the environment the tests pass in.

### Step 14 — Write the Dockerfile
- **Approach:** base `python:3.11`, install pinned requirements, AND download the spaCy model
  (`en_core_web_sm`) at build time so Presidio/Secrets-PII works in-container. Default command launches the
  dashboard.
- **Done when:** `docker build` succeeds and `docker run` serves the dashboard with all five agents active.

### Step 15 — Write docker-compose + `.env.example`
- **Approach:** compose file brings the app up in one command; leave room to split Haris into its own
  service later. Wire existing env vars (`HARIS_DASHBOARD_TOKEN`, `HARIS_ALERT_WEBHOOK`) and commit a
  documented `.env.example`.
- **Done when:** `docker compose up` runs the whole thing reproducibly.

## Workstream 3 — Streamlit (UI) organization

### Step 16 — Real data-lineage / provenance view
- **Approach:** replace the current "Data Lineage" page (which just duplicates "Live Traffic") with an
  actual taint-propagation trace: source → hop → hop → sink, marking where Haris intercepts. Pull lineage
  from the `GraphStateStore` the pipeline already fills. Info-flow is our differentiator — it needs its own
  view.
- **Done when:** the page shows a distinct provenance trace, not a copy of Live Traffic.

### Step 17 — Incidents / Health page
- **Approach:** surface the already-built notification system as its own page: incident feed (severity,
  sanitized summary, timestamp — never raw content), health-probe status, channel status. Read the sanitized
  incident feed the data layer already exposes.
- **Done when:** the page lists this run's incidents and shows health + channel status.

### Step 18 — Layout + accessibility tidying
- **Approach:** make the 6-column KPI grid wrap on narrow widths; add a text/shape token next to color-coded
  verdicts (don't rely on color alone); make the scenario selector prominent; smooth click-to-inspect (the
  per-row `st.button` reruns the whole app — use `st.dataframe` selection or expanders).
- **Done when:** the dashboard reads cleanly at different widths and verdicts are legible without color.

---

# NEXT WEEK & BUFFER (Aug 11–31)

## Finalize the evaluation

### Step 19 — Real-LLM realism slice (optional, budgeted)
- **Approach:** in one or two domains, run a few dozen scenarios with genuine LLM agents instead of scripted
  traffic, judged by an INDEPENDENT LLM (different model/prompt than anything in Haris, never shown Haris's
  decision). Stays in the non-semantic leak classes. Shows the result holds with real agents; keep it small
  to bound cost.
- **Done when:** the slice runs and its numbers are reported alongside (not merged into) the deterministic
  core.

> **CUT 2026-08-21.** Days of work, and it introduces an LLM judge we would then have to
> defend. The deterministic core is the stronger claim.

### Step 20 — Generate evaluation figures
- **Approach:** use the dataviz skill. Charts: baseline vs enforce leak rate, per-domain bars, per-topology
  bars, leak-class breakdown (including the paraphrase gap), latency distribution.
- **Done when:** report-ready figures are exported.

> **Amended.** "Baseline vs enforce" no longer means the deleted no-Haris arm. The
> per-topology chart is dropped: three labels over two distinct shapes is not a defensible
> axis (**Step 20b — deepening the topologies — CUT 2026-08-21**).

## Complete the deployment (all by Aug 31)

### Step 21 — Persisted audit log + dashboard reads it
- **Approach:** point the audit log at a file/volume; have the dashboard read the persisted store instead of
  replaying the demo in-process. This is the real "backend connection."
- **Done when:** the dashboard renders a persisted run, not an inline replay.

> **Prerequisite, found 2026-08-22.** The chain had to be seeded from the last record on
> disk first: without it the first record written after any restart carried `prev_hash=""`,
> the chain failed verification, and in enforce mode the health probe then refused to run
> the pipeline at all. Persisting the log before fixing that would have bricked the demo on
> its second boot. Fixed in `haris/audit.py`.

### Step 22 — Split Haris into its own service
- **Approach:** a thin service boundary/API so the demo app and dashboard call Haris as a separate,
  isolated, least-privilege service (the "service" product form).
- **Done when:** Haris runs as its own container the others depend on.

> **Reduced 2026-08-21.** A minimal `POST /v1/inspect` + `GET /health`. `/health` is needed
> for the ECS target group regardless. The dashboard is **not** rewired to call it — it
> keeps reading the persisted log. Half the work, no judge-visible loss.

### Step 23 — Deploy to AWS
- **Approach:** push images to ECS/Fargate (Bedrock for any model calls); scoped IAM roles for isolation.
  The reachable URL is the operator dashboard.
- **Done when:** mentors can open the live dashboard URL and the eval reproduces there.

> **Timebox 2026-08-21: TLS/ALB by end of Mon Aug 24**, or deploy on the ALB's own DNS name
> over HTTP and document it as a limitation.

### Step 24 — Real email alerting (SES)
- **Approach:** wire an SES channel into the existing Notifier; smoke-test. This is the one notification
  channel that needs deployment.
- **Done when:** a CRITICAL incident sends a real email.

## Finish the UI

### Step 25 — Render simulation runs across domains
- **Approach:** let the dashboard display generated simulation runs (not just the hospital replay), making
  the app-agnostic claim tangible on screen.
- **Done when:** the dashboard can show a chosen domain's simulation run.

> **CUT 2026-08-21.** The graph uses hardcoded pixel positions; adding domains collides the
> nodes. A day of work for twenty seconds of attention.

### Step 26 — Who-catches-what matrix
- **Approach:** add the agent × threat matrix from the deck, mapped onto the simulation results.
- **Done when:** the matrix renders and matches the eval numbers.

> **CUT from the UI 2026-08-21** — it goes in the report as a static table. Same
> information, 5% of the cost.

## Write the report (written deliverable)

### Step 27 — Outline + problem/motivation
- **Approach:** motivate with the source paper + MAScope (why per-message input guardrails are
  insufficient; why provenance/cross-agent matters).
- **Done when:** outline agreed and the motivation section drafted.

### Step 28 — Threat model section
- **Approach:** refresh `THREAT_MODEL.md` into threat → answer → staged-attack rows; lift into the report.
- **Done when:** section drafted from the refreshed threat model.

> **Added 2026-08-22.** The refresh now includes §2.3, the trusted-metadata boundary — the
> assumption that most security decisions key off fields supplied by the party the threat
> model treats as compromised. It is stated rather than buried, with the measured cost of
> the strict alternative. Expect it to be the first thing a security reviewer asks about.

### Step 29 — System design section
- **Approach:** lift the high/low-level design + per-agent mechanisms from the deck; include the
  library/service/dashboard product shape.
- **Done when:** section drafted.

### Step 30 — Reliability / logging / audit / notification section
- **Approach:** describe fail-open/closed, the agent-crash guard, two-tier logging, the tamper-evident audit
  log, and the notification system.
- **Done when:** section drafted.

> **Wording 2026-08-22.** "Tamper-evident" is accurate only with `HARIS_AUDIT_KEY` set, and
> truncation is detectable only against a head hash held outside the log. Both limits are
> now stated in `haris/audit.py` and `THREAT_MODEL.md`, and the report must carry the same
> qualifications rather than the unqualified phrase.

### Step 31 — Evaluation section (the heart)
- **Approach:** write up the simulation methodology, the independent oracle, the three arms, and the
  results/figures — including the honest realistic numbers and the paraphrase gap. This is what the grade
  hinges on; give it the most care.
- **Done when:** section drafted with final figures embedded.

> **Amended.** Not "the independent oracle" and not "the three arms" — see decisions 4 and
> 8. The section should describe the label-consistency check honestly, name what external
> confirmation was and was not available, and report leak prevention separately from
> policy-violation detection.

### Step 32 — Related work section
- **Approach:** position G-Safeguard (topology axis + complementary defense), MAScope (justifies our
  provenance design), BreachSeek (attack-generation inspiration), and the source paper.
- **Done when:** section drafted with citations.

### Step 33 — Limitations & future work section
- **Approach:** state the semantic/paraphrase gap WITH its measured miss-rate as the headline future work,
  plus no injection detector, bearer-token identity, partial self-protection, second framework (CrewAI),
  full AWS/IAM.
- **Done when:** section drafted, honest and quantified.

> **Note.** CrewAI is future work only. The dashboard previously advertised a CrewAI adapter
> as available; the only occurrence of the word in the codebase was that string, and it was
> removed on 2026-08-22.

### Step 34 — Assemble + export as Word
- **Approach:** assemble all sections and export via the docx skill once results/figures are final.
- **Done when:** a complete Word document is produced.

## Hardening & loose ends

### Step 35 — README refresh
- **Approach:** update the README (it predates the 5-agent enforcing system, dashboard, eval, CI) so a
  grader goes clone → `docker compose up` → reproduce the eval in three commands.
- **Done when:** the README reflects the current system and reproduction steps.

### Step 36 — Prompt-injection framing decision
- **Approach:** decide as a team — scope injection out clearly as future work, OR add a minimal heuristic
  check only if the spine finishes early. Two of our cited papers are about injection, so a reviewer will
  ask; have the answer ready.
- **Done when:** the decision is made and reflected in the report.

> **Decided 2026-08-21: scoped out, deliberately.** Injection is a per-message content
> problem that per-agent guardrails already address. Our contribution is the cross-agent
> layer they structurally cannot provide, and composing Haris with an input guardrail is the
> correct architecture. That is a better answer than a weak sixth detector.

### Step 37 — (Optional/stretch) monitor-only semantic-agent prototype
- **Approach:** ONLY if everything else is done. A basic embedding-similarity check as a monitor-only 6th
  agent, off by default, out of the enforce path and out of the headline numbers — just to show a first cut
  at closing the paraphrase gap. Drop it with zero damage if time runs out.
- **Done when:** (if attempted) it flags one reworded leak in a demo, clearly labeled experimental.

> **CUT 2026-08-21.** It would be untested at submission, which is worse than absent, and it
> would replace a documented ceiling with an undefended claim.

## Final proof

### Step 38 — Full test pass
- **Approach:** run the whole suite; keep 124+ tests green.
- **Done when:** the suite is green.

### Step 39 — Clean-machine / fresh-container reproducibility check
- **Approach:** on a clean environment, clone → build → run the eval and confirm the reported numbers
  reproduce.
- **Done when:** numbers reproduce from scratch.

### Step 40 — Freeze & submit
- **Approach:** freeze the repo, confirm code + deployment + report are all in place, submit before Aug 31.
- **Done when:** submitted.