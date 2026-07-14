# Haris — Phase 2: Build the Modules in Parallel

**Phase goal:** now that Phase 1 proved the spine — a real message flows end-to-end
through the interception seam, the orchestrator, and the state store, and both scary
unknowns (interception, coarse lineage) came back **proven/feasible** — Phase 2 fills
in the boxes. Each module below implements the already-frozen `SecurityAgent` contract
(or plugs into the pipeline at a known seam) and can be built **independently and in
parallel**. Nobody is blocked waiting for a redesign: the contracts are frozen, the
pipeline runs, and each module is a self-contained job against an interface that
already exists.

This is where the two-person parallelism pays off. Six modules, each described on its
own terms below. Ownership is deliberately left open — pick them up off the board in
whatever order suits the team, respecting only the dependency notes.

---

## What Phases 0 and 1 already gave us (do NOT rebuild)

- **The five frozen contracts** — `Message`, `Verdict`, `SecurityAgent`, `StateStore`,
  `Policy` — plus the 6th `Decision`/enforcement contract. Every agent in Phase 2 is an
  implementation of `SecurityAgent`; do not change the interface, implement against it.
- **A real, running pipeline.** The hospital LangGraph app (`demo_app/hospital/`:
  `record_reader → summarizer → emailer` over shared state, two patients A and B) is
  wired to the real interception seam and passes every hop through the orchestrator.
- **The interception seam is proven** (Step 2 finding). The **node wrapper**
  (`demo_app/langgraph_interception.py :: HarisLangGraph.wrap`) routes each hop through
  `InterceptionAdapter → Orchestrator → Decision`. It can **observe, modify, and block**
  a message mid-flight — so redact/block enforcement is real, not aspirational.
- **The orchestrator** (`haris/orchestrator/`, `Orchestrator.process()`) runs today with
  zero agents in monitor mode. Per hop it calls `record_flow(message)`, then
  `get_context()`, then each agent's `check(message, context)`, then `resolve()` for the
  final `Decision`, logging every hop. Phase 2 gives it real agents; the plumbing does
  not change.
- **The policy resolver** (`haris/policy/engine.py`, the `resolve()` function) already
  resolves a set of verdicts via
  threshold → most-restrictive → redaction-compose → mode-gate, with a passing test
  suite. Phase 2 extends it to consume real multi-agent verdicts, not rebuilds it.
- **A working Information-flow spike** (Step 5 finding). `haris/agents/infoflow.py`
  already implements `SecurityAgent`, reads session history, extracts taint tags, and
  catches the derived leak (TC3) in the real pipeline. Phase 2 **promotes** this spike
  to MVP; it is not a blank page.
- **`InMemoryStateStore`** and the abstract `InterceptionAdapter` from Phase 0, plus the
  threat-model test cases (TC1 clean, TC2 verbatim, TC3 derived — the flagship, TC5
  external recipient, and the semantic-paraphrase ceiling case).

**What Phase 2 has to actually build (the gaps):** a real graph-backed state store and
lineage ledger; three MVP agents (Secrets/PII, Authorization, and the promoted
Information-flow); the policy engine's multi-agent composition wired into the
orchestrator; and a dashboard over the audit log. That is the whole product.

---

## Ordering & dependencies

- **Module 6 (State store) is slightly foundational.** The Information-flow agent reads
  lineage from it, so **freeze and land its interface first**, even before its internals
  are perfect. Once `get_lineage()` / the ledger API is stable, everything else can lean
  on it.
- **Module 7 (Secrets & PII) is the fastest win** and also produces the real PII
  detector that Module 9 borrows to replace its spike-grade tag extractor. Doing 7
  early unblocks a cleaner 9.
- **Module 9 (Information-flow) is the hard, novel one — give it the most time.** It
  depends on Module 6's ledger and benefits from Module 7's detector.
- **Module 8 (Authorization)** needs no heavy state — it reads the policy schema and can
  start immediately, in full parallel.
- **Module 10 (Policy engine)** pairs naturally with the orchestrator: it consumes the
  verdicts the agents emit, so it firms up as the agents land, but its composition logic
  can be built against stub verdicts from day one.
- **Module 11 (Dashboard)** depends only on the event-log / audit-log format, so it can
  be built alongside everything else — agree the log schema early and it never blocks.

Everything implements a frozen contract, so a half-finished module never breaks another
person's work: a stub agent returns a benign `Verdict` and the pipeline keeps running.

---

## Module 6 — State store: real interaction graph + data-lineage ledger (NetworkX)

**Why it's slightly foundational.** The whole reason Haris catches the *derived* leak is
that it remembers where data came from. The Information-flow agent (Module 9) asks the
store "what tainted this session, and did it originate somewhere that isn't allowed to
reach this destination?" That question is only answerable if the store keeps a real
lineage ledger, not just a flat log. So this module's **interface** is on everyone's
critical path even though its internals are not.

**What "done" looks like.** A concrete `StateStore` implementation (the frozen contract)
backed by a **NetworkX** directed graph, that is a **true drop-in** for
`InMemoryStateStore` (`haris/state/memory.py`) — the three frozen methods return
byte-for-byte identical values so the existing pipeline works unchanged. Concretely, the
frozen behavior (verified against `memory.py`) is: `record_flow(message)` appends the
`Message`; `get_lineage(session_id) -> list[Message]`; `get_context(session_id) ->
{"history": list[Message]}`. On top of that — and *only* additively — it maintains a
**NetworkX interaction graph** (agents = nodes, each hop = an edge carrying
`data_type` / `data_subject` / `content` / `timestamp` from `Message.metadata`) for the
dashboard, and a taint query for the Info-flow agent. Nothing about the frozen three
changes; the graph is the value-add over the in-memory store.

> **Status: implemented** — `haris/state/graph_store.py` (`GraphStateStore`) plus
> `tests/test_graph_store.py` exist and pass (6/6), including a parity test against the
> real `InMemoryStateStore`. Remaining: wire it in wherever the store is constructed and
> confirm `networkx` is in `requirements.txt`.

**Concretely, what to build.**
- Implement the `StateStore` contract in `haris/state/graph_store.py`, mirroring
  `InMemoryStateStore._flows` so the frozen methods are identical, then swap it in
  wherever the store is constructed (the `Orchestrator(state_store=...)` call site).
- Model the interaction graph in NetworkX **additively**: a node per agent, an edge per
  hop, with `data_type` / `data_subject` / `content` / `timestamp` on the edge. Expose it
  (`.graph`, `session_subgraph(session_id)`) for Module 11 — do not put it in the frozen
  return values.
- Surface taint for the Info-flow agent. The existing `infoflow.py` already reads
  `context["history"]` (a `list[Message]`) and extracts its own tags, so **no interface
  change is needed**; offer an additive `taint_sources(session_id)` helper as a
  convenience for the promoted agent. Taint is coarse/session-level (Step 5).
- **The read-side is already pinned by the frozen contract** (`get_lineage -> list[Message]`,
  `get_context -> {"history": [...]}`), so Module 9 can code against it today.
- Note the ordering: `Orchestrator.process()` calls `record_flow` **then** `get_context`,
  so the current hop is the last item in `history` — match that (don't exclude it).

**Subtasks (checklist):**
- [x] Implement `StateStore` over a NetworkX `MultiDiGraph`; **parity** with `InMemoryStateStore`
- [x] Record every hop as node(s) + edge(s) with `data_type` / `data_subject` / origin
- [x] `get_lineage(session_id) -> list[Message]`; `get_context -> {"history": [...]}` (frozen shapes)
- [x] Expose an additive "sources that taint this artifact" query (`taint_sources`)
- [x] Unit tests: parity, two-hop session, derived artifact, multi-subject (A and B) lineage
- [ ] Swap `GraphStateStore` in at the `Orchestrator(state_store=...)` construction site
- [ ] Add `networkx` to `requirements.txt` if not already present
- [ ] Confirm the dashboard (Module 11) reads the graph via `.graph` / `session_subgraph`

**Dependencies:** none upstream; **downstream, Module 9 depends on this** — land the
interface first.

---

## Module 7 — Secrets & PII agent (wrap Presidio + detect-secrets)

**Why it's your easiest, fastest win.** The detectors already exist and are already in
`requirements`. This module is *integration, not invention*: wrap **Presidio** (PII) and
**detect-secrets** (credentials/keys) behind the `SecurityAgent` interface. Do **not**
build your own regexes or entity models — that way lies a worse detector and a week lost.

**What "done" looks like.** A `SecurityAgent` implementation (e.g.
`haris/agents/secrets_pii.py`) that, given a `Message`, runs Presidio + detect-secrets
over the content and returns a `Verdict`: clean content yields a pass; content with PII
or a secret yields a `flag`/`redact`-worthy verdict carrying `redacted_content` with the
detected spans masked. It plugs into the orchestrator's agent list and its verdict flows
straight into the policy engine (Module 10) with no special-casing. Running it on the
hospital app must catch TC2 (verbatim PHI in an outbound message) and any planted
`credential` data type.

**Concretely, what to build.**
- Implement `SecurityAgent.__call__` (or the frozen method name) to return a `Verdict`.
- Call Presidio's analyzer/anonymizer for PII entities (names, DOB, conditions as
  configured) and detect-secrets for credentials; union the findings.
- Produce `redacted_content` by masking detected spans, so the policy engine can resolve
  a `redact` in enforce mode using the same `Verdict.redacted_content` channel the
  Info-flow spike already uses.
- Set the verdict's confidence/severity so the policy engine's threshold logic behaves.
- **Export the detector as a reusable helper** — Module 9 will call the same Presidio
  wrapper to replace its spike-grade `_extract_tags`.

**Subtasks (checklist):**
- [ ] Wrap Presidio analyzer + anonymizer behind a small internal helper
- [ ] Wrap detect-secrets for credential/key detection
- [ ] Implement the `SecurityAgent` contract; return a `Verdict` with `redacted_content`
- [ ] Map detector confidence → verdict severity so thresholds resolve correctly
- [ ] Register the agent with the orchestrator; confirm it flows into the policy engine
- [ ] Verify against TC2 (verbatim PHI) and a planted credential; confirm TC1 stays clean
- [ ] Expose the PII wrapper as a shared helper for Module 9

**Dependencies:** none. Ship early; its detector helper de-risks Module 9.

---

## Module 8 — Authorization agent (relationship rules)

**Why it needs no heavy state.** Authorization is a *stateless* check: does this
`sender → receiver → data_type` relationship satisfy the policy's relationship rules?
It reads the `Policy` schema and the message metadata and answers yes/no — it does not
need the lineage ledger, so it can be built in complete isolation from Module 6.

**What "done" looks like.** A `SecurityAgent` implementation (e.g.
`haris/agents/authorization.py`) that reads the relationship rules from the `Policy`
contract and, for each `Message`, checks whether the `sender`, `receiver`, and
`data_type` (from `Message.metadata`) form an allowed combination. On a disallowed
combination — e.g. `summary`/`PHI` heading to an **external** recipient rather than
`doctor@hospital.internal` — it returns a `block`/`flag` verdict; on an allowed one, a
pass. This is what makes the emailer's two-recipient choice a real security question
(TC5, external recipient) rather than a formality.

**Concretely, what to build.**
- Load relationship rules from the frozen `Policy` schema (sender→receiver→data_type
  allow/deny); do not hardcode the hospital's specifics into the agent.
- Read `sender`, `receiver`, and `data_type`/`recipient` from the `Message` and its
  `metadata` (Phase 1 stashes `data_type` and `recipient` there at each hop).
- Return a `Verdict`: allowed → pass; disallowed → `block` (or `flag`, per policy) with a
  human-readable reason for the audit log.
- Keep the rule evaluation pure and table-driven so new relationships are data, not code.

**Subtasks (checklist):**
- [ ] Parse relationship rules from the `Policy` schema into a lookup
- [ ] Implement the `SecurityAgent` contract; evaluate `sender→receiver→data_type`
- [ ] Read recipient/data_type from `Message.metadata` as populated by the pipeline
- [ ] Emit a clear reason string on denial for the audit trail
- [ ] Verify TC5 (external recipient) is blocked/flagged; internal recipient passes
- [ ] Unit tests over the rule table (allowed, denied, unknown data_type)

**Dependencies:** none — reads the policy schema only; fully parallel.

---

## Module 9 — Information-flow agent (the flagship)

**Why this is the hard, novel one — give it the most time.** This is the capability that
separates Haris from a per-message scanner: catching the **derived** leak (TC3), where
the summary carries no verbatim record text but still leaks identifying detail that
originated in a PHI source. A regex scanner sees ordinary prose and misses it. The
Step 5 spike **already proved this works** (`haris/agents/infoflow.py` catches TC3 and
correctly passes the clean derivation TC1) — Phase 2's job is to graduate that spike
into the MVP agent, not to reinvent it.

**What "done" looks like.** The Information-flow agent consults the **real lineage
ledger** (Module 6) to decide whether the data in the current message is *allowed to
reach this destination*, given where it came from. It tags data at its PHI source,
recognizes the taint resurfacing downstream even after paraphrasing, and — when tainted
data heads somewhere it shouldn't — emits a `flag` verdict with `redacted_content`
(identifiers masked), which the policy engine resolves to `redact`/`block` in enforce
mode. The spike's session-history read is replaced by real ledger queries, and its
spike-grade `_extract_tags` is replaced by **Module 7's Presidio wrapper**. The honest
semantic-paraphrase ceiling (identifier itself reworded) stays a documented roadmap
item, not a Phase 2 blocker.

**Concretely, what to build (promote the spike).**
- Swap the spike's `context`-based session read for **Module 6's lineage ledger** query
  ("what sources taint this artifact, with origin + `data_subject`").
- Replace spike-grade `_extract_tags` with **Module 7's Presidio detector** so taint tags
  come from a real PII detector, not structured-field parsing.
- Add the **destination rule**: given the taint origin/subject and the message's
  destination (recipient/data_type from metadata), decide allowed vs. not — this is the
  "info-flow" judgment, distinct from Module 8's relationship check.
- Keep emitting a `flag` verdict with masked `redacted_content` so the policy engine
  composes it with the other agents' verdicts unchanged.
- Preserve the honest scorecard: TC3 caught, TC1 clean, semantic paraphrase documented as
  the known ceiling (keep `test_semantic_paraphrase_is_missed_the_ceiling` green as a
  living limit, not a bug).

**Subtasks (checklist):**
- [ ] Repoint the agent from spike session-history to Module 6's lineage ledger
- [ ] Replace `_extract_tags` with Module 7's Presidio wrapper for real taint tags
- [ ] Implement the destination decision: tainted origin/subject vs. this destination
- [ ] Emit `flag` + `redacted_content`; confirm the policy engine resolves it in enforce
- [ ] Re-run the scorecard: TC3 CATCH, TC1 pass, TC2 caught, paraphrase = documented miss
- [ ] Keep the semantic-ceiling test green as an honest, documented limit
- [ ] Note over-tainting behavior in comments; rely on the identifier check to bound it

**Dependencies:** **blocked on Module 6's ledger interface**; **benefits from Module 7's
detector.** Start against Module 6's frozen read-side API as soon as it lands.

---

## Module 10 — Policy engine (verdicts + thresholds + mode → final decision)

**Why it pairs with the orchestrator.** Each agent returns its own `Verdict`; something
has to combine them into one final `allow` / `redact` / `block` / `flag` `Decision`,
respecting thresholds and the current mode (monitor vs. enforce). That combiner is the
policy engine, and it lives right next to the orchestrator that collects the verdicts —
so build them as a pair.

**What "done" looks like.** `haris/policy/engine.py` (whose `resolve()` already resolves a verdict set via
threshold → most-restrictive → redaction-compose → mode-gate, with passing tests) is
extended to consume the **real multi-agent verdicts** from Modules 7, 8, and 9 and emit
the final `Decision`. Most-restrictive wins (a `block` beats a `redact` beats a `flag`
beats `allow`); multiple `redact` verdicts **compose** their `redacted_content` rather
than clobbering each other; the mode gate downgrades enforcement to logging in monitor
mode. Wired through the orchestrator, a hospital run produces one coherent decision per
hop with every contributing verdict recorded in the audit log.

**Concretely, what to build.**
- Extend the existing resolver to accept the verdict list the orchestrator now collects
  from real agents (don't rewrite the passing threshold/most-restrictive logic — build
  on it).
- Make **redaction composition** correct when two agents both redact the same content
  (e.g. Secrets/PII masks a name and Info-flow masks a derived identifier) — union the
  masks, don't let the last writer win.
- Honor the mode gate: in monitor mode every `Decision` stays observational and logged;
  in enforce mode `redact`/`block` actually alter/stop the message via the proven
  interception seam.
- Wire the composed decision through the orchestrator and ensure each verdict + the final
  decision land in the audit log (for Module 11).

**Subtasks (checklist):**
- [ ] Feed real multi-agent verdicts (Modules 7/8/9) into `haris/policy/engine.py`
- [ ] Confirm most-restrictive ordering: block > redact > flag > allow
- [ ] Make multi-redaction compose (union masks) rather than overwrite
- [ ] Verify the mode gate: monitor = log only; enforce = modify/block via the seam
- [ ] Wire the final `Decision` + contributing verdicts into the orchestrator + audit log
- [ ] Tests: conflicting verdicts, double-redaction, monitor vs. enforce on TC2/TC3/TC5

**Dependencies:** consumes Modules 7/8/9's verdicts (can develop against stub verdicts
first); pairs with the orchestrator.

---

## Module 11 — Streamlit dashboard (interaction graph + audit log)

**Why it can be built alongside everything.** The dashboard depends only on the **shape
of the event/audit log** and the interaction graph the state store already produces —
not on any agent's internals. Agree the log schema early and this module never blocks on
anyone; it reads what the pipeline writes.

**What "done" looks like.** A **Streamlit** app that renders (a) the **interaction
graph** — the NetworkX graph from Module 6, showing agents as nodes and data flows as
edges, with `data_type` / `data_subject` on the flows — and (b) the **audit log** — a
chronological, filterable table of every hop: sender, receiver, data_type, each agent's
verdict, and the final `Decision` (allow/redact/block/flag) with mode. A reviewer can run
the hospital app, open the dashboard, and *see* TC2/TC3/TC5 being caught: which agent
fired, what got redacted, and why the message was allowed, redacted, or blocked.

**Concretely, what to build.**
- Read the audit/event log the orchestrator + policy engine write; **agree its schema
  with Module 10/6 up front** and depend only on that.
- Render the interaction graph from Module 6's NetworkX structure (e.g. via networkx +
  a Streamlit-friendly renderer) with per-edge data_type/subject.
- Build the audit table: one row per hop, columns for sender/receiver/data_type, per-agent
  verdicts, final decision, mode; add filters by session, decision type, and data_subject.
- Make it read-only and side-effect-free — it observes the log, it never touches the
  pipeline (streaming/observe-only is exactly the seam Step 2 flagged as dashboard-grade).

**Subtasks (checklist):**
- [ ] Fix the event/audit-log schema with Modules 6 and 10; depend only on it
- [ ] Streamlit page 1: render the Module 6 interaction graph (nodes = agents, edges = flows)
- [ ] Streamlit page 2: audit table (hop, sender/receiver, data_type, verdicts, decision)
- [ ] Add filters: by session, by decision (allow/redact/block/flag), by data_subject
- [ ] Demo pass: run the hospital app and show TC2/TC3/TC5 being caught in the UI
- [ ] Keep it strictly read-only over the log — no pipeline side effects

**Dependencies:** the event-log format only (coordinate with Modules 6 and 10);
otherwise fully parallel.

---

## Suggested board setup (new "Haris Phase 2" board)

Six draft cards, one per module, each pasting the checklist above into its body.
Columns: **Todo / In Progress / Done** (same as Phase 0 and Phase 1).

Recommended card titles:
1. `Module 6 — State store: NetworkX interaction graph + lineage ledger`
2. `Module 7 — Secrets & PII agent (Presidio + detect-secrets)`
3. `Module 8 — Authorization agent (relationship rules)`
4. `[FLAGSHIP] Module 9 — Information-flow agent (promote the Step 5 spike)`
5. `Module 10 — Policy engine (verdict composition + mode gate)`
6. `Module 11 — Streamlit dashboard (graph + audit log)`

Suggested labels/fields if your board supports them: mark card 4 as `flagship`; set
card 4 (Info-flow) as **blocked-by** card 1 (State store) until the ledger interface is
frozen; and note that cards 1 (State store) and 2 (Secrets/PII) should be picked up
first because they unblock the flagship. Everything else runs fully in parallel.
