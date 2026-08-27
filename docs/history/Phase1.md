# Haris — Phase 1: The Spine

**Phase goal:** get one real message flowing end-to-end through a do-nothing Haris,
sitting inside a real LangGraph app, with the two scariest unknowns (interception
and data-lineage) de-risked by throwaway spikes *before* anything is built on top
of them. 

**What Phase 0 already gave us:**
- The five frozen contracts — `Message`, `Verdict`, `SecurityAgent`, `StateStore`,
  `Policy` — plus the 6th `Decision`/enforcement contract.
- A do-nothing `Orchestrator` (zero agents, monitor mode) that logs every hop.
- The `policy/engine.py` resolver (threshold → most-restrictive → redaction-compose
  → mode-gate) and its passing test suite.
- An abstract `InterceptionAdapter` and an `InMemoryStateStore`.
- `run_demo.py`, which pushes ONE hardcoded message through the abstract adapter.

**What Phase 1 has to actually build:** a real LangGraph app, real
LangGraph message interception, real wiring of the two together, and coarse taint /
lineage tracking. `run_demo.py` is a stand-in that Phase 1 replaces with real graph
integration.

---

## Step 2 — [SPIKE] Prove you can intercept LangGraph messages

**Why this is first** The entire product is premised on Haris sitting
*between* agents and seeing every message. If LangGraph won't let us observe — and
later modify or block — the messages passing between nodes, the architecture doesn't
work and we need to know immediately. This is a throwaway experiment in isolation:
a tiny 2-agent graph, whose only job is to print every message that crosses the wire.

**What "done" looks like.** A small script that builds a 2-node LangGraph graph
(agent A → agent B sharing state), runs it, and prints — for every hop — the sender,
the receiver, and the content. Plus a short written finding (a few paragraphs in the
repo) naming the interception mechanism we'll standardize on and answering the one
question that actually matters: *can we modify/block a message mid-flight, or only
observe it after the fact?* The answer changes how enforce mode is designed.

**Subtasks (checklist):**
- [ ] Scaffold a tiny 2-node LangGraph graph (A → B) over a shared state object
- [ ] Try node-wrapper interception: wrap each node fn, log state before & after
- [ ] Try stream-based observation: `graph.stream(...)` across `stream_mode` values
- [ ] Confirm we can read sender, receiver, and content for each hop
- [ ] Confirm we can MODIFY a message mid-flight (not just read it) — the critical bit
- [ ] Write the findings note: chosen mechanism, can-we-block/modify?, limitations
- [ ] Timebox check: stop at ~1 day and report even if the answer is partial

**Deliverable** is a decision + a print-everything script, not polish.

---

## Step 3 — Minimal vulnerable demo app (the 3-agent hospital app)

**Why build it early.** This one app is three things at once: the test fixture every
test case runs against, the integration target Haris hooks into, and the final demo we
show. Building it now means every later step has something real to run against. Keep it
deliberately ugly and deliberately vulnerable — the point is that it *leaks*, so Haris
has something to catch.

**What "done" looks like.** A runnable LangGraph app implementing
`record_reader → summarizer → emailer` over shared state, with fake data for at least
two patients (A and B) so subject-confusion cases are possible later. `record_reader`
loads a patient record containing PHI; `summarizer` produces derived "summary" content
(which can, by design, still carry identifying detail); `emailer` "sends" the summary
to a configurable recipient — the internal `doctor@hospital.internal` or an external
address — by just logging it, not sending real email. No Haris yet. Running it should
reproduce the raw material for the threat-model test cases: a verbatim-PHI path (TC2)
and an external-recipient path (TC5) that a human can trigger by hand.

**Design notes to get right.** Match the frozen `DEMOscenario.md`: node names are
exactly `record_reader`, `summarizer`, `emailer`; data types are `PHI`, `summary`,
`credential`; every record carries a `data_subject` (which patient) even though the
policy doesn't use it yet. The emailer's two-recipient choice is what makes
authorization a real question rather than a formality, so keep the recipient
configurable. Note in code the exact seams where Haris will later intercept (the two
hops) so Step 4 is a wiring job, not a redesign.

**Subtasks (checklist):**
- [ ] Define fake patient records for A and B (name, DOB, condition, + `data_subject`)
- [ ] `record_reader` node: load a chosen record's raw PHI into shared state
- [ ] `summarizer` node: produce a derived summary (allowed to carry identifiers)
- [ ] `emailer` node: "send" to a configurable recipient (internal/external), log it
- [ ] Compile as a LangGraph graph with an explicit shared-state schema
- [ ] Add an entrypoint to run one scenario end-to-end (e.g. `python -m demo_app.hospital`)
- [ ] Hand-reproduce TC2 (verbatim leak) and TC5 (external recipient) to confirm it leaks
- [ ] Mark the two interception seams in comments for Step 4

---

## Step 4 — Pass-through pipeline skeleton (end-to-end do-nothing Haris)

**Why this is the milestone that unlocks everything.** Once one real message flows
from the hospital app, through Haris interception, into the orchestrator (zero agents,
just logging), and continues to the next agent unchanged — the whole architecture is
proven end-to-end and every remaining task becomes "fill in a box" (write an agent,
turn on a policy rule). This step connects the abstract skeleton already in the repo
to the REAL LangGraph app from Step 3, using the REAL interception seam from Step 2.
`run_demo.py` (one hardcoded message through the abstract adapter) is the stand-in this
step retires.

**What "done" looks like.** The hospital app runs and behaves *identically* to Step 3
— nothing is blocked, nothing is changed — but now every inter-agent hop is
intercepted: a `Message` is constructed with the correct sender/receiver and useful
`metadata` (data_type, recipient), passed through `orchestrator.process()`, logged,
recorded in the state store, and the content continues on. Because the orchestrator has
zero agents and runs in monitor mode, every `Decision` is a pass-through. Verifiable
signal: `get_lineage(session_id)` grows to the full session history (both hops), and a
smoke test confirms `decision.action == allow` with content delivered unchanged.

**The wiring, concretely.** Take the seam chosen in Step 2 and insert the
`InterceptionAdapter` at the two hospital hops (`record_reader → summarizer` and
`summarizer → emailer`). At each hop, build the `Message` from the real state — real
sender, real receiver, real content — and stash data_type/recipient in `metadata` so
the agents written later have what they need. Keep the orchestrator at zero agents:
this step proves the *plumbing*, not detection.

**Subtasks (checklist):**
- [ ] Adapt `InterceptionAdapter` to the Step-2 LangGraph seam (real hop content)
- [ ] Insert interception at both hops: `record_reader→summarizer`, `summarizer→emailer`
- [ ] Each hop: construct `Message` with correct sender/receiver + `metadata`
- [ ] Confirm the zero-agent monitor orchestrator logs every hop and passes content unchanged
- [ ] Confirm the state store records each flow; `get_lineage` returns the full history
- [ ] End-to-end run: app behaves identically, Haris logs every message
- [ ] Add a smoke test: message flows through, `action == allow`, lineage complete

**Dependencies:** blocked by Step 2 (seam) and Step 3 (app).

---

## Step 5 — [SPIKE] Prove coarse data-lineage tracking (taint / propagation tags)

**Why this is the flagship de-risker.** The one capability that separates Haris from a
plain per-message scanner is catching the *derived* leak — TC3, where the summary
carries no verbatim record text but still leaks identifying detail that originated in a
PHI source. A regex scanner sees ordinary prose and misses it. The only way to catch it
is lineage: tag data at its source and recognize it when it resurfaces downstream, even
after it's been rewritten. This spike proves whether that's feasible and *how well* it
works — honestly, including its false-positive/false-negative behavior — before we build
the Information-flow agent on top of it.

**What "done" looks like.** A demo where patient A's PHI is tagged at the source
(`record_reader`), the `summarizer` derives a paraphrased summary, and Haris detects at
the `emailer` hop that "this content is tainted by PHI from patient A" — using
propagation tags carried with the data, **not** by string-matching the original record
text. Plus an honest written finding: how coarse the tracking is, whether it survives
real LLM paraphrasing, and where it produces false positives/negatives. That finding is
what tells us whether coarse tagging is enough for the Info-flow agent or whether we
need something finer.

**The core idea and the options.** Exact string matching fails on TC3 because the
summarizer rewrites the words; propagation tags survive rewriting because they travel
with the data object, not the text. Representation options to try: carrying a taint
label (origin + `data_subject`) in `Message.metadata` / shared state; wrapping data in a
tainted-value type; or tracing origin via the `StateStore` lineage (`get_lineage`)
that Phase 0 already exposes. The honest part matters most: coarse tagging will
over-taint (everything downstream of a PHI read looks tainted) — the spike measures how
badly, so we know its real limits before betting the flagship test case on it.

**Subtasks (checklist):**
- [ ] Decide the tag representation (taint label + `data_subject`; metadata vs state)
- [ ] Tag PHI at the source node (`record_reader`) with origin + subject
- [ ] Propagate the tag through the `summarizer` so derived data keeps the source taint
- [ ] Detect tainted origin at a later hop WITHOUT any exact string match
- [ ] Test against TC3: a paraphrased summary is still flagged as PHI-derived
- [ ] Stress it: does the tag survive real LLM rewriting? measure false pos/neg
- [ ] Write the findings note: how coarse, limitations, is it enough for Info-flow?
- [ ] Timebox check: report feasibility honestly even if the result is partial

**Timebox:** hard. This is a spike — the output is a feasibility answer and a finding,
not a production info-flow engine.