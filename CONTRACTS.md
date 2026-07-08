# Haris — the five frozen contracts

These are the frozen interfaces the rest of the system is built against. "Frozen"
means new fields may be added later, but existing fields must not be changed or
removed without coordinating first, since other components depend on them.

---

## 1. Message — `haris/schemas/message.py`

The single object that represents one message moving between two agents. Every
part of Haris speaks in Messages.

- `session_id` — which run/conversation this belongs to. Ties related messages
  together so the state store can reconstruct one session's history.
- `sender` — the agent the message came from (e.g. `record_reader`).
- `receiver` — the agent it's going to (e.g. `summarizer`).
- `content` — the actual text/payload being passed.
- `timestamp` — when it happened; auto-filled, so you never set it by hand.
- `metadata` — a free-form dict for anything extra (tool name, data type, etc.)
  without changing the schema. This is your escape hatch: put new stuff here
  instead of adding fields and re-freezing.

Agree on: the five core fields are enough to describe any hop in the hospital demo.

---

## 2. Verdict — `haris/schemas/verdict.py`

What every security agent hands back after inspecting a message. One shape for
all three agents, so the orchestrator treats them uniformly.

- `agent_name` — who produced this verdict (for logging/debugging).
- `label` — the decision, one of three: `pass`, `flag`, `block`.
    - `pass` = nothing wrong.
    - `flag` = suspicious; in monitor mode this is logged but not acted on.
    - `block` = would stop the message — only enforced later, in enforce mode.
- `score` — a 0–1 confidence, so you can set thresholds ("only act above 0.8").
- `reason` — human-readable explanation; drives the dashboard and your demo story.
- `redacted_content` — optional cleaned version (e.g. PII masked). Present only
  when an agent rewrote the content; otherwise left empty.

Agree on: three labels are enough, and score is 0–1.

---

## 3. SecurityAgent — `haris/agents/base.py`

The interface all three MVP agents (Secrets & PII, Authorization,
Information-flow) must implement. This is the contract that lets two people build
different agents in parallel without coordinating.

- `check(message, context) -> Verdict` — the one method. Given a message and some
  context, return a Verdict. That's the whole promise.
- `context` — a dict the orchestrator passes in (comes from the state store's
  `get_context`), so an agent can see history, not just the current message.

Agree on: every agent takes `(message, context)` and returns exactly one Verdict.

---

## 4. StateStore — `haris/state/base.py`

The interface for "Haris's memory" — what has flowed through the system. The real
version is built against this interface; the in-memory one already works so
development isn't blocked while it's in progress.

- `get_context(session_id)` — hand an agent what it needs to know about the
  session so far.
- `record_flow(message)` — remember that a message happened.
- `get_lineage(session_id)` — return the ordered history for a session; this is
  what the Information-flow agent and the dashboard will read.

Agree on: these three methods cover what agents and the dashboard need.

---

## 5. Policy — `haris/schemas/policy.py`

The rules Haris enforces, plus how strict to be and whether it's even allowed to
block yet.

- `rules` — a list of `PolicyRule`, each: `{sender, receiver, data_type, action}`
  — "when THIS sender sends THIS data_type to THIS receiver, do THIS action"
  (allow / deny / redact).
    - `data_subject` (optional) — reserved now so subject-aware authorization
      (patient-A's data must not reach patient-B's context) isn't designed out.
      You don't use it yet — you just kept the door open.
- `thresholds` — score cutoffs per agent, so policy (not code) decides how
  aggressive each agent is.
- `mode` — `monitor` or `enforce`. Phase 0 runs `monitor`: flags and blocks are
  logged but nothing is ever stopped, so a false positive can't break the demo.
  You flip to `enforce` in a later phase.

Agree on: the rule shape, keeping `data_subject` reserved, and starting in monitor.

---

## Freezing the contracts

Once all five interfaces have been reviewed and agreed, they are considered
frozen. Any later change to an existing field must be coordinated before it is
committed, since every other component is built against these shapes.
