# Haris-Team23

A security layer for multi-agent LLM apps. Haris sits **between** agents, inspects every
inter-agent message, and blocks, redacts or flags secrets/PII leaks, unauthorized flows and
cross-subject data mixing before the message reaches the next agent.

The threat model it is built against: **one agent in a multi-agent system is compromised.**
Everything that agent puts in a message — including the metadata saying who it is and where
the message is going — is attacker-controlled. See `THREAT_MODEL.md`.

## What actually ships

This README said `monitor first`, three agents, and no dashboard until 2026-08-24, by which
point all three were wrong. What is in the repo today:

- **Five security agents**, all wired into the shipped pipeline
  (`demo_app/hospital/haris_pipeline.py:build_hospital_agents`):

  | agent | catches |
  |---|---|
  | `secrets_pii` | names, MRNs, credentials in message content (Presidio + detect-secrets) |
  | `authorization` | sender→receiver relationship and egress outside the trust boundary |
  | `subject_binding` | a second data subject entering a session bound to the first |
  | `infoflow` | data *derived* from a sensitive source leaving the boundary (lineage) |
  | `identity` | a forged sender — a per-agent bearer token bound by the adapter, not the sender |

  Injection and Semantic detection remain **roadmap, not built**, and the dashboard labels
  them `PLANNED`.

- **Enforce is the default.** `run_secured(..., mode=Mode.ENFORCE)` blocks for real: a
  blocked hop raises `HarisBlocked` inside the graph and the message never reaches the next
  agent. `Mode.MONITOR` clamps every action to at most `flag`, and is what you use while
  tuning. The mode gate lives in `haris/policy/engine.py`; the semantics are in
  `ENFORCEMENT.md`.

- **It is not default-deny.** `Policy.rules` and `Policy.default_action` are declared and
  read by nothing. What is enforced is a *sender* allow-list (the identity token table) plus
  the content, subject and destination checks. `THREAT_MODEL.md` §9 has the measured table
  and the residual risk.

- **A tamper-evident audit log** (`haris/audit.py`): hash-chained, HMAC-keyed when
  `HARIS_AUDIT_KEY` is set, storing content **hashes and metadata rather than message
  bodies** by default. Truncation is detectable against a checkpoint held outside the log.

- **A Streamlit operator dashboard** (`demo_app/dashboard.py`) reading that audit log —
  KPIs, a per-hop audit table, an interaction graph and an incident feed.

- **A 312-scenario evaluation** across 4 domains × 3 topologies × 13 families
  (`demo_app/eval/`), scored by an outcome-based leak metric that is independent of Haris's
  own verdicts, plus a third-party label check. `EVAL_DESIGN.md` carries the design, the
  current numbers, and an honest reading of what they do and do not show.

## Getting started

    python -m venv .venv
    source .venv/bin/activate                  # Windows: .venv\Scripts\activate
    pip install -r requirements.txt
    python -m spacy download en_core_web_sm    # REQUIRED for the secrets/PII agent
    pytest                                     # the full suite

`en_core_web_sm` is not a pip dependency and has to be downloaded separately. Without it the
Presidio path is unavailable; every entry point detects that and runs the other four agents,
so nothing crashes — but the PII results will be missing.

## Running it

    # the hospital app end to end through the full secured pipeline, ENFORCE
    python -m demo_app.hospital.haris_pipeline

    # single-point demos
    python -m demo_app.hospital.subject_demo      # TC4: a second patient in one session
    python -m demo_app.hospital.identity_demo     # a forged sender
    python -m demo_app.hospital.audit_demo        # the hash chain, and tampering with it
    python -m demo_app.hospital.notify_demo       # alert routing
    python -m demo_app.hospital.latency_report    # per-hop overhead

    # the evaluation
    python -m demo_app.eval.simulate              # 312 scenarios, all arms
    python -m demo_app.eval.external_check        # third-party label confirmation

    # the operator dashboard
    export HARIS_DASHBOARD_TOKEN=$(python -c "import secrets;print(secrets.token_urlsafe(24))")
    streamlit run demo_app/dashboard.py

The dashboard **refuses to start without `HARIS_DASHBOARD_TOKEN`** — it renders the audit
log, which concerns protected traffic, so it is gated rather than open. Two other environment
variables are optional: `HARIS_AUDIT_KEY` makes the audit chain keyed (set it in any real
deployment), and `HARIS_ALERT_WEBHOOK` points alerts at a Slack or Discord incoming webhook.
Generate these locally; never commit one.

## Project structure

    haris/
      schemas/        # frozen contracts: Message, Verdict, Decision, Policy, Notification
      agents/         # SecurityAgent interface + the five shipped agents
      state/          # StateStore interface: in-memory + NetworkX lineage graph
      orchestrator/   # routes one message through the agents to a Decision
      policy/         # decision composition + the monitor/enforce mode gate
      notify/         # notifier, channels, health checks
      audit.py        # the tamper-evident security-audit log
    demo_app/
      hospital/       # the vulnerable demo app, the secured pipeline, the demos
      eval/           # scenario generator, arms, metrics, golden-file guard
      dashboard*.py   # the Streamlit operator view
    tests/            # the full suite

## Documents

| file | what it covers |
|---|---|
| `THREAT_MODEL.md` | the attacker, what is defended, what is not, and the measured rules |
| `ENFORCEMENT.md` | how verdicts compose into one action, and the mode gate |
| `EVAL_DESIGN.md` | the corpus, the metrics, current results, honest reading |
| `DEMOscenario.md` | the hospital scenario and its test cases |
| `CONTRACTS.md`, `SCOPE_FREEZE.md` | frozen interfaces, and what is out of scope |

**Framework scope:** LangGraph only. Haris's core (`haris/`) has no framework dependency;
the LangGraph binding is one adapter in `demo_app/langgraph_interception.py`.
