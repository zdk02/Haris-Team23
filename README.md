# Haris-Team23

A security layer for multi-agent LLM apps. Haris sits **between** agents, inspects every
inter-agent message, and blocks, redacts or flags secrets/PII leaks, unauthorized flows and
cross-subject data mixing before the message reaches the next agent.

The threat model it is built against: **one agent in a multi-agent system is compromised.**
Everything that agent puts in a message — including the metadata saying who it is and where
the message is going — is attacker-controlled. See `THREAT_MODEL.md`.

**Live dashboard:** https://haris-monitor.com — read-only, replaying a recorded scenario
battery over synthetic data. The sign-in token is in Section 5 of the report, and is
rotated after assessment.

---

## Quick start

Four commands from a clean machine to the running operator dashboard. Docker Desktop must be
running. Docker is the supported path — the image is the artefact we ship and the one the
evaluation numbers were reproduced on.

```bash
git clone https://github.com/zdk02/Haris-Team23.git
cd Haris-Team23
cp .env.example .env          # then open .env and set HARIS_DASHBOARD_TOKEN
docker compose up --build
```

Then open **http://localhost:8501** and sign in with the token you just set. The first load
takes up to 90 seconds — it initialises Presidio and spaCy and replays the demo battery. The
container reports `unhealthy` until that finishes; that is expected, not a failure.

Generate a token with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(24))"
```

To reproduce the evaluation from the same container:

```bash
docker compose exec dashboard python -m demo_app.eval.simulate
```

That run takes a few minutes and prints the four headline rates below. They should match
report §6 exactly; if they do not, the report is wrong, not the run.

## Results at a glance

Measured on the 576-scenario generated corpus, with 95% confidence intervals:

| metric | Haris |
|---|---|
| exfiltration prevented | 73% [67–78] |
| boundary crossings prevented | 100% [94–100] |
| false positives | 12% [8–17] |
| detection rate | 76% |

The single-rule baseline in report §6.4.2 scores higher on exfiltration alone. It does so by
blocking every external send — at double the false-positive rate, and catching none of the
48 boundary crossings. §6.4.2 is the place to read that comparison in full.

---

## What ships

- **Five security agents**, all wired into the shipped pipeline
  (`demo_app/hospital/haris_pipeline.py:build_hospital_agents`):

  | agent | catches |
  |---|---|
  | `secrets_pii` | names, MRNs, credentials in message content (Presidio + detect-secrets) |
  | `authorization` | sender→receiver relationship and egress outside the trust boundary |
  | `subject_binding` | a second data subject entering a session bound to the first |
  | `infoflow` | data *derived* from a sensitive source leaving the boundary (lineage) |
  | `identity` | a forged sender — a per-agent bearer token bound by the adapter, not the sender |

  Injection and semantic detection remain **roadmap, not built**, and the dashboard labels
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
  The chain is verified by in-process replay; it is not a durable store — see report §8.

- **A Streamlit operator dashboard** (`demo_app/dashboard.py`) reading that audit log —
  KPIs, a per-hop audit table, an interaction graph and an incident feed.

- **A 576-scenario evaluation** across 4 domains × 3 topologies × 24 threat families
  (`demo_app/eval/`), scored by an outcome-based leak metric that does not consult Haris's
  own verdicts, plus a label-consistency check over the generated labels. `EVAL_DESIGN.md`
  carries the design, the current numbers, and an honest reading of what they do and do not
  show.

## Running from source

Only needed if you want to work on the code; the container above is the supported path.

```bash
python -m venv .venv
source .venv/bin/activate                  # Windows: .venv\Scripts\activate
pip install -r requirements.lock.txt
pytest                                     # the full suite
```

`requirements.lock.txt` is the exact closure the shipped image installs — use it rather than
`requirements.txt` so that what you test is what we ship. It includes the `en_core_web_sm`
model the secrets/PII agent needs. If that model is unavailable for any reason, every entry
point detects it and runs the other four agents, so nothing crashes — but the PII results
will be missing.

## Other entry points

```bash
# the hospital app end to end through the full secured pipeline, ENFORCE
python -m demo_app.hospital.haris_pipeline

# single-point demos
python -m demo_app.hospital.subject_demo      # TC4: a second patient in one session
python -m demo_app.hospital.identity_demo     # a forged sender
python -m demo_app.hospital.audit_demo        # the hash chain, and tampering with it
python -m demo_app.hospital.notify_demo       # alert routing
python -m demo_app.hospital.latency_report    # per-hop overhead

# the evaluation
python -m demo_app.eval.simulate              # 576 scenarios, all arms
python -m demo_app.eval.external_check        # label-consistency check

# the operator dashboard, outside Docker
export HARIS_DASHBOARD_TOKEN=$(python -c "import secrets;print(secrets.token_urlsafe(24))")
streamlit run demo_app/dashboard.py
```

## Environment

| variable | required | what it does |
|---|---|---|
| `HARIS_DASHBOARD_TOKEN` | yes | sign-in token for the dashboard |
| `HARIS_AUDIT_KEY` | in any real deployment | makes the audit chain HMAC-keyed |
| `HARIS_ALERT_WEBHOOK` | no | points alerts at a Slack or Discord incoming webhook |

The dashboard **refuses to start without `HARIS_DASHBOARD_TOKEN`** — it renders the audit
log, which concerns protected traffic, so it is gated rather than open. Generate these
locally; never commit one. `.env` is gitignored; `.env.example` carries the names and the
reasoning, no values.

Leaving `HARIS_AUDIT_KEY` blank is a working configuration but a weaker one: the chain
becomes corruption-evident rather than tamper-evident, because anyone who can write the log
can also recompute it. The deployed task takes this from Secrets Manager.

## Project structure

```
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
docs/history/     # phase plans and scaffolding, kept for provenance
```

## Documents

| file | what it covers |
|---|---|
| `THREAT_MODEL.md` | the attacker, what is defended, what is not, and the measured rules |
| `ENFORCEMENT.md` | how verdicts compose into one action, and the mode gate |
| `EVAL_DESIGN.md` | the corpus, the metrics, current results, honest reading |
| `DEMOscenario.md` | the hospital scenario and its test cases |
| `CONTRACTS.md`, `SCOPE_FREEZE.md` | frozen interfaces, and what is in and out of scope |

**Framework scope:** LangGraph only. Haris's core (`haris/`) has no framework dependency;
the LangGraph binding is one adapter in `demo_app/langgraph_interception.py`.