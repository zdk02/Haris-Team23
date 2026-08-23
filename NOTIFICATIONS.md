# Notifications — what alerts a human, and how

Five files cited this document (`haris/notify/notifier.py`, `haris/notify/__init__.py`,
`haris/notify/channels.py`, `haris/schemas/notification.py`, `THREAT_MODEL.md` §5) before it
existed. Written 2026-08-24 from the code as it actually behaves; every claim below is
checked against `tests/test_notify.py` and `tests/test_shipped_pipeline_wiring.py`.

The question it answers is the mentor's: **if something goes wrong, how do we know?** A
guard that fails silently is worse than no guard, because it is trusted.

## The shape

Everything is one object, `NotificationEvent` (`haris/schemas/notification.py`) — the same
way every agent returns one `Verdict`. A crashed detector, a blocked leak and a failed health
check all arrive at the Notifier in the same shape, so routing needs no special cases.

    category   operational | security | client_error
    severity   info | warning | critical
    source     which component raised it
    summary    SANITIZED, human-readable — never a raw secret
    reference  content_sha256: a pointer into the audit log, not the data
    session_id ties the alert to a session
    metadata   free-form; kept for the internal log, STRIPPED before any channel

## Triggers

| # | when | category · severity | raised in |
|---|---|---|---|
| T1 | a detector crashed, failing **closed** (enforce) | operational · critical | `orchestrator._safe_check` |
| T2 | a detector crashed, failing **open** (monitor) | operational · critical | `orchestrator._safe_check` |
| T3 | a health probe failed | operational · critical | `HealthCheck.check` |
| T4 | a message was **blocked** | security · warning | `Orchestrator.process` |

T4 fires only in enforce mode, because monitor clamps BLOCK to FLAG before the engine
returns — so an alert saying "blocked" always means a message really was stopped.

`NotificationEvent.client_error` exists in the schema for the protected app to report its
own failures. **Nothing calls it.** It is a constructor with no trigger site, and saying
otherwise would be the kind of claim the rest of this repo has been correcting.

## Routing

Each channel declares `min_severity`; the Notifier sends an event to a channel only if the
event is at least that severe. Channels never do their own filtering.

| channel | default `min_severity` | where it goes |
|---|---|---|
| `BufferChannel` | warning | an in-memory ring of the last 50 alerts — the dashboard's incident banner, and `run_secured(...)["alerts"]` |
| `WebhookChannel` | critical | POSTs to a Slack or Discord incoming webhook |

The shipped pipeline constructs **both**, and lowers the webhook to `warning`, because a
blocked leak is a WARNING and is precisely what an operator must be told about. Two separate
defects lived here and both are fixed: the webhook's default filtered T4 out, and a
`WebhookChannel` with no `HARIS_ALERT_WEBHOOK` set is a silent no-op — so on any machine
without one configured, "the operator is alerted" described nothing at all. The
`BufferChannel` is what makes the alert land somewhere with zero configuration.
`tests/test_shipped_pipeline_wiring.py::test_a_blocked_leak_actually_reaches_a_channel`
asserts the alert arrives, not that a notifier object exists.

Set `HARIS_ALERT_WEBHOOK` to a Slack or Discord incoming-webhook URL to add the out-of-band
push. The channel detects the platform from the URL. Never commit the URL.

## The three rules the Notifier enforces

1. **De-duplicate.** A crashing detector fires on every hop. Identical events — same
   `(category, source, summary)` — inside a 60-second window collapse into one alert, and
   the next one that gets through says `(+N similar suppressed)`. The collapse is visible,
   not silent.
2. **Always log.** Every event that survives de-dup goes to the Tier-1 operational logger
   (`haris/logging_config.py`) at a level matching its severity, **with** metadata. The log
   is the complete record even when every external channel is off. Note that this tier needs
   `configure_logging()` to have a destination at all — `logging.basicConfig` does not reach
   it, because `configure_logging` sets `propagate=False` on the `haris` namespace.
3. **Sanitize at the boundary.** Channels receive a copy with `metadata` emptied. That field
   is the one place a raw detail could ride along, and it stops at the process edge. The
   summary carries sender, receiver and data type; the secret itself is never in an alert.
   `reference` is the content hash, so an operator can find the full record in the audit log.

A channel that raises is contained and logged — a broken alerter must not become an outage,
the same posture as the reliability guard around agents.

## Health checks

`HealthCheck` (`haris/notify/health.py`) runs registered probes and does two things on
failure: notifies CRITICAL (T3), and **fails closed in enforce mode** —
`assert_serviceable(mode)` raises `HarisUnhealthy` rather than letting the protected app run
behind a broken guard. In monitor it never raises.

The shipped pipeline registers three probes: `agents` (the orchestrator has agents wired
in), `state_store` (a trivial context read succeeds), and `audit_chain` (the hash chain still
verifies). `Heartbeat` can run the check on a timer in a daemon thread so degradation is
noticed while no traffic is flowing; nothing in the demo starts one.

## Try it

    python -m demo_app.hospital.notify_demo        # dedup, routing, sanitization
    export HARIS_ALERT_WEBHOOK=...                 # optional: also post to Slack/Discord
