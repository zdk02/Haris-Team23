"""Phase 4 self-test — verify the whole notification system (tasks 2-7) locally.

Run from the repo root:

    python phase4_selftest.py

It exercises every piece end to end and prints PASS/FAIL per task. No external
services needed: the webhook is tested against a local mock HTTP server. If you have
also set HARIS_ALERT_WEBHOOK to a real Slack/Discord URL, it additionally sends ONE
real alert there so you can see it land in your channel.

This is a convenience verifier; the pytest suite (`python -m pytest tests/ -q`) is the
authoritative regression check.
"""
from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from haris.notify import Notifier, Channel, NotificationEvent, Category, Severity
from haris.notify.channels import WebhookChannel, BufferChannel
from haris.notify.health import HealthCheck, Heartbeat, HarisUnhealthy, audit_chain_probe
from haris.orchestrator.orchestrator import Orchestrator
from haris.audit import AuditLog
from haris.schemas.message import Message
from haris.schemas.policy import Policy, Mode
from haris.schemas.verdict import Verdict, Label
from haris.schemas.decision import HarisBlocked
from haris.state.memory import InMemoryStateStore
from haris.agents.base import SecurityAgent
from haris.logging_config import configure_logging

import logging
configure_logging(level=logging.CRITICAL)   # quiet the ops log so the report is readable

PASSED = 0
FAILED = 0


def check(name: str, condition: bool) -> None:
    global PASSED, FAILED
    mark = "PASS" if condition else "FAIL"
    if condition:
        PASSED += 1
    else:
        FAILED += 1
    print(f"   [{mark}] {name}")


# --- fixtures ------------------------------------------------------------------------------
class Capture(Channel):
    name = "capture"
    min_severity = Severity.WARNING

    def __init__(self):
        self.got = []

    def send(self, event):
        self.got.append(event)


class Blocker(SecurityAgent):
    name = "authorization"
    def check(self, m, ctx):
        return Verdict(agent_name="authorization", label=Label.BLOCK, score=1.0,
                       reason="egress of PHI to external — record MRN-0001")


class Crasher(SecurityAgent):
    name = "secrets_pii"
    def check(self, m, ctx):
        raise ValueError("presidio model not loaded")


MSG = Message(session_id="selftest", sender="summarizer", receiver="emailer",
              content="patient MRN-0001 secret sk-LEAK",
              metadata={"data_type": "summary", "recipient": "ext@evil.com"})


# --- Task 2: NotificationEvent schema ------------------------------------------------------
def task2_schema():
    print("\nTask 2 — NotificationEvent schema")
    e = NotificationEvent.operational("orchestrator", "detector crashed", error="x")
    check("factory sets category/severity", e.category is Category.OPERATIONAL and e.severity is Severity.CRITICAL)
    check("timestamp auto-filled as string", isinstance(e.timestamp, str) and "T" in e.timestamp)
    check("serializes to JSON (webhook-ready)", isinstance(json.dumps(e.model_dump()), str))
    check("one_line() renders", "orchestrator" in e.one_line())
    s = NotificationEvent.security("orchestrator", "blocked")
    check("security factory defaults to WARNING", s.severity is Severity.WARNING)


# --- Task 3: Notifier dispatcher -----------------------------------------------------------
def task3_notifier():
    print("\nTask 3 — Notifier dispatcher")
    banner = Capture(); banner.min_severity = Severity.WARNING
    webhook = Capture(); webhook.min_severity = Severity.CRITICAL
    n = Notifier(channels=[banner, webhook], dedup_window_s=30)

    n.notify(NotificationEvent.operational("x", "info-level", severity=Severity.INFO))
    n.notify(NotificationEvent.security("x", "a warning"))
    n.notify(NotificationEvent.operational("x", "critical thing", secret="sk-DONOTLEAK"))
    check("INFO reaches neither external channel", [e.severity.value for e in banner.got] == ["warning", "critical"])
    check("webhook only gets CRITICAL", [e.severity.value for e in webhook.got] == ["critical"])
    check("secret-safe: metadata stripped for channels", webhook.got[0].metadata == {})

    before = len(webhook.got)
    for _ in range(4):
        n.notify(NotificationEvent.operational("x", "critical thing"))
    check("de-dup collapses an alert storm", len(webhook.got) == before)

    class Boom(Channel):
        name = "boom"; min_severity = Severity.INFO
        def send(self, e): raise RuntimeError("down")
    n2 = Notifier(channels=[Boom(), banner])
    n2.notify(NotificationEvent.operational("x", "still delivered"))
    check("a failing channel doesn't break the others", banner.got[-1].summary == "still delivered")


# --- Task 4: Health check ------------------------------------------------------------------
def task4_health():
    print("\nTask 4 — Health check + heartbeat")
    cap = Capture(); n = Notifier(channels=[cap])
    hc = HealthCheck(notifier=n)
    hc.register("ok", lambda: True)
    check("healthy run raises no alert", hc.is_healthy() and len(cap.got) == 0)

    hc.register("bad", lambda: False)
    hc.register("boom", lambda: (_ for _ in ()).throw(RuntimeError("store down")))
    st = hc.check()
    check("unhealthy detected", not st.healthy and set(st.failures) == {"bad", "boom"})
    check("failure fires a CRITICAL alert", cap.got and cap.got[-1].severity is Severity.CRITICAL)

    raised = False
    try:
        hc.assert_serviceable(Mode.ENFORCE)
    except HarisUnhealthy:
        raised = True
    check("ENFORCE + unhealthy -> fail closed (raises)", raised)
    ok = hc.assert_serviceable(Mode.MONITOR)  # must not raise
    check("MONITOR + unhealthy -> fail open (no raise)", ok.healthy is False)

    log = AuditLog()
    hc2 = HealthCheck(); hc2.register("chain", audit_chain_probe(log))
    check("audit_chain_probe works on a real AuditLog", hc2.is_healthy())


# --- Task 5: Orchestrator triggers ---------------------------------------------------------
def task5_orchestrator():
    print("\nTask 5 — Orchestrator runtime triggers")
    # backward-compat: no notifier still works exactly as before
    o = Orchestrator(InMemoryStateStore(), agents=[Blocker()], policy=Policy(mode=Mode.ENFORCE))
    raised = False
    try:
        o.process(MSG)
    except HarisBlocked:
        raised = True
    check("no-notifier: block still raises HarisBlocked (unchanged)", raised)

    # T4 block trigger
    cap = Capture(); n = Notifier(channels=[cap])
    o = Orchestrator(InMemoryStateStore(), agents=[Blocker()], policy=Policy(mode=Mode.ENFORCE), notifier=n)
    try:
        o.process(MSG)
    except HarisBlocked:
        pass
    sec = [e for e in cap.got if e.category is Category.SECURITY]
    check("T4: a blocked leak fires a SECURITY alert", len(sec) == 1)
    check("T4: summary carries NO raw secret", sec and "MRN-0001" not in sec[0].summary and "sk-LEAK" not in sec[0].summary)
    check("T4: reference is a content hash", sec and sec[0].reference and len(sec[0].reference) == 64)

    # T1/T2 crash trigger, still fails closed
    cap2 = Capture(); n2 = Notifier(channels=[cap2])
    o = Orchestrator(InMemoryStateStore(), agents=[Crasher()], policy=Policy(mode=Mode.ENFORCE), notifier=n2)
    try:
        o.process(MSG)
    except HarisBlocked:
        pass
    ops = [e for e in cap2.got if e.category is Category.OPERATIONAL]
    check("T1/T2: a detector crash fires an OPERATIONAL CRITICAL alert",
          ops and ops[0].severity is Severity.CRITICAL)


# --- Task 6: Dashboard banner feed ---------------------------------------------------------
def task6_dashboard():
    print("\nTask 6 — Dashboard alert banner feed")
    from demo_app.dashboard_data import get_dashboard
    d = get_dashboard(Mode.ENFORCE, include_secrets=False)
    inc = d.get("incidents", [])
    check("get_dashboard returns an incidents feed", isinstance(inc, list) and len(inc) >= 1)
    check("incidents are WARNING+ only", all(i["severity"] in ("warning", "critical") for i in inc))
    blob = " ".join(i["summary"] for i in inc)
    check("no raw content in the banner feed", "MRN" not in blob and "sk-" not in blob)


# --- Task 7: Webhook channel (mock + optional real) ----------------------------------------
def task7_webhook():
    print("\nTask 7 — Webhook channel")
    # auto-detect payload shape
    slack = WebhookChannel(url="https://hooks.slack.com/services/x")
    discord = WebhookChannel(url="https://discord.com/api/webhooks/x")
    ev = NotificationEvent.operational("x", "hello")
    check("Slack payload uses 'attachments'", "attachments" in slack._format(ev))
    check("Discord payload uses 'embeds'", "embeds" in discord._format(ev))
    check("no URL -> channel is a no-op (won't break local runs)", WebhookChannel(url="").send(ev) is None)

    # POST against a local mock server
    posts = []
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            ln = int(self.headers.get("Content-Length", 0))
            posts.append(json.loads(self.rfile.read(ln)))
            self.send_response(204); self.end_headers()
        def log_message(self, *a): pass
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    wh = WebhookChannel(url=f"http://127.0.0.1:{port}/discord.com/webhook")
    wh.send(NotificationEvent.security("orchestrator", "blocked a PHI flow", reference="a"*64))
    srv.shutdown()
    check("webhook actually POSTs to the endpoint", len(posts) == 1)
    check("posted body carries no secret", "MRN" not in json.dumps(posts))

    # optional: real Slack/Discord if the env var is set
    real = os.environ.get("HARIS_ALERT_WEBHOOK")
    if real:
        WebhookChannel().send(NotificationEvent.operational(
            "selftest", "✅ Haris webhook self-test — if you see this, the webhook works"))
        print("   [sent] a real alert to HARIS_ALERT_WEBHOOK — check your channel")
    else:
        print("   [skip] set HARIS_ALERT_WEBHOOK to also send one real alert")


def main():
    print("=" * 66)
    print("Haris Phase 4 — notification system self-test")
    print("=" * 66)
    task2_schema()
    task3_notifier()
    task4_health()
    task5_orchestrator()
    task6_dashboard()
    task7_webhook()
    print("\n" + "=" * 66)
    print(f"RESULT: {PASSED} passed, {FAILED} failed")
    print("=" * 66)
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    main()