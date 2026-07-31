"""Notification system (Phase 4): the alerting path, tested as a measured behavior.

Covers the whole feature the way `test_reliability.py` covers the reliability guard:
  * the NotificationEvent contract (sanitized, serializable),
  * the Notifier dispatcher (severity routing, de-dup, the secret-safe boundary, and that a
    broken channel can't break the others),
  * the health check (alert + fail-closed / fail-open),
  * the orchestrator triggers (a blocked leak and a detector crash raise alerts, and the
    notifier is optional so existing behavior is unchanged),
  * the channels (BufferChannel ordering; WebhookChannel payload shapes, the no-op when no
    URL is set, and the User-Agent header that stops Discord's 403).

Pure stubs + a monkeypatched urlopen — no Presidio, no langgraph, no network.
"""
from __future__ import annotations

import json

import pytest

from haris.agents.base import SecurityAgent
from haris.notify import Notifier, Channel, NotificationEvent, Category, Severity
from haris.notify.channels import BufferChannel, WebhookChannel
from haris.notify.health import (HealthCheck, HarisUnhealthy, audit_chain_probe)
from haris.orchestrator.orchestrator import Orchestrator
from haris.audit import AuditLog
from haris.schemas.message import Message
from haris.schemas.policy import Mode, Policy
from haris.schemas.decision import Action, HarisBlocked
from haris.schemas.verdict import Label, Verdict
from haris.state.memory import InMemoryStateStore


# --- fixtures ------------------------------------------------------------------------------
class CaptureChannel(Channel):
    """Records everything it is sent, for assertions. Defaults to WARNING+ like the banner."""
    def __init__(self, min_severity=Severity.WARNING):
        self.min_severity = min_severity
        self.got: list[NotificationEvent] = []

    def send(self, event):
        self.got.append(event)


class Blocker(SecurityAgent):
    name = "authorization"
    def check(self, message, context):
        return Verdict(agent_name="authorization", label=Label.BLOCK, score=1.0,
                       reason="egress of PHI to external — record MRN-0001 sk-LEAK")


class Crasher(SecurityAgent):
    name = "secrets_pii"
    def check(self, message, context):
        raise ValueError("presidio model not loaded")


def _leaky_msg():
    return Message(session_id="s1", sender="summarizer", receiver="emailer",
                   content="patient MRN-0001 secret sk-LEAK",
                   metadata={"data_type": "summary", "recipient": "ext@evil.com"})


# --- the event contract --------------------------------------------------------------------
def test_event_factories_set_category_and_default_severity():
    op = NotificationEvent.operational("orchestrator", "detector crashed")
    sec = NotificationEvent.security("orchestrator", "leak blocked")
    assert op.category is Category.OPERATIONAL and op.severity is Severity.CRITICAL
    assert sec.category is Category.SECURITY and sec.severity is Severity.WARNING


def test_event_is_json_serializable_with_string_timestamp():
    e = NotificationEvent.operational("x", "hi", foo="bar")
    assert isinstance(e.timestamp, str) and "T" in e.timestamp
    assert isinstance(json.dumps(e.model_dump()), str)  # webhook-ready, no datetime issues


# --- the Notifier dispatcher ---------------------------------------------------------------
def test_severity_routing_respects_each_channels_minimum():
    banner = CaptureChannel(min_severity=Severity.WARNING)
    webhook = CaptureChannel(min_severity=Severity.CRITICAL)
    n = Notifier(channels=[banner, webhook])
    n.notify(NotificationEvent.operational("x", "info", severity=Severity.INFO))
    n.notify(NotificationEvent.security("x", "warn"))
    n.notify(NotificationEvent.operational("x", "crit"))          # CRITICAL by default
    assert [e.severity for e in banner.got] == [Severity.WARNING, Severity.CRITICAL]
    assert [e.severity for e in webhook.got] == [Severity.CRITICAL]


def test_secret_safe_boundary_strips_metadata_before_channels():
    cap = CaptureChannel(min_severity=Severity.INFO)
    n = Notifier(channels=[cap])
    n.notify(NotificationEvent.operational("x", "boom", secret="sk-DONOTLEAK"))
    assert cap.got[0].metadata == {}                              # metadata never leaves the process


def test_dedup_collapses_a_storm_then_reemits_with_a_count():
    cap = CaptureChannel(min_severity=Severity.INFO)
    n = Notifier(channels=[cap], dedup_window_s=999)
    for _ in range(5):
        n.notify(NotificationEvent.operational("x", "same thing"))
    assert len(cap.got) == 1                                      # storm collapsed to one
    assert n.counts["suppressed"] == 4
    n.dedup_window_s = 0.0                                        # window elapsed
    n.notify(NotificationEvent.operational("x", "same thing"))
    assert "suppressed" in cap.got[-1].summary                   # the collapse is made visible


def test_a_broken_channel_does_not_break_the_others():
    class Boom(Channel):
        name = "boom"; min_severity = Severity.INFO
        def send(self, event): raise RuntimeError("down")
    good = CaptureChannel(min_severity=Severity.INFO)
    n = Notifier(channels=[Boom(), good])
    n.notify(NotificationEvent.operational("x", "still delivered"))  # must not raise
    assert good.got[-1].summary == "still delivered"


# --- the health check ----------------------------------------------------------------------
def test_health_alerts_and_fails_closed_in_enforce():
    cap = CaptureChannel(min_severity=Severity.INFO)
    hc = HealthCheck(notifier=Notifier(channels=[cap]))
    hc.register("ok", lambda: True)
    assert hc.is_healthy() and cap.got == []                      # healthy: no alert

    hc.register("down", lambda: False)
    with pytest.raises(HarisUnhealthy):
        hc.assert_serviceable(Mode.ENFORCE)                      # enforce: fail closed
    assert cap.got and cap.got[-1].severity is Severity.CRITICAL  # and it alerted


def test_health_fails_open_in_monitor():
    hc = HealthCheck(); hc.register("down", lambda: False)
    status = hc.assert_serviceable(Mode.MONITOR)                  # must NOT raise
    assert status.healthy is False


def test_audit_chain_probe_reflects_the_log():
    log = AuditLog()
    hc = HealthCheck(); hc.register("chain", audit_chain_probe(log))
    assert hc.is_healthy() is True


# --- the orchestrator triggers -------------------------------------------------------------
def test_blocked_leak_emits_a_security_alert_without_the_secret():
    cap = CaptureChannel(min_severity=Severity.INFO)
    orch = Orchestrator(InMemoryStateStore(), agents=[Blocker()],
                        policy=Policy(mode=Mode.ENFORCE), notifier=Notifier(channels=[cap]))
    with pytest.raises(HarisBlocked):
        orch.process(_leaky_msg())
    sec = [e for e in cap.got if e.category is Category.SECURITY]
    assert len(sec) == 1
    assert "MRN-0001" not in sec[0].summary and "sk-LEAK" not in sec[0].summary
    assert sec[0].reference and len(sec[0].reference) == 64       # a content hash, not the body


def test_detector_crash_emits_operational_critical_and_still_fails_closed():
    cap = CaptureChannel(min_severity=Severity.INFO)
    orch = Orchestrator(InMemoryStateStore(), agents=[Crasher()],
                        policy=Policy(mode=Mode.ENFORCE), notifier=Notifier(channels=[cap]))
    with pytest.raises(HarisBlocked):                             # fail closed, as before
        orch.process(_leaky_msg())
    ops = [e for e in cap.got if e.category is Category.OPERATIONAL]
    assert ops and ops[0].severity is Severity.CRITICAL


def test_notifier_is_optional_behavior_unchanged():
    orch = Orchestrator(InMemoryStateStore(), agents=[Blocker()], policy=Policy(mode=Mode.ENFORCE))
    with pytest.raises(HarisBlocked):                             # identical to pre-Phase-4
        orch.process(_leaky_msg())


# --- the channels --------------------------------------------------------------------------
def test_buffer_channel_keeps_recent_first_and_is_bounded():
    buf = BufferChannel(capacity=2, min_severity=Severity.INFO)
    for i in range(3):
        buf.send(NotificationEvent.operational("x", f"e{i}"))
    summaries = [e.summary for e in buf.events()]
    assert summaries == ["e2", "e1"]                              # most-recent-first, capped at 2


def test_webhook_payload_shapes_per_platform():
    ev = NotificationEvent.operational("x", "hi")
    assert "attachments" in WebhookChannel(url="https://hooks.slack.com/x")._format(ev)
    assert "embeds" in WebhookChannel(url="https://discord.com/api/webhooks/x")._format(ev)
    assert "text" in WebhookChannel(url="https://example.com/hook")._format(ev)


def test_webhook_is_a_noop_when_no_url(monkeypatch):
    def boom(*a, **k):  # pragma: no cover - must never be called
        raise AssertionError("should not POST when unconfigured")
    monkeypatch.setattr("urllib.request.urlopen", boom)
    assert WebhookChannel(url="").send(NotificationEvent.operational("x", "hi")) is None


def test_webhook_sends_explicit_user_agent(monkeypatch):
    """Discord (Cloudflare) 403s the default urllib User-Agent; we must send our own."""
    captured = {}

    class FakeResp:
        status = 204
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def getcode(self): return 204

    def fake_urlopen(req, timeout=None):
        captured["req"] = req
        return FakeResp()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    WebhookChannel(url="https://discord.com/api/webhooks/x").send(
        NotificationEvent.operational("x", "hi"))
    ua = captured["req"].get_header("User-agent")
    assert ua and "urllib" not in ua
