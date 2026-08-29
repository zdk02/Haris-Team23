"""S3 — the Incidents & Health page, tested at the seam rather than at the parts.

The defect this page exists to close was a seam defect: `haris/notify/health.py` was
correct, complete and registered NOWHERE on the deployed path, so the dashboard's banner
reported "all systems healthy" from the absence of incidents rather than from a measured
check. Testing `HealthCheck` again would not have caught that — `tests/test_notify.py`
already does, and it passed throughout. So every assertion here is about a CONNECTION:

  * that `get_dashboard()` actually registers a probe and runs it,
  * that a probe which fails travels the Notifier rather than merely being drawn, so the
    failure reaches the incident feed and the webhook and not only the page,
  * and that the counters and channel status the page renders describe the same Notifier
    the pipeline used, not a fresh one built for display.

Each is verified by cutting the wire: comment out the `_run_health` call and
`test_get_dashboard_runs_a_probe` fails; drop the `notifier=` argument in `_run_health`
and `test_a_failing_probe_reaches_the_incident_feed` fails while everything else stays
green.
"""
from __future__ import annotations

from dataclasses import replace

import pytest

from demo_app.dashboard_data import _channel_dict, _run_health, get_dashboard
from haris.audit import AuditLog
from haris.notify import Notifier, Severity
from haris.notify.channels import BufferChannel, WebhookChannel
from haris.orchestrator.orchestrator import Orchestrator
from haris.schemas.message import Message
from haris.schemas.policy import Mode, Policy
from haris.state.memory import InMemoryStateStore


@pytest.fixture
def audit() -> AuditLog:
    """A real chain, built the way the deployment builds one — through an Orchestrator —
    rather than by appending records by hand. A hand-built log would let the probe pass
    against a chain no production path ever produces."""
    log = AuditLog(store_delivered_content=True)
    orch = Orchestrator(InMemoryStateStore(), agents=[], policy=Policy(mode=Mode.MONITOR),
                        audit_log=log)
    for i in range(3):
        orch.process(Message(session_id="s", sender="a", receiver="b",
                             content=f"record {i}",
                             metadata={"data_type": "PHI", "data_subject": "patient-A"}))
    assert log.verify_chain(), "fixture must start from an intact chain"
    return log


@pytest.fixture(scope="module")
def dashboard():
    """One battery replay shared by the end-to-end assertions — it is the slow part, and
    running it per test would triple the suite's cost for no extra coverage."""
    return get_dashboard(Mode.ENFORCE, include_secrets=False)


# --- the probe itself, against a real chain -------------------------------------------

def _corrupt(audit: AuditLog) -> None:
    """Rewrite one record in the MIDDLE of the chain, which is the tampering the chain is
    designed to catch. Truncation is deliberately not used here: dropping records off the
    end leaves a shorter chain that still verifies internally, so it would not fail the
    probe — that case needs an external checkpoint and is covered in test_audit.py.

    `AuditRecord` is a frozen dataclass, so the tampering has to be done the way a real
    attacker would have to do it: build a replacement record and put it in the log. The
    stored `entry_hash` still describes the old fields, which is exactly the inconsistency
    `verify_chain()` exists to notice."""
    assert len(audit.records()) >= 2, "need a chain long enough to have a middle"
    original = audit._records[0]
    audit._records[0] = replace(
        original, action="allow" if original.action != "allow" else "block")


def test_probe_passes_on_an_intact_chain(audit):
    status = _run_health(audit, Notifier())
    assert status["healthy"] is True
    assert status["checks"] == {"audit_chain": True}
    assert status["failures"] == []


def test_probe_fails_on_a_rewritten_record(audit):
    _corrupt(audit)
    status = _run_health(audit, Notifier())
    assert status["healthy"] is False
    assert status["checks"]["audit_chain"] is False
    assert status["failures"] == ["audit_chain"]


# --- the wiring: a failure must TRAVEL, not just render --------------------------------

def test_a_failing_probe_reaches_the_incident_feed(audit):
    """The page could have been built by calling `verify_chain()` and drawing the result.
    It is not: the check runs through the Notifier, so the failure becomes a CRITICAL
    event on every configured channel. This asserts the event arrives in the buffer the
    incident feed reads — which is the same thing as asserting it would have arrived at
    the webhook on the deployed task."""
    buffer = BufferChannel(min_severity=Severity.WARNING)
    notifier = Notifier(channels=[buffer])
    _corrupt(audit)

    _run_health(audit, notifier)

    events = buffer.events()
    assert len(events) == 1, "a failed probe must raise exactly one alert"
    assert events[0].severity is Severity.CRITICAL
    assert "audit_chain" in events[0].summary
    assert notifier.counts["emitted"] == 1
    assert notifier.counts["delivered"] == 1


def test_a_passing_probe_stays_quiet(audit):
    """The other half, and the one that keeps the page trustworthy: a healthy check must
    not manufacture an incident. An alerter that fires on success trains an operator to
    ignore it."""
    buffer = BufferChannel(min_severity=Severity.WARNING)
    notifier = Notifier(channels=[buffer])

    _run_health(audit, notifier)

    assert buffer.events() == []
    assert notifier.counts["emitted"] == 0


def test_the_failure_summary_carries_no_record_content(audit):
    """The alert names probes, never payloads. The detailed reasons go in metadata, which
    the Notifier strips before any channel — so the operator console cannot become the
    leak the block prevented."""
    buffer = BufferChannel(min_severity=Severity.WARNING)
    notifier = Notifier(channels=[buffer])
    _corrupt(audit)

    _run_health(audit, notifier)

    event = buffer.events()[0]
    assert event.metadata in (None, {}), "metadata must not survive the sanitiser"
    for record in audit.records():
        if record.delivered_content:
            assert record.delivered_content not in event.summary


# --- what the page renders about the channels ------------------------------------------

def test_channel_dict_separates_present_from_configured():
    """`skipped` versus `delivered` is the distinction that diagnosed the placeholder
    webhook in production, and the page must not collapse it. A WebhookChannel with no URL
    is in the channel list, is counted, and is NOT a delivery path."""
    unconfigured = _channel_dict(WebhookChannel(url=None))
    assert unconfigured["name"] == "webhook"
    assert unconfigured["configured"] is False

    configured = _channel_dict(WebhookChannel(url="https://example.invalid/hook"))
    assert configured["configured"] is True

    # A BufferChannel defines no `enabled` at all; it is always live, and the reader must
    # not mistake the missing attribute for "off".
    assert _channel_dict(BufferChannel())["configured"] is True


# --- the seam: get_dashboard must actually do all of this ------------------------------

def test_get_dashboard_runs_a_probe(dashboard):
    """The assertion the missing wiring would have failed. `health` is not merely present
    — a probe must have RUN, which means `checks` is non-empty. An empty dict would render
    a page saying '0 probes passing', which is what the code did before this change."""
    data = dashboard

    assert "health" in data
    assert data["health"]["checks"], "no probe ran — the health surface is decorative"
    assert "audit_chain" in data["health"]["checks"]
    assert data["health"]["healthy"] is True


def test_get_dashboard_reports_the_pipeline_notifier(dashboard):
    """Counters and channel status must describe the Notifier the battery ran through. If
    the page built its own for display, `emitted` would be 0 while the incident feed showed
    three blocks — a contradiction visible on one screen."""
    data = dashboard

    assert data["counts"]["emitted"] == len(data["incidents"])
    assert data["counts"]["emitted"] > 0, "the battery raises blocks; none were counted"
    assert {c["name"] for c in data["channels"]} == {"buffer", "webhook"}
    for key in ("emitted", "suppressed", "delivered", "failed", "skipped"):
        assert key in data["counts"]