"""Wiring tests for the SHIPPED pipeline (`run_secured`).

WHY THIS FILE EXISTS.
An audit on 2026-08-24 mutated `run_secured` four ways — removed the audit log, removed the
health check, replaced the notifier with None, disabled checkpoints — and the full suite
passed **170/170 every time**. Mutating the library internals was caught every time. So the
components were well tested and the twenty lines that connect them to the running system
were tested by nothing at all.

Six real defects were living in that blind spot, every one of them a property claimed in
THREAT_MODEL.md and true only of the test suite:

  * `SubjectBindingAgent` was inert — the adapter copied the state key `subject` while the
    agent reads `data_subject`, so it reported "no data_subject to bind against" on every
    hop and the cross-subject defence never ran.
  * `IdentityAgent` was never constructed by the pipeline at all, while §6 claimed 100%
    SPOOF detection from a harness that appends it.
  * `run_secured` created no `AuditLog`, so nothing the shipped path did was recorded.
  * `audit_chain_probe` was registered nowhere outside the tests.
  * Audit checkpoints were emitted on a logger no entry point configured.
  * A blocked leak reached no channel: the only channel was a webhook that (a) filtered
    WARNING out and (b) is a silent no-op unless HARIS_ALERT_WEBHOOK is set.

These tests assert the CONNECTIONS, not the components. Each one should fail if the
corresponding wire is cut.

SECOND ROUND, 2026-08-24. A re-audit mutated the fixes themselves and found three that this
file claimed to cover and did not — the tests passed 180/180 with the wire removed:

  * reverting the webhook to min_severity=CRITICAL,
  * deleting `health.register("audit_chain", ...)`, under a test *named* for it,
  * deleting `configure_logging()` from the entry point, because `caplog` installs its own
    handler and therefore proves nothing about what the entry point configures.

Each now has a test that goes red when the wire is cut; verified by cutting all three. The
lesson repeats one level up: a test named after a property is not a test of that property.
"""
from __future__ import annotations

import logging

import pytest

from demo_app.hospital.app import EXTERNAL_EXAMPLE, INTERNAL_DOCTOR
from demo_app.hospital.haris_pipeline import (HOSPITAL_TOKENS, build_hospital_agents,
                                              run_secured)
from haris.schemas.decision import HarisBlocked
from haris.schemas.message import Message
from haris.schemas.policy import Mode, Policy

pytest.importorskip("langgraph.graph")

EXPECTED_AGENTS = {"authorization", "subject_binding", "infoflow", "identity"}


def _run(**kw):
    kw.setdefault("include_secrets", False)
    return run_secured("wire", "patient-A", INTERNAL_DOCTOR, leak="identified", **kw)


# --- the audit log is connected -----------------------------------------------

def test_the_shipped_pipeline_writes_an_audit_log():
    """It previously created none, so nothing the real pipeline did was ever recorded."""
    result = _run()
    audit = result["audit"]
    assert len(audit) == 2, "every inter-agent hop must be audited"
    assert audit.verify_chain() is True


def test_every_shipped_agent_actually_produces_a_verdict():
    """Not "is the agent in the list" — did it RUN and record an opinion on a real hop.
    An agent that is constructed but never reached is indistinguishable from one that is
    absent, and that is exactly how the identity gap survived."""
    audit = _run()["audit"]
    for record in audit.records():
        assert {v["agent"] for v in record.verdicts} == EXPECTED_AGENTS, record.as_dict()


def test_the_data_subject_reaches_the_agents():
    """THE BUG. The graph calls the field `subject`; SubjectBindingAgent reads
    `data_subject`. Copying the name through unchanged made the agent inert on every hop
    while still appearing in the line-up and still returning PASS."""
    audit = _run()["audit"]
    assert [r.data_subject for r in audit.records()] == ["patient-A", "patient-A"]
    for record in audit.records():
        reason = next(v["reason"] for v in record.verdicts if v["agent"] == "subject_binding")
        assert "no data_subject" not in reason, reason


def test_identity_is_verified_on_every_shipped_hop():
    """The token is bound by the adapter at wrap() time, not carried in graph state, so a
    compromised node cannot read it and replay it as another sender."""
    audit = _run()["audit"]
    for record in audit.records():
        verdict = next(v for v in record.verdicts if v["agent"] == "identity")
        assert verdict["label"] == "pass", verdict
        assert "identity verified" in verdict["reason"]


# --- the defences the shipped line-up must actually mount ----------------------

def test_a_spoofed_sender_is_blocked_by_the_shipped_lineup():
    """THREAT_MODEL.md Problem F. Previously the shipped stack had no IdentityAgent, so a
    forged sender was merely flagged and delivered."""
    from haris.orchestrator.orchestrator import Orchestrator
    from haris.state.graph_store import GraphStateStore

    orch = Orchestrator(GraphStateStore(), agents=build_hospital_agents(include_secrets=False),
                        policy=Policy(mode=Mode.ENFORCE))
    with pytest.raises(HarisBlocked):
        orch.process(Message(
            session_id="spoof", sender="record_reader", receiver="summarizer",
            content="PATIENT RECORD [patient-A]\nName: Jane Doe",
            metadata={"data_type": "PHI", "data_subject": "patient-A",
                      "auth_token": "not-the-real-token"}))


def test_a_second_data_subject_is_blocked_by_the_shipped_lineup():
    """THREAT_MODEL.md Problem D (TC4). Needs `data_subject` to actually arrive, which is
    what the wiring bug prevented."""
    from haris.orchestrator.orchestrator import Orchestrator
    from haris.state.graph_store import GraphStateStore

    orch = Orchestrator(GraphStateStore(), agents=build_hospital_agents(include_secrets=False),
                        policy=Policy(mode=Mode.ENFORCE))

    def hop(subject):
        return orch.process(Message(
            session_id="tc4", sender="record_reader", receiver="summarizer",
            content=f"PATIENT RECORD [{subject}]\nName: Someone",
            metadata={"data_type": "PHI", "data_subject": subject,
                      "auth_token": HOSPITAL_TOKENS["record_reader"]}))

    hop("patient-A")                       # binds the session
    with pytest.raises(HarisBlocked):
        hop("patient-B")                   # a different subject must not enter


# --- the observability wiring --------------------------------------------------

def test_the_orchestrator_has_an_audit_log_and_a_notifier():
    """Both were absent from the shipped path: without an audit log nothing is recorded, and
    without a notifier the orchestrator's block and crash alerts go nowhere."""
    orchestrator = _run()["haris"].adapter.orchestrator
    assert orchestrator.audit_log is not None, "orchestrator has no audit log"
    assert orchestrator.notifier is not None, "orchestrator has no notifier"


def test_the_chain_probe_is_actually_registered():
    """The previous version of this test was NAMED for the probe and only asserted that a
    notifier existed. Deleting `health.register("audit_chain", ...)` left it green. The probe
    is what turns "the log is tamper-evident" into something the running system checks, so
    assert it is in the registry and that it runs."""
    health = _run()["health"]
    status = health.check()
    assert "audit_chain" in status.checks, sorted(status.checks)
    assert status.checks["audit_chain"] is True
    assert {"agents", "state_store", "audit_chain"} <= set(status.checks)


def test_the_dashboard_notifier_has_an_out_of_band_channel(monkeypatch):
    """R3b — THE DEPLOYED CHANNEL SET. The sibling test above proves the WARNING floor is
    right in `run_secured`. The ECS task does not call `run_secured`: it runs dashboard.py,
    which reaches `dashboard_data.get_dashboard()`. That built a Notifier with only the
    in-memory BufferChannel, so a blocked leak on the live site reached the banner and left
    the process by no route at all -- R3's fix governing a path production never takes.

    Asserts the CHANNEL SET the deployed path constructs, not the constant, so the test
    fails if either the webhook is dropped or its threshold is raised back above WARNING.
    """
    from haris.notify.notifier import _rank
    from haris.schemas.notification import Severity

    import demo_app.dashboard_data as dd

    captured = {}
    real = dd.run_battery

    def spy(*a, notifier=None, **kw):
        captured["notifier"] = notifier
        return real(*a, notifier=notifier, **kw)

    monkeypatch.setattr(dd, "run_battery", spy)
    # Unset, so the webhook is a no-op and this test never touches the network.
    monkeypatch.delenv("HARIS_ALERT_WEBHOOK", raising=False)
    dd.get_dashboard(include_secrets=False)

    channels = captured["notifier"].channels
    accepting = [c for c in channels if _rank(Severity.WARNING) >= _rank(c.min_severity)]
    assert any(c.name == "webhook" for c in accepting), (
        "the deployed dashboard has no out-of-band channel that accepts WARNING — a blocked "
        "leak never leaves the container")
    assert any(c.name == "buffer" for c in accepting), [c.name for c in channels]

def test_audit_checkpoints_are_emitted_for_every_record(caplog):
    """A checkpoint is the reference that makes truncation detectable. This covers
    EMISSION only — `caplog` attaches its own handler, so it says nothing about whether any
    destination is configured. That is the next test's job."""
    with caplog.at_level(logging.INFO, logger="haris.audit.checkpoint"):
        _run()
    emitted = [r.getMessage() for r in caplog.records
               if r.name == "haris.audit.checkpoint"]
    assert len(emitted) == 2, emitted
    assert "count=2" in emitted[-1]


def test_the_entry_point_gives_the_checkpoint_logger_a_destination(monkeypatch):
    """THE DESTINATION. `configure_logging` sets propagate=False on the `haris` namespace, so
    the operational tier needs its own handler — `logging.basicConfig` does not reach it.
    Deleting the call from the entry point left every checkpoint-related test green, because
    they all installed a handler themselves.

    So: tear the operational logger down to nothing, run the real entry point with the demo
    body stubbed out, and assert the entry point put a handler back. Nothing but
    `configure_logging` sets the `_haris_operational` marker, so pytest's own capture cannot
    satisfy this."""
    import demo_app.hospital.haris_pipeline as pipeline
    from haris.logging_config import OPERATIONAL_LOGGER

    ops = logging.getLogger(OPERATIONAL_LOGGER)
    saved = (list(ops.handlers), ops.level, ops.propagate)
    for handler in list(ops.handlers):
        ops.removeHandler(handler)
    ops.setLevel(logging.NOTSET)

    monkeypatch.setattr(pipeline, "_presidio_available", lambda: False)
    monkeypatch.setattr(pipeline, "run_secured",
                        lambda *a, **kw: {"decisions": [], "blocked": False, "final": {}})
    try:
        pipeline.main()
        assert any(getattr(h, "_haris_operational", False) for h in ops.handlers), (
            "the entry point configured no operational handler — checkpoints are dropped")
        assert logging.getLogger("haris.audit.checkpoint").isEnabledFor(logging.INFO)
    finally:
        for handler in list(ops.handlers):
            ops.removeHandler(handler)
        for handler in saved[0]:
            ops.addHandler(handler)
        ops.setLevel(saved[1])
        ops.propagate = saved[2]


def test_a_checkpoint_taken_now_detects_a_later_truncation():
    """End to end: the property THREAT_MODEL.md section 2 claims, exercised on the audit log
    the shipped pipeline actually produced."""
    audit = _run()["audit"]
    checkpoint = audit.checkpoint()
    assert audit.verify_checkpoint(checkpoint) is True
    audit._records.pop()                                  # attacker truncates
    assert audit.verify_chain() is True                   # still internally consistent
    assert audit.verify_checkpoint(checkpoint) is False    # caught by the outside reference


# --- and the enforcement path still works end to end ---------------------------

def test_an_external_leak_is_blocked_through_the_whole_graph():
    result = run_secured("wire-ext", "patient-A", EXTERNAL_EXAMPLE,
                         leak="identified", include_secrets=False)
    assert result["blocked"] is True
    assert result["audit"].records()[-1].action == "block"
    assert result["audit"].records()[-1].delivered_content is None

def test_the_dashboard_entry_point_gives_the_checkpoint_logger_a_destination(monkeypatch):
    """THE DEPLOYED DESTINATION. The ECS task runs `streamlit run demo_app/dashboard.py`,
    not haris_pipeline. The sibling test above covers the CLI entry point; this one covers
    the only entry point production actually takes — which is the one that had no handler,
    so every audit checkpoint, notifier event and health error in the container was dropped.
    """
    import demo_app.dashboard as dash
    from haris.logging_config import OPERATIONAL_LOGGER

    ops = logging.getLogger(OPERATIONAL_LOGGER)
    saved = (list(ops.handlers), ops.level, ops.propagate)
    for handler in list(ops.handlers):
        ops.removeHandler(handler)
    ops.setLevel(logging.NOTSET)
    ops.propagate = True

    # st.cache_resource memoises the FIRST call for the life of the process, so without this
    # the body never re-runs and the result depends on test ORDER, not on the code.
    dash._configure_operational_logging.clear()

    # main() configures logging, THEN returns at the auth gate. Stubbing the gate exercises
    # the real ordering: a container with no operator token must still have an ops log.
    monkeypatch.setattr(dash, "_authenticated", lambda: False)
    try:
        dash.main()
        assert any(getattr(h, "_haris_operational", False) for h in ops.handlers), (
            "dashboard.main() configured no operational handler — the DEPLOYED container "
            "drops every audit checkpoint, notifier event and health error")
        assert logging.getLogger("haris.audit.checkpoint").isEnabledFor(logging.INFO)
    finally:
        for handler in list(ops.handlers):
            ops.removeHandler(handler)
        for handler in saved[0]:
            ops.addHandler(handler)
        ops.setLevel(saved[1])
        ops.propagate = saved[2]
        dash._configure_operational_logging.clear()
