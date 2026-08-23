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
  * A blocked leak reached no channel (still open — see the notifier test below).

These tests assert the CONNECTIONS, not the components. Each one should fail if the
corresponding wire is cut.
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

def test_the_chain_probe_is_registered_and_the_notifier_is_connected():
    """Both were absent from the shipped path: the probe existed only in tests, and without
    a notifier the orchestrator's block and crash alerts go nowhere."""
    orchestrator = _run()["haris"].adapter.orchestrator
    assert orchestrator.audit_log is not None, "orchestrator has no audit log"
    assert orchestrator.notifier is not None, "orchestrator has no notifier"


def test_audit_checkpoints_reach_a_configured_destination(caplog):
    """A checkpoint is the reference that makes truncation detectable. Emitting one to a
    logger nothing configures is the same as not emitting it -- which is what the first
    attempt at this did, while THREAT_MODEL.md claimed a destination."""
    with caplog.at_level(logging.INFO, logger="haris.audit.checkpoint"):
        _run()
    emitted = [r.getMessage() for r in caplog.records
               if r.name == "haris.audit.checkpoint"]
    assert len(emitted) == 2, emitted
    assert "count=2" in emitted[-1]


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
