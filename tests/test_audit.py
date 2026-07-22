"""Security audit log: Haris records every decision, app-agnostically, hashing content."""
from __future__ import annotations

import pytest

from haris.agents.base import SecurityAgent
from haris.audit import AuditLog, _sha256
from haris.orchestrator.orchestrator import Orchestrator
from haris.schemas.decision import HarisBlocked
from haris.schemas.message import Message
from haris.schemas.policy import Mode, Policy
from haris.schemas.verdict import Label, Verdict
from haris.state.memory import InMemoryStateStore


class _Blocker(SecurityAgent):
    name = "blocker"

    def check(self, m, c):
        return Verdict(agent_name="blocker", label=Label.BLOCK, score=1.0, reason="nope")


def _msg(content="hi", **md):
    return Message(session_id="s", sender="a", receiver="b", content=content, metadata=md)


def _orch(log, agents=None, mode=Mode.MONITOR):
    return Orchestrator(InMemoryStateStore(), agents=agents or [],
                        policy=Policy(mode=mode), audit_log=log)


def test_orchestrator_writes_a_record_per_decision():
    log = AuditLog()
    _orch(log).process(_msg("hello", data_type="PHI", data_subject="patient-A"))
    assert len(log) == 1
    rec = log.records()[0]
    assert (rec.sender, rec.receiver) == ("a", "b")
    assert rec.data_type == "PHI" and rec.data_subject == "patient-A"
    assert rec.action == "allow" and rec.latency_ms >= 0.0


def test_content_is_hashed_not_stored_raw():
    log = AuditLog(store_delivered_content=False)     # hardened mode
    secret = "AKIA-super-secret-key"
    _orch(log).process(_msg(secret))
    rec = log.records()[0]
    assert rec.content_sha256 == _sha256(secret)
    assert rec.delivered_content is None
    assert secret not in str(rec.as_dict())           # the raw secret is nowhere in the log


def test_blocked_decision_is_recorded_before_raising():
    log = AuditLog()
    with pytest.raises(HarisBlocked):
        _orch(log, agents=[_Blocker()], mode=Mode.ENFORCE).process(_msg())
    assert len(log) == 1 and log.records()[0].action == "block"


def test_records_returns_an_append_only_snapshot():
    log = AuditLog()
    orch = _orch(log)
    orch.process(_msg())
    snap = log.records()
    orch.process(_msg())
    assert len(snap) == 1 and len(log.records()) == 2   # the returned list is a copy


def test_orchestrator_without_audit_log_is_unaffected():
    d = Orchestrator(InMemoryStateStore(), agents=[]).process(_msg())
    assert d.action.value == "allow"
