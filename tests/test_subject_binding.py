"""Data-subject authorization (SubjectBindingAgent / threat-model TC4).

A session is bound to its FIRST data_subject; another subject's data is then blocked from
entering that session. No Presidio/langgraph needed — pure orchestrator + graph store.
"""
from __future__ import annotations

import pytest

from haris.agents.subject_binding import SubjectBindingAgent
from haris.orchestrator.orchestrator import Orchestrator
from haris.schemas.decision import Action, HarisBlocked
from haris.schemas.message import Message
from haris.schemas.policy import Mode, Policy
from haris.schemas.verdict import Label
from haris.state.graph_store import GraphStateStore


def _msg(session, subject, sender="record_reader", receiver="summarizer"):
    return Message(session_id=session, sender=sender, receiver=receiver,
                   content=f"record for {subject}",
                   metadata={"data_type": "PHI", "data_subject": subject})


def _ctx(*subjects):
    return {"history": [_msg("s", s) for s in subjects]}


# ---- unit: the agent against a constructed context ---------------------------

def test_first_subject_binds_and_passes():
    v = SubjectBindingAgent().check(_msg("s", "patient-A"), _ctx("patient-A"))
    assert v.label is Label.PASS


def test_matching_subject_passes():
    v = SubjectBindingAgent().check(_msg("s", "patient-A"), _ctx("patient-A", "patient-A"))
    assert v.label is Label.PASS


def test_mismatched_subject_blocks():
    v = SubjectBindingAgent().check(_msg("s", "patient-B"), _ctx("patient-A", "patient-B"))
    assert v.label is Label.BLOCK
    assert "patient-A" in v.reason and "patient-B" in v.reason


def test_message_without_subject_passes():
    m = Message(session_id="s", sender="a", receiver="b", content="x", metadata={})
    assert SubjectBindingAgent().check(m, {"history": [m]}).label is Label.PASS


# ---- integration through the real orchestrator (TC4) -------------------------

def _orch(mode=Mode.ENFORCE):
    return Orchestrator(GraphStateStore(), agents=[SubjectBindingAgent()],
                        policy=Policy(mode=mode))


def test_tc4_cross_patient_blocked_in_enforce():
    orch = _orch(Mode.ENFORCE)
    d1 = orch.process(_msg("case-A", "patient-A"))          # binds session to A
    assert d1.action is Action.ALLOW
    with pytest.raises(HarisBlocked) as exc:                # B into A's session
        orch.process(_msg("case-A", "patient-B"))
    assert any(v.agent_name == "subject_binding" and v.label is Label.BLOCK
               for v in exc.value.decision.verdicts)


def test_tc4_same_patient_flows_across_hops():
    orch = _orch(Mode.ENFORCE)
    orch.process(_msg("case-A", "patient-A"))
    d = orch.process(_msg("case-A", "patient-A", sender="summarizer", receiver="emailer"))
    assert d.action is Action.ALLOW


def test_tc4_monitor_never_blocks():
    orch = _orch(Mode.MONITOR)
    orch.process(_msg("case-A", "patient-A"))
    d = orch.process(_msg("case-A", "patient-B"))           # would block in enforce
    assert d.enforced is False and d.action is not Action.BLOCK


def test_separate_sessions_are_independent():
    orch = _orch(Mode.ENFORCE)
    orch.process(_msg("case-A", "patient-A"))
    d = orch.process(_msg("case-B", "patient-B"))           # B is fine in B's own session
    assert d.action is Action.ALLOW
