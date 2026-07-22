"""Reliability guard (a non-functional requirement): a crashing security agent must
neither take Haris down for the whole hop nor let a message pass silently.

Stated failure policy, verified here:
  * MONITOR -> fail OPEN  (deliver, but surface the error as a verdict for observability)
  * ENFORCE -> fail CLOSED (block the message)
One agent crashing never suppresses another agent's verdict.

No Presidio/langgraph needed — pure stubs over the InMemory store.
"""
from __future__ import annotations

import pytest

from haris.agents.base import SecurityAgent
from haris.orchestrator.orchestrator import Orchestrator
from haris.schemas.decision import Action, HarisBlocked
from haris.schemas.message import Message
from haris.schemas.policy import Mode, Policy
from haris.schemas.verdict import Label, Verdict
from haris.state.memory import InMemoryStateStore


class BoomAgent(SecurityAgent):
    name = "boom"

    def check(self, message, context):
        raise RuntimeError("detector exploded")


class OkAgent(SecurityAgent):
    name = "ok"

    def check(self, message, context):
        return Verdict(agent_name="ok", label=Label.PASS, score=0.0, reason="fine")


def _msg():
    return Message(session_id="s", sender="a", receiver="b", content="hi", metadata={})


def _orch(mode, agents):
    return Orchestrator(InMemoryStateStore(), agents=agents, policy=Policy(mode=mode))


def _boom_verdict(decision):
    return next((v for v in decision.verdicts if v.agent_name == "boom"), None)


def test_monitor_fails_open_but_records_the_error():
    """A crash in monitor mode must NOT raise and must NOT block; the app keeps working,
    and the failure is surfaced as a verdict so it shows on the dashboard."""
    orch = _orch(Mode.MONITOR, [BoomAgent(), OkAgent()])
    d = orch.process(_msg())                      # must not raise
    assert d.enforced is False
    assert d.action is not Action.BLOCK           # message delivered (fail open)
    bv = _boom_verdict(d)
    assert bv is not None and bv.label is Label.FLAG
    assert "error" in bv.reason.lower() and "monitor" in bv.reason.lower()


def test_enforce_fails_closed_and_blocks():
    """A crash in enforce mode must fail CLOSED: the message is blocked, not waved through."""
    orch = _orch(Mode.ENFORCE, [BoomAgent(), OkAgent()])
    with pytest.raises(HarisBlocked) as exc:
        orch.process(_msg())
    d = exc.value.decision
    assert d.action is Action.BLOCK
    bv = _boom_verdict(d)
    assert bv is not None and bv.label is Label.BLOCK
    assert "error" in bv.reason.lower() and "enforce" in bv.reason.lower()


def test_one_agent_crashing_does_not_suppress_the_others():
    """The healthy agent still contributes its verdict even though another threw."""
    orch = _orch(Mode.MONITOR, [BoomAgent(), OkAgent()])
    d = orch.process(_msg())
    assert {v.agent_name for v in d.verdicts} == {"boom", "ok"}


def test_all_agents_healthy_is_unaffected_by_the_guard():
    """Sanity: with no crash, behavior is exactly as before (the guard is transparent)."""
    orch = _orch(Mode.ENFORCE, [OkAgent()])
    d = orch.process(_msg())
    assert d.action is Action.ALLOW
    assert [v.agent_name for v in d.verdicts] == ["ok"]
