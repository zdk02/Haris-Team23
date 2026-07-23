"""Per-agent identity (IdentityAgent / authentication, threat-model Problem F).

A message must carry its sender's issued token; a spoofed or unauthenticated sender is
blocked. No Presidio/langgraph needed.
"""
from __future__ import annotations

import pytest

from haris.agents.identity import IdentityAgent
from haris.orchestrator.orchestrator import Orchestrator
from haris.schemas.decision import Action, HarisBlocked
from haris.schemas.message import Message
from haris.schemas.policy import Mode, Policy
from haris.schemas.verdict import Label
from haris.state.graph_store import GraphStateStore

TOKENS = {"agent_a": "tok-a", "agent_b": "tok-b"}


def _msg(sender, token=None):
    md = {}
    if token is not None:
        md["auth_token"] = token
    return Message(session_id="s", sender=sender, receiver="x", content="c", metadata=md)


# ---- unit ---------------------------------------------------------------------

def test_valid_token_verifies():
    assert IdentityAgent(TOKENS).check(_msg("agent_a", "tok-a"), {}).label is Label.PASS


def test_missing_token_blocks():
    assert IdentityAgent(TOKENS).check(_msg("agent_a", None), {}).label is Label.BLOCK


def test_wrong_token_blocks():
    v = IdentityAgent(TOKENS).check(_msg("agent_a", "guessed"), {})
    assert v.label is Label.BLOCK and "spoofed" in v.reason


def test_unregistered_sender_blocked_by_default():
    assert IdentityAgent(TOKENS).check(_msg("ghost", "whatever"), {}).label is Label.BLOCK


def test_unregistered_sender_allowed_when_configured():
    agent = IdentityAgent(TOKENS, default_allow_unregistered=True)
    assert agent.check(_msg("ghost", None), {}).label is Label.PASS


# ---- integration through the orchestrator (enforce) ---------------------------

def _orch():
    return Orchestrator(GraphStateStore(), agents=[IdentityAgent(TOKENS)],
                        policy=Policy(mode=Mode.ENFORCE))


def test_authenticated_message_passes():
    assert _orch().process(_msg("agent_a", "tok-a")).action is Action.ALLOW


def test_spoofed_message_is_blocked():
    with pytest.raises(HarisBlocked):
        _orch().process(_msg("agent_a", token=None))
