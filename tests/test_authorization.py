"""Unit tests for AuthorizationAgent (Module 8).

Covers the rule table (allow/deny/redact/wildcard/default-deny), the egress check
(TC5 external recipient blocked, internal passes, PHI hop without a recipient
passes), the verdict shape, and integration with the REAL policy engine
(resolve()) to prove a BLOCK is enforced in ENFORCE mode and clamped to FLAG in
MONITOR mode.
"""

from haris.agents.authorization import AuthorizationAgent
from haris.schemas.message import Message
from haris.schemas.policy import Policy, PolicyRule, Mode
from haris.schemas.verdict import Label
from haris.schemas.decision import Action
from haris.policy.engine import resolve

CTX: dict = {"history": []}
INTERNAL = "doctor@hospital.internal"
EXTERNAL = "outside@example.com"


def _msg(sender, receiver, data_type=None, recipient=None, data_subject=None, content="..."):
    md: dict = {}
    if data_type is not None:
        md["data_type"] = data_type
    if recipient is not None:
        md["recipient"] = recipient
    if data_subject is not None:
        md["data_subject"] = data_subject
    return Message(session_id="s1", sender=sender, receiver=receiver, content=content, metadata=md)


# ---- egress check (the TC5 story) -------------------------------------------

def test_tc5_external_recipient_blocked():
    agent = AuthorizationAgent()  # zero config
    v = agent.check(_msg("summarizer", "emailer", "summary", recipient=EXTERNAL), CTX)
    assert v.label is Label.BLOCK
    assert "external" in v.reason and EXTERNAL in v.reason


def test_internal_recipient_passes():
    agent = AuthorizationAgent()
    v = agent.check(_msg("summarizer", "emailer", "summary", recipient=INTERNAL), CTX)
    assert v.label is Label.PASS


def test_phi_hop_without_recipient_passes():
    # record_reader -> summarizer carries PHI but has no recipient: not egress.
    agent = AuthorizationAgent()
    v = agent.check(_msg("record_reader", "summarizer", "PHI"), CTX)
    assert v.label is Label.PASS


# ---- relationship rule table ------------------------------------------------

def test_explicit_deny_rule_blocks():
    agent = AuthorizationAgent(rules=[
        PolicyRule(sender="summarizer", receiver="emailer", data_type="summary", action="deny")])
    v = agent.check(_msg("summarizer", "emailer", "summary", recipient=INTERNAL), CTX)
    assert v.label is Label.BLOCK


def test_explicit_allow_still_blocks_external_egress():
    # An allow rule permits the relationship but does NOT license external leakage.
    agent = AuthorizationAgent(rules=[
        PolicyRule(sender="summarizer", receiver="emailer", data_type="summary", action="allow")])
    v = agent.check(_msg("summarizer", "emailer", "summary", recipient=EXTERNAL), CTX)
    assert v.label is Label.BLOCK


def test_redact_rule_flags():
    agent = AuthorizationAgent(rules=[
        PolicyRule(sender="summarizer", receiver="emailer", data_type="summary", action="redact")])
    v = agent.check(_msg("summarizer", "emailer", "summary", recipient=INTERNAL), CTX)
    assert v.label is Label.FLAG


def test_wildcard_deny_credentials():
    agent = AuthorizationAgent(rules=[
        PolicyRule(sender="*", receiver="*", data_type="credential", action="deny")])
    v = agent.check(_msg("summarizer", "emailer", "credential", recipient=INTERNAL), CTX)
    assert v.label is Label.BLOCK


def test_default_allow_vs_strict_deny():
    m = _msg("summarizer", "emailer", "summary", recipient=INTERNAL)  # internal, no rule
    assert AuthorizationAgent(default_allow=True).check(m, CTX).label is Label.PASS
    assert AuthorizationAgent(default_allow=False).check(m, CTX).label is Label.BLOCK


def test_verdict_shape():
    agent = AuthorizationAgent()
    v = agent.check(_msg("record_reader", "summarizer", "PHI"), CTX)
    assert v.agent_name == "authorization"
    assert v.redacted_content is None
    assert 0.0 <= v.score <= 1.0


# ---- integration with the real policy engine --------------------------------

def test_block_verdict_enforced_by_engine():
    agent = AuthorizationAgent()
    m = _msg("summarizer", "emailer", "summary", recipient=EXTERNAL)
    v = agent.check(m, CTX)

    # ENFORCE: block stands and is enforced
    d_enf = resolve(m, [v], Policy(mode=Mode.ENFORCE))
    assert d_enf.action is Action.BLOCK
    assert d_enf.enforced is True

    # MONITOR: same verdict, clamped to FLAG, not enforced
    d_mon = resolve(m, [v], Policy(mode=Mode.MONITOR))
    assert d_mon.action is Action.FLAG
    assert d_mon.enforced is False
