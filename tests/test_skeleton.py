import pytest

from demo_app.interception import InterceptionAdapter
from haris.agents.base import SecurityAgent
from haris.orchestrator.orchestrator import Orchestrator
from haris.schemas.decision import Action, HarisBlocked
from haris.schemas.policy import Mode, Policy
from haris.schemas.verdict import Label, Verdict
from haris.state.memory import InMemoryStateStore


class StubAgent(SecurityAgent):
    """Test double: returns whatever verdict it was constructed with."""

    def __init__(self, name, label, score, redacted=None):
        self.name = name
        self._v = Verdict(agent_name=name, label=label, score=score,
                          redacted_content=redacted, reason="stub")

    def check(self, message, context):
        return self._v


def _haris(agents=None, policy=None):
    store = InMemoryStateStore()
    orch = Orchestrator(state_store=store, agents=agents or [], policy=policy)
    return store, InterceptionAdapter(orch)


def test_message_passes_through_unchanged():
    _, haris = _haris()
    delivered, decision = haris.intercept("s1", "a", "b", "hello")
    assert delivered == "hello"
    assert decision.action is Action.ALLOW


def test_flow_is_recorded():
    store, haris = _haris()
    haris.intercept("s1", "a", "b", "hello")
    assert len(store.get_lineage("s1")) == 1


def test_monitor_mode_never_blocks():
    agents = [StubAgent("authz", Label.BLOCK, 0.99)]
    _, haris = _haris(agents)  # Policy() defaults to MONITOR
    delivered, decision = haris.intercept("s1", "a", "b", "secret")
    assert delivered == "secret"          # nothing was stopped
    assert decision.action is Action.FLAG  # clamped from BLOCK
    assert decision.enforced is False


def test_enforce_mode_blocks_and_raises():
    agents = [StubAgent("authz", Label.BLOCK, 0.99)]
    policy = Policy(mode=Mode.ENFORCE)
    _, haris = _haris(agents, policy)
    with pytest.raises(HarisBlocked) as excinfo:
        haris.intercept("s1", "a", "b", "secret")
    assert excinfo.value.decision.action is Action.BLOCK


def test_sub_threshold_block_downgrades_to_flag():
    agents = [StubAgent("authz", Label.BLOCK, 0.40)]
    policy = Policy(mode=Mode.ENFORCE, thresholds={"authz": 0.75})
    _, haris = _haris(agents, policy)
    delivered, decision = haris.intercept("s1", "a", "b", "hi")
    assert decision.action is Action.FLAG   # not blocked
    assert delivered == "hi"


def test_redactions_compose_in_agent_order():
    agents = [
        StubAgent("pii", Label.FLAG, 0.9, redacted="[X] and SSN"),
        StubAgent("infoflow", Label.FLAG, 0.9, redacted="[X] and [Y]"),
    ]
    policy = Policy(mode=Mode.ENFORCE)
    _, haris = _haris(agents, policy)
    delivered, decision = haris.intercept("s1", "a", "b", "NAME and SSN")
    assert decision.action is Action.REDACT
    assert delivered == "[X] and [Y]"


def test_block_beats_redact():
    agents = [
        StubAgent("pii", Label.FLAG, 0.9, redacted="[X]"),
        StubAgent("authz", Label.BLOCK, 0.9),
    ]
    policy = Policy(mode=Mode.ENFORCE)
    _, haris = _haris(agents, policy)
    with pytest.raises(HarisBlocked):
        haris.intercept("s1", "a", "b", "NAME")