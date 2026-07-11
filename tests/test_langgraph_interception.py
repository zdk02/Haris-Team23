"""Step 2 check: prove Haris intercepts LangGraph messages through the REAL spine.

Most of these tests call the wrapped node directly (a wrapped node is just a
`state -> delta` function), so they exercise the real Message -> Orchestrator ->
Decision path WITHOUT needing langgraph installed. The final test builds an actual
2-node LangGraph graph and is skipped if langgraph is not present.
"""
from __future__ import annotations

import pytest

from demo_app.interception import InterceptionAdapter
from demo_app.langgraph_interception import HarisLangGraph
from haris.agents.base import SecurityAgent
from haris.orchestrator.orchestrator import Orchestrator
from haris.schemas.decision import Action, HarisBlocked
from haris.schemas.policy import Mode, Policy
from haris.schemas.verdict import Label, Verdict
from haris.state.memory import InMemoryStateStore


class StubAgent(SecurityAgent):
    """Test double: returns a fixed verdict, so we drive the real policy engine."""

    def __init__(self, name, label, score, redacted=None):
        self.name = name
        self._v = Verdict(agent_name=name, label=label, score=score,
                          redacted_content=redacted, reason="stub")

    def check(self, message, context):
        return self._v


def _haris(agents=None, policy=None):
    store = InMemoryStateStore()
    orch = Orchestrator(state_store=store, agents=agents or [], policy=policy)
    return store, HarisLangGraph(InterceptionAdapter(orch))


# The two trivial "agents" (stand-ins; the real ones arrive in Step 3). Their
# content is fake, but the interception wrapper never assumes anything about it.
def agent_a(state):
    return {"message": "hello from A -- SECRET=sk-12345"}


def agent_b(state):
    return {"message": f"B forwards <{state['message']}>"}


def test_pass_through_zero_agents_is_transparent():
    """Zero agents + monitor mode => every hop passes through unchanged (the spine)."""
    store, haris = _haris()  # zero agents, default Policy() == monitor
    wa = haris.wrap(agent_a, "agent_a", "agent_b", data_type="PHI")
    wb = haris.wrap(agent_b, "agent_b", "emailer", data_type="summary")

    state = {"session_id": "s1"}
    state = {**state, **wa(state)}
    state = {**state, **wb(state)}

    assert "sk-12345" in state["message"]                 # nothing was altered
    assert [d.action for d in haris.decisions] == [Action.ALLOW, Action.ALLOW]
    assert all(d.enforced is False for d in haris.decisions)
    assert len(store.get_lineage("s1")) == 2               # both hops recorded


def test_redaction_flows_to_next_node():
    """A redacting agent in enforce mode: the NEXT node sees the redacted message."""
    agents = [StubAgent("pii", Label.FLAG, 0.9,
                        redacted="hello from A -- SECRET=[REDACTED]")]
    _, haris = _haris(agents, Policy(mode=Mode.ENFORCE))
    wa = haris.wrap(agent_a, "agent_a", "agent_b", data_type="PHI")

    out = wa({"session_id": "s1"})
    assert "sk-12345" not in out["message"]                # redacted mid-flight
    assert haris.decisions[-1].action is Action.REDACT


def test_block_halts_the_flow():
    """A blocking agent in enforce mode raises HarisBlocked out of the node."""
    agents = [StubAgent("authz", Label.BLOCK, 0.99)]
    _, haris = _haris(agents, Policy(mode=Mode.ENFORCE))
    wa = haris.wrap(agent_a, "agent_a", "agent_b", data_type="PHI")

    with pytest.raises(HarisBlocked):
        wa({"session_id": "s1"})


def test_end_to_end_on_a_real_langgraph_graph():
    """The same wrapper inside an actual compiled LangGraph graph."""
    lg = pytest.importorskip("langgraph.graph")
    from typing import TypedDict

    class State(TypedDict):
        session_id: str
        message: str

    store, haris = _haris()  # zero agents, monitor
    builder = lg.StateGraph(State)
    builder.add_node("agent_a", haris.wrap(agent_a, "agent_a", "agent_b", data_type="PHI"))
    builder.add_node("agent_b", haris.wrap(agent_b, "agent_b", "emailer", data_type="summary"))
    builder.add_edge(lg.START, "agent_a")
    builder.add_edge("agent_a", "agent_b")
    builder.add_edge("agent_b", lg.END)
    graph = builder.compile()

    final = graph.invoke({"session_id": "s1", "message": ""})

    assert "B forwards" in final["message"]                # graph ran end to end
    assert len(haris.decisions) == 2                        # Haris saw both hops
    assert len(store.get_lineage("s1")) == 2