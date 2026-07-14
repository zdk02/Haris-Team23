"""Unit tests for GraphStateStore (Module 6).

Includes a parity test proving it is a true drop-in for InMemoryStateStore:
for the same sequence of flows, get_context / get_lineage return identical values.
Plus the three checklist cases (two-hop, derived artifact taint, multi-subject).
"""

import networkx as nx

from haris.schemas.message import Message
from haris.state.memory import InMemoryStateStore
from haris.state.graph_store import GraphStateStore


def _msg(session_id, sender, receiver, content, data_type=None, data_subject=None):
    return Message(
        session_id=session_id,
        sender=sender,
        receiver=receiver,
        content=content,
        metadata={"data_type": data_type, "data_subject": data_subject},
    )


SEQUENCE = [
    ("s1", "record_reader", "summarizer", "Alice, DOB 1980-01-01, Type 2 diabetes", "PHI", "A"),
    ("s1", "summarizer", "emailer", "Patient summary: chronic condition managed", "summary", "A"),
]


def test_drop_in_parity_with_in_memory_store():
    """The frozen methods must behave identically to InMemoryStateStore."""
    mem, graph = InMemoryStateStore(), GraphStateStore()
    # Same Message instances into both stores (Message.timestamp is auto-set at
    # construction, so re-building per store would differ by microseconds).
    for args in SEQUENCE:
        m = _msg(*args)
        mem.record_flow(m)
        graph.record_flow(m)

    # get_lineage: same Messages, same order
    assert graph.get_lineage("s1") == mem.get_lineage("s1")
    # get_context: same shape and same value
    assert graph.get_context("s1") == mem.get_context("s1")
    # unknown session behaves the same
    assert graph.get_lineage("nope") == mem.get_lineage("nope") == []
    assert graph.get_context("nope") == mem.get_context("nope") == {"history": []}


def test_get_lineage_returns_message_objects_in_order():
    store = GraphStateStore()
    for args in SEQUENCE:
        store.record_flow(_msg(*args))
    lineage = store.get_lineage("s1")
    assert all(isinstance(m, Message) for m in lineage)
    assert [m.sender for m in lineage] == ["record_reader", "summarizer"]


def test_context_history_includes_current_hop():
    """Orchestrator records before get_context, so the current hop is in history."""
    store = GraphStateStore()
    store.record_flow(_msg(*SEQUENCE[0]))
    ctx = store.get_context("s1")
    assert isinstance(ctx["history"][-1], Message)
    assert ctx["history"][-1].sender == "record_reader"


def test_interaction_graph_shape():
    store = GraphStateStore()
    for args in SEQUENCE:
        store.record_flow(_msg(*args))
    assert set(store.graph.nodes) == {"record_reader", "summarizer", "emailer"}
    assert store.graph.number_of_edges() == 2
    sub = store.session_subgraph("s1")
    assert isinstance(sub, nx.MultiDiGraph)
    assert sub.number_of_edges() == 2


def test_derived_artifact_taint_surfaces():
    """PHI origin is a taint source; the derived summary hop is not."""
    store = GraphStateStore()
    for args in SEQUENCE:
        store.record_flow(_msg(*args))
    sources = store.taint_sources("s1")
    assert len(sources) == 1
    assert sources[0]["origin"] == "record_reader"
    assert sources[0]["data_type"] == "PHI"
    assert sources[0]["data_subject"] == "A"


def test_multi_subject_lineage_is_isolated():
    store = GraphStateStore()
    store.record_flow(_msg("sA", "record_reader", "summarizer", "Alice PHI", "PHI", "A"))
    store.record_flow(_msg("sB", "record_reader", "summarizer", "Bob PHI", "PHI", "B"))

    assert {s["data_subject"] for s in store.taint_sources("sA")} == {"A"}
    assert {s["data_subject"] for s in store.taint_sources("sB")} == {"B"}
    assert len(store.get_lineage("sA")) == 1
    assert len(store.get_lineage("sB")) == 1
    assert all(
        d["session_id"] == "sA"
        for *_e, d in store.session_subgraph("sA").edges(data=True)
    )
