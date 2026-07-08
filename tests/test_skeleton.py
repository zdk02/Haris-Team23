from demo_app.interception import InterceptionAdapter
from haris.orchestrator.orchestrator import Orchestrator
from haris.state.memory import InMemoryStateStore


def _haris():
    store = InMemoryStateStore()
    return store, InterceptionAdapter(Orchestrator(state_store=store, agents=[]))


def test_message_passes_through_unchanged():
    _, haris = _haris()
    out = haris.intercept("s1", "a", "b", "hello")
    assert out.content == "hello"


def test_flow_is_recorded():
    store, haris = _haris()
    haris.intercept("s1", "a", "b", "hello")
    assert len(store.get_lineage("s1")) == 1
