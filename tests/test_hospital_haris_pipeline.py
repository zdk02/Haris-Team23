"""Step 4 check: the hospital app running end-to-end through Haris.

Proves the pass-through spine: with zero agents in monitor mode the app behaves
identically (still leaks) but Haris sees and records every hop. Also proves the
spine is ready to enforce: a blocking agent in enforce mode halts the flow.

Most tests wrap the hospital agents and call them directly (no langgraph). The last
builds the real compiled graph and is skipped if langgraph is absent.
"""
from __future__ import annotations

import pytest

from demo_app.hospital.app import (
    record_reader, summarizer, emailer, INTERNAL_DOCTOR, EXTERNAL_EXAMPLE,
)
from demo_app.interception import InterceptionAdapter
from demo_app.langgraph_interception import HarisLangGraph
from haris.agents.base import SecurityAgent
from haris.orchestrator.orchestrator import Orchestrator
from haris.schemas.decision import Action, HarisBlocked
from haris.schemas.policy import Mode, Policy
from haris.schemas.verdict import Label, Verdict
from haris.state.memory import InMemoryStateStore


class StubAgent(SecurityAgent):
    def __init__(self, name, label, score, redacted=None):
        self.name = name
        self._v = Verdict(agent_name=name, label=label, score=score,
                          redacted_content=redacted, reason="stub")

    def check(self, message, context):
        return self._v


def _pipeline(agents=None, policy=None):
    store = InMemoryStateStore()
    orch = Orchestrator(state_store=store, agents=agents or [], policy=policy)
    haris = HarisLangGraph(InterceptionAdapter(orch))
    w_reader = haris.wrap(record_reader, "record_reader", "summarizer",
                          data_type="PHI", message_key="record")
    w_summ = haris.wrap(summarizer, "summarizer", "emailer",
                        data_type="summary", message_key="summary",
                        state_metadata_keys=["recipient", "subject"])
    return store, haris, w_reader, w_summ


def _run_by_hand(w_reader, w_summ, subject, recipient, leak):
    state = {"session_id": "s1", "subject": subject,
             "recipient": recipient, "leak": leak}
    state.update(w_reader(state))
    state.update(w_summ(state))
    state.update(emailer(state))
    return state


def test_pass_through_is_transparent_but_observed():
    """Zero agents + monitor: app still leaks, but Haris saw & recorded both hops."""
    store, haris, w_reader, w_summ = _pipeline()  # zero agents, monitor
    final = _run_by_hand(w_reader, w_summ, "patient-A", EXTERNAL_EXAMPLE, "verbatim")

    assert "MRN-0001" in final["sent"]["body"]              # nothing was blocked
    assert [d.action for d in haris.decisions] == [Action.ALLOW, Action.ALLOW]
    assert all(d.enforced is False for d in haris.decisions)
    assert len(store.get_lineage("s1")) == 2                 # both hops recorded


def test_metadata_carries_data_type_and_recipient():
    """The summarizer->emailer hop's Message carries the info later agents need."""
    store, haris, w_reader, w_summ = _pipeline()
    _run_by_hand(w_reader, w_summ, "patient-B", EXTERNAL_EXAMPLE, "identified")

    lineage = store.get_lineage("s1")
    assert lineage[0].metadata.get("data_type") == "PHI"          # record hop
    assert lineage[1].metadata.get("data_type") == "summary"      # summary hop
    assert lineage[1].metadata.get("recipient") == EXTERNAL_EXAMPLE
    assert lineage[1].metadata.get("subject") == "patient-B"


def test_spine_is_ready_to_enforce():
    """A blocking agent in enforce mode halts the flow at the first hop."""
    agents = [StubAgent("authz", Label.BLOCK, 0.99)]
    _, _, w_reader, _ = _pipeline(agents, Policy(mode=Mode.ENFORCE))
    with pytest.raises(HarisBlocked):
        w_reader({"session_id": "s1", "subject": "patient-A"})


def test_end_to_end_on_real_langgraph_graph():
    pytest.importorskip("langgraph.graph")
    from demo_app.hospital.haris_pipeline import run_through_haris
    final, haris, store = run_through_haris(
        "e2e", "patient-A", EXTERNAL_EXAMPLE, leak="verbatim")
    assert len(haris.decisions) == 2                 # Haris saw both hops
    assert len(store.get_lineage("e2e")) == 2
    assert "MRN-0001" in final["sent"]["body"]        # monitor never blocks