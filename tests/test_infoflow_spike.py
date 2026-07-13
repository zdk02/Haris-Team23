"""Step 5 spike measurements: coarse taint-by-lineage in the InformationFlowAgent.

The direct tests build (message, context) pairs and call the agent -- no langgraph.
The last test runs the agent inside the real hospital pipeline and is skipped if
langgraph is absent.
"""
from __future__ import annotations

import pytest

from demo_app.hospital.app import EXTERNAL_EXAMPLE
from demo_app.hospital.records import load_record
from demo_app.hospital.app import format_record
from haris.agents.infoflow import InformationFlowAgent
from haris.schemas.message import Message
from haris.schemas.verdict import Label

RECORD_A = format_record(load_record("patient-A"))


def _phi_source() -> Message:
    return Message(session_id="s", sender="record_reader", receiver="summarizer",
                   content=RECORD_A, metadata={"data_type": "PHI"})


def _derived(text: str) -> Message:
    return Message(session_id="s", sender="summarizer", receiver="emailer",
                   content=text, metadata={"data_type": "summary",
                                           "recipient": EXTERNAL_EXAMPLE})


def _ctx(*msgs) -> dict:
    return {"history": list(msgs)}


AGENT = InformationFlowAgent()


def test_tc3_derived_leak_is_caught_via_lineage():
    """Identifiers resurface in a rewritten summary -> flagged, with redaction."""
    msg = _derived("Visit summary for Jane Doe: Type 2 diabetes; hypertension. "
                   "Follow-up advised.")
    v = AGENT.check(msg, _ctx(_phi_source(), msg))
    assert v.label is Label.FLAG
    assert v.score >= 0.6
    assert "Jane Doe" not in (v.redacted_content or "")   # masked
    assert "[REDACTED]" in (v.redacted_content or "")


def test_tc1_clean_summary_is_not_a_false_positive():
    """De-identified summary derived from PHI -> correctly passes (no over-flag)."""
    msg = _derived("Visit summary: routine follow-up, no action required.")
    v = AGENT.check(msg, _ctx(_phi_source(), msg))
    assert v.label is Label.PASS


def test_semantic_paraphrase_is_missed_the_ceiling():
    """Condition leaked with NO exact identifier tokens -> coarse taint misses it.

    This documents the honest limit that motivates the roadmap semantic agent.
    """
    msg = _derived("Visit summary: a middle-aged individual is managing a chronic "
                   "blood-sugar condition and raised arterial pressure.")
    v = AGENT.check(msg, _ctx(_phi_source(), msg))
    assert v.label is Label.PASS   # false negative, by design of a coarse detector


def test_no_phi_source_in_lineage_passes():
    msg = _derived("Some unrelated message with Jane Doe in it.")
    v = AGENT.check(msg, _ctx(msg))          # no PHI source present
    assert v.label is Label.PASS


def test_naive_whole_record_scan_would_miss_tc3():
    """Proves the value: the baseline a per-message scanner uses fails on TC3."""
    tc3_summary = ("Visit summary for Jane Doe: Type 2 diabetes; hypertension. "
                   "Follow-up advised.")
    assert RECORD_A.strip() not in tc3_summary       # whole-record match: MISS
    # but the lineage agent catches it (see test_tc3_...), which is the point.


def test_in_real_pipeline_redacts_tc3_to_emailer():
    pytest.importorskip("langgraph.graph")
    from demo_app.hospital.haris_pipeline import build_haris_graph
    from haris.orchestrator.orchestrator import Orchestrator
    from haris.schemas.policy import Mode, Policy
    from haris.state.memory import InMemoryStateStore

    store = InMemoryStateStore()
    orch = Orchestrator(store, agents=[InformationFlowAgent()],
                        policy=Policy(mode=Mode.ENFORCE))
    graph, haris = build_haris_graph(orch)
    final = graph.invoke({"session_id": "tc3", "subject": "patient-A",
                          "recipient": EXTERNAL_EXAMPLE, "leak": "identified"})
    # The summary that reached the emailer was redacted by the info-flow agent.
    assert "Jane Doe" not in final["sent"]["body"]
    assert "[REDACTED]" in final["sent"]["body"]