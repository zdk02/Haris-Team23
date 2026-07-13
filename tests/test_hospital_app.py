"""Step 3 check: the hospital app reproduces the threat-model scenarios.

These assertions PIN the vulnerable behaviour so Step 4 can later assert that Haris
catches it. Most tests call the agent functions directly (no langgraph needed); the
last one runs the real compiled graph and is skipped if langgraph is absent.
"""
from __future__ import annotations

import pytest

from demo_app.hospital.app import (
    record_reader, summarizer, emailer,
    INTERNAL_DOCTOR, EXTERNAL_EXAMPLE,
)


def _flow(subject: str, recipient: str, leak: str) -> dict:
    """Run the three agents in order by hand (no langgraph) and return final state."""
    state = {"session_id": "t", "subject": subject,
             "recipient": recipient, "leak": leak}
    state.update(record_reader(state))
    state.update(summarizer(state))
    state.update(emailer(state))
    return state


def test_tc1_clean_baseline_is_safe():
    """De-identified summary to the internal doctor: no PHI, not external."""
    s = _flow("patient-A", INTERNAL_DOCTOR, leak="clean")
    assert "Jane Doe" not in s["summary"]
    assert "MRN-0001" not in s["summary"]
    assert s["sent"]["external"] is False


def test_tc2_direct_leak_sends_raw_phi_externally():
    """Verbatim mode leaks raw PHI (MRN) to an external address -- the easy catch."""
    s = _flow("patient-A", EXTERNAL_EXAMPLE, leak="verbatim")
    assert "MRN-0001" in s["summary"]          # raw record text is present
    assert s["sent"]["external"] is True       # ... and it is going outside


def test_tc5_same_summary_differs_only_by_recipient():
    """Identical summary, two recipients: content is the same, only external differs."""
    internal = _flow("patient-B", INTERNAL_DOCTOR, leak="identified")
    external = _flow("patient-B", EXTERNAL_EXAMPLE, leak="identified")
    assert internal["summary"] == external["summary"]     # same content
    assert "John Smith" in internal["summary"]            # carries identifying detail
    assert internal["sent"]["external"] is False
    assert external["sent"]["external"] is True           # the only difference


def test_record_reader_emits_phi_with_subject():
    s = {"subject": "patient-A"}
    out = record_reader(s)
    assert "patient-A" in out["record"]
    assert "MRN-0001" in out["record"]


def test_end_to_end_on_real_langgraph_graph():
    pytest.importorskip("langgraph.graph")
    from demo_app.hospital.app import run_scenario
    final = run_scenario("e2e", "patient-A", EXTERNAL_EXAMPLE, leak="verbatim")
    assert final["sent"]["to"] == EXTERNAL_EXAMPLE
    assert "MRN-0001" in final["sent"]["body"]   # graph ran; leak reproduced