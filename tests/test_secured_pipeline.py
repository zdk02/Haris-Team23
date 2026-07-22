"""Phase 3: the three real agents ENFORCING through the LIVE LangGraph pipeline.

`test_multiagent_integration.py` proves the agents compose at the Orchestrator level
(hand-built Messages through `process()`). This file proves the SAME stack enforcing
through the REAL compiled graph + interception seam, via `run_secured()`: egress leaks
are blocked mid-graph, the in-boundary flow is permitted, and monitor never blocks.

The langgraph-dependent runs are skipped where langgraph is absent (matches the existing
`test_end_to_end_on_real_langgraph_graph`). Presidio is NOT required here: these exercise
the Authorization + Information-flow agents (`include_secrets=False`), so they run without
the spaCy model. The Presidio-on, redaction-composing variant is covered by
`test_multiagent_integration.py`.
"""
from __future__ import annotations

import pytest

pytest.importorskip("langgraph.graph")

from demo_app.hospital.app import INTERNAL_DOCTOR, EXTERNAL_EXAMPLE
from demo_app.hospital.haris_pipeline import build_hospital_agents, run_secured
from haris.schemas.policy import Mode


def test_verbatim_to_external_is_blocked_in_enforce():
    r = run_secured("s1", "patient-A", EXTERNAL_EXAMPLE, leak="verbatim",
                    mode=Mode.ENFORCE, include_secrets=False)
    assert r["blocked"] is True
    assert r["final"] is None                                    # halted before delivery
    assert r["block_decision"].action.value == "block"
    assert any(v.agent_name == "authorization" and v.label.value == "block"
               for v in r["block_decision"].verdicts)


def test_derived_to_external_is_blocked_in_enforce():
    r = run_secured("s2", "patient-A", EXTERNAL_EXAMPLE, leak="identified",
                    mode=Mode.ENFORCE, include_secrets=False)
    assert r["blocked"] is True


def test_derived_to_internal_is_permitted_and_recorded():
    r = run_secured("s3", "patient-B", INTERNAL_DOCTOR, leak="identified",
                    mode=Mode.ENFORCE, include_secrets=False)
    assert r["blocked"] is False
    assert r["final"] is not None
    assert len(r["store"].get_lineage("s3")) == 2                # both hops recorded
    assert r["store"].graph.number_of_edges() == 2              # interaction graph built


def test_monitor_mode_never_blocks_even_on_egress():
    r = run_secured("s4", "patient-A", EXTERNAL_EXAMPLE, leak="identified",
                    mode=Mode.MONITOR, include_secrets=False)
    assert r["blocked"] is False
    assert r["final"] is not None
    assert all(d.enforced is False for d in r["decisions"])


def test_canonical_agent_lineup():
    """The single-source-of-truth agent list carries all three (or two without secrets)."""
    assert {a.name for a in build_hospital_agents(include_secrets=True)} == {
        "secrets_pii", "authorization", "infoflow"}
    assert {a.name for a in build_hospital_agents(include_secrets=False)} == {
        "authorization", "infoflow"}
