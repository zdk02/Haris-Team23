"""Phase 3: the three real agents ENFORCING through the LIVE LangGraph pipeline.

`test_multiagent_integration.py` proves the agents compose at the Orchestrator level
(hand-built Messages through `process()`). This file proves the SAME stack enforcing
through the REAL compiled graph + interception seam, via `run_secured()`: egress leaks
are blocked mid-graph, the in-boundary flow is permitted, and monitor never blocks.

The langgraph-dependent runs are skipped where langgraph is absent (matches the existing
`test_end_to_end_on_real_langgraph_graph`). The core cases exercise Authorization +
Information-flow (`include_secrets=False`), so they run without the spaCy model; the
full-battery cases add the real Secrets/PII agent and are skipped when Presidio is
unavailable. The reliability cases drive a crashing agent through the running graph to
prove task 2's fail-open / fail-closed guard end-to-end.
"""
from __future__ import annotations

import pytest

pytest.importorskip("langgraph.graph")

from demo_app.hospital.app import INTERNAL_DOCTOR, EXTERNAL_EXAMPLE
from demo_app.hospital.haris_pipeline import build_hospital_agents, run_secured
from haris.agents.base import SecurityAgent
from haris.schemas.policy import Mode


def _presidio_available() -> bool:
    try:
        from haris.agents.secrets_pii import SecretsPIIAgent
        SecretsPIIAgent().pii.analyze("warm up")
        return True
    except Exception:
        return False


requires_presidio = pytest.mark.skipif(
    not _presidio_available(), reason="Presidio/spaCy model unavailable")


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


# --------------------------------------------------------------------------- #
# Whole-pipeline battery with ALL THREE real agents (Presidio on)             #
# --------------------------------------------------------------------------- #

@requires_presidio
def test_full_battery_all_three_real_agents_enforce():
    """The complete assembled system on the threat battery: real graph + Secrets/PII +
    Authorization + Information-flow, Presidio on, ENFORCE. One outcome per threat case."""
    # TC1 clean -> internal: delivered, nothing leaked
    tc1 = run_secured("b1", "patient-A", INTERNAL_DOCTOR, leak="clean",
                      mode=Mode.ENFORCE, include_secrets=True)
    assert tc1["blocked"] is False and tc1["final"] is not None

    # TC2 verbatim PHI -> external: blocked before delivery
    tc2 = run_secured("b2", "patient-A", EXTERNAL_EXAMPLE, leak="verbatim",
                      mode=Mode.ENFORCE, include_secrets=True)
    assert tc2["blocked"] is True

    # TC3 derived leak -> external: blocked
    tc3 = run_secured("b3", "patient-A", EXTERNAL_EXAMPLE, leak="identified",
                      mode=Mode.ENFORCE, include_secrets=True)
    assert tc3["blocked"] is True

    # TC5 derived -> internal doctor: permitted, and the boundary-aware Secrets/PII agent
    # does NOT scrub the patient name the treating doctor is allowed to see.
    tc5 = run_secured("b5", "patient-B", INTERNAL_DOCTOR, leak="identified",
                      mode=Mode.ENFORCE, include_secrets=True)
    assert tc5["blocked"] is False and tc5["final"] is not None
    body = tc5["final"]["sent"]["body"]
    assert "John Smith" in body            # the doctor sees the patient name
    assert "[REDACTED]" not in body        # not scrubbed / not mangled on the internal path


@requires_presidio
def test_full_battery_monitor_never_blocks():
    """The same egress leaks in MONITOR: the app always behaves as if Haris weren't there."""
    for sid, leak in [("m2", "verbatim"), ("m3", "identified")]:
        r = run_secured(sid, "patient-A", EXTERNAL_EXAMPLE, leak=leak,
                        mode=Mode.MONITOR, include_secrets=True)
        assert r["blocked"] is False and r["final"] is not None
        assert all(d.enforced is False for d in r["decisions"])


# --------------------------------------------------------------------------- #
# Reliability guard exercised through the LIVE pipeline (task 2)              #
# --------------------------------------------------------------------------- #

class _CrashAgent(SecurityAgent):
    name = "crash"

    def check(self, message, context):
        raise RuntimeError("detector exploded")


def test_agent_crash_fails_closed_through_pipeline_in_enforce():
    """A crashing agent inside the running graph fails CLOSED: the hop is blocked."""
    r = run_secured("rc", "patient-A", INTERNAL_DOCTOR, leak="clean",
                    mode=Mode.ENFORCE, agents=[_CrashAgent()])
    assert r["blocked"] is True
    assert r["final"] is None


def test_agent_crash_fails_open_through_pipeline_in_monitor():
    """The same crash in MONITOR fails OPEN: the app is delivered, unbroken by our bug."""
    r = run_secured("rm", "patient-A", INTERNAL_DOCTOR, leak="clean",
                    mode=Mode.MONITOR, agents=[_CrashAgent()])
    assert r["blocked"] is False
    assert r["final"] is not None
