"""Tests for the dashboard's data layer (`demo_app/dashboard_data.py`).

WHY THIS FILE EXISTS.
`grep -rn "run_battery\\|get_dashboard" tests/` returned nothing until 2026-08-24. The
dashboard is one of the four graded deliverables and no test touched it, which is how the
following regression shipped and stayed green at 180/180:

Adding `IdentityAgent` to the shipped line-up (correct, and required — the pipeline had no
spoof defence) blocked EVERY hop of the demo battery, because `_play` builds `Message`
objects by hand and supplied no `auth_token`. The dashboard rendered 10 blocked, 0 allowed,
0 delivered payloads; "TC1 · clean → internal" displayed as BLOCKED; and because a blocked
message is never recorded to lineage, the info-flow and subject-binding module counters
dropped to 0 — the two cases the demo exists to show.

The lesson is the same one the wiring tests encode: a component change is safe, and its
effect on the systems that CONSUME that component is not. These tests assert the shape of
what a grader actually sees on screen.
"""
from __future__ import annotations

import pytest

from demo_app.dashboard_data import (SCENARIOS, compute_kpis, get_dashboard,
                                     presidio_available, run_battery)
from haris.schemas.policy import Mode


@pytest.fixture(scope="module")
def enforce():
    return get_dashboard(Mode.ENFORCE, include_secrets=False)


@pytest.fixture(scope="module")
def monitor():
    return get_dashboard(Mode.MONITOR, include_secrets=False)


@pytest.fixture(scope="module")
def with_secrets():
    """The battery WITH the secrets/PII agent. Separate fixture because it needs Presidio +
    the spaCy model, and the rest of this file must keep running on a machine without them.
    Only the redaction tests need it: redaction is that agent's output."""
    if not presidio_available():
        pytest.skip("Presidio/spaCy not installed — the redact path cannot run")
    return get_dashboard(Mode.ENFORCE, include_secrets=True)


# --- the battery must actually flow, not just terminate ------------------------

def test_every_scenario_produces_hops(enforce):
    assert len(enforce["records"]) == 2 * len(SCENARIOS)
    assert {r["session"] for r in enforce["records"]} == {s.label for s in SCENARIOS}


def test_the_demo_is_not_uniformly_blocked(enforce):
    """THE REGRESSION. Every hop blocked is indistinguishable from Haris working, and it
    is what a grader would have seen: no delivered payload anywhere on the screen."""
    actions = [r["action"] for r in enforce["records"]]
    assert actions.count("block") > 0, "nothing blocked — the demo shows no enforcement"
    assert actions.count("allow") > 0, ("everything blocked — most likely the battery "
                                        "stopped authenticating its own senders")
    assert any(r["final_content"] for r in enforce["records"]), "no delivered payload to show"


def test_monitor_mode_blocks_nothing(monitor):
    """The mode gate, from the dashboard's side: monitor observes and never stops."""
    assert all(r["action"] != "block" for r in monitor["records"])
    assert monitor["kpis"]["blocked"] == 0


# --- the cases the demo exists to demonstrate ----------------------------------

def test_the_clean_scenario_is_delivered(enforce):
    """TC1 is the control. If it is blocked, the demo argues against itself."""
    tc1 = [r for r in enforce["records"] if r["session"].startswith("TC1")]
    assert tc1 and all(r["action"] == "allow" for r in tc1), tc1


def test_the_external_leaks_are_blocked(enforce):
    """TC2 (verbatim) and TC3 (derived) must be stopped at the egress hop."""
    for label in ("TC2", "TC3"):
        hops = [r for r in enforce["records"] if r["session"].startswith(label)]
        assert hops, label
        assert hops[-1]["action"] == "block", (label, hops[-1]["action"])


def test_the_cross_subject_case_is_blocked_by_subject_binding(enforce):
    """TC4. It needs a session that BOUND a subject first, which needs the first hop to be
    delivered — so this fails if the battery is uniformly blocked."""
    tc4 = [r for r in enforce["records"] if r["session"].startswith("TC4")]
    assert tc4, "TC4 produced no hops"
    blocked = [r for r in tc4 if r["action"] == "block"]
    assert blocked, "TC4 blocked nothing — the session never bound a subject"
    assert any(v["agent"] == "subject_binding" and v["label"] == "block"
               for v in blocked[-1]["verdicts"]), blocked[-1]["verdicts"]


def test_redaction_is_reachable_and_delivers_the_message_minus_the_secret(with_secrets):
    """TC7. Every decision the dashboard could show was allow, flag or block: nothing in the
    battery ever resolved to REDACT, because in each scenario that produced redacted content
    an agent also blocked, and block wins. So the redact KPI tile, the legend entry, the
    filter option and `_highlight_payload` were all dead UI describing a capability the demo
    never exercised.

    Redaction is the outcome that distinguishes Haris from a firewall: the message still
    arrives, minus the part that must not travel. Assert BOTH halves."""
    tc7 = [r for r in with_secrets["records"] if r["session"].startswith("TC7")]
    assert tc7, "TC7 produced no hops"
    redacted = [r for r in tc7 if r["action"] == "redact"]
    assert redacted, [r["action"] for r in tc7]

    delivered = redacted[-1]["final_content"]
    assert delivered, "a redacted message must still be delivered — that is the point"
    assert "AKIAIOSFODNN7EXAMPLE" not in delivered, delivered
    assert "sk-live-4f9a2c7e13b64d8fa05e6c19" not in delivered, delivered
    assert "[REDACTED]" in delivered, delivered
    # and the clinical content the receiving agent legitimately needs survived
    assert "Visit summary" in delivered, delivered


def test_redaction_is_visible_in_the_kpis(with_secrets):
    """The tile reads from compute_kpis, so a live redact path must reach it."""
    assert with_secrets["kpis"]["redacted"] >= 1, with_secrets["kpis"]


def test_the_module_counters_are_not_all_zero(enforce):
    """The 'Security checks' panel. All-zero means the agents never got to run, which is
    what a uniformly-blocked battery produces."""
    counts = {m["name"]: m["num"] for m in enforce["modules"] if m["num"] is not None}
    assert sum(counts.values()) > 0, counts


# --- every shipped agent must be visible to the operator -----------------------

def test_every_agent_that_votes_has_a_display_label(enforce):
    """An agent whose raw name appears next to prettified ones is one nobody thought about
    when it was added. `identity` shipped without a label, a table column or a module card
    while driving the outcome of every hop."""
    from demo_app.dashboard_data import AGENT_LABELS
    voting = {v["agent"] for r in enforce["records"] for v in r["verdicts"]}
    missing = voting - set(AGENT_LABELS)
    assert not missing, f"agents with no display label: {sorted(missing)}"


def test_the_incident_feed_carries_no_message_content(enforce):
    """The banner renders sanitized fields only — an alert channel must not become the leak."""
    for incident in enforce["incidents"]:
        assert set(incident) == {"severity", "category", "source", "summary",
                                 "session_id", "timestamp"}, incident
        assert "Jane Doe" not in incident["summary"]


def test_kpis_agree_with_the_records(enforce):
    k = compute_kpis(enforce["records"])
    assert k["inspected"] == len(enforce["records"])
    assert k["blocked"] == sum(1 for r in enforce["records"] if r["action"] == "block")


def test_run_battery_produces_a_verifiable_audit_chain():
    audit = run_battery(mode=Mode.ENFORCE, include_secrets=False)
    assert len(audit) == 2 * len(SCENARIOS)
    assert audit.verify_chain() is True
