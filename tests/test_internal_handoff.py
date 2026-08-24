"""The false positive we chose to keep.

`internal_handoff` is the commonest message in a multi-agent pipeline: one agent reads a
record, the next receives a derived summary. No `recipient`, because this hop has no
destination outside the system. The hospital demo's own summarizer -> emailer handoff has
exactly this shape, and until now nothing in the corpus tested it.

Haris refuses it. `InformationFlowAgent.flag_unknown_destination` defaults True, so taint
bound for an undeclared destination is treated as not permitted.

THAT IS NOT A BUG TO FIX. `recipient` is sender-supplied, and an absent one is
indistinguishable from a deleted one (THREAT_MODEL.md §2.3): relaxing the check would let
an attacker switch off egress control by removing a single key. The cost of failing closed
is a false-positive rate, and the right response is to measure it, report it, and name the
deployment-era fix — an adapter that binds `recipient` from the transport — rather than to
trade the property away for a nicer number.

These tests pin all of that, including the part that is uncomfortable: both baselines get
this right and Haris does not.
"""
from __future__ import annotations

import pytest

from demo_app.eval.baselines import content_scanner, haris, metadata_heuristic
from demo_app.eval.generate import generate
from demo_app.eval.oracle import label_consistency_check


@pytest.fixture(scope="module")
def scenarios():
    return generate()


@pytest.fixture(scope="module")
def handoffs(scenarios):
    return [s for s in scenarios if s.family == "internal_handoff"]


def test_the_family_is_benign_and_undeclared(handoffs):
    assert len(handoffs) == 24
    for scn in handoffs:
        assert not scn.is_attack, scn.id
        for m in scn.messages:
            assert not m.metadata.get("recipient"), scn.id
            assert m.metadata.get("auth_token"), scn.id
        subjects = {m.metadata.get("data_subject") for m in scn.messages}
        assert len(subjects) == 1, scn.id


def test_it_is_labelled_benign_from_traffic(handoffs):
    for scn in handoffs:
        should_stop, method = label_consistency_check(scn)
        assert not should_stop, scn.id
        assert method == "traffic:none", (scn.id, method)


def test_nothing_leaves_the_system(handoffs):
    """No egress at all, so whatever the objection is, it is not exfiltration."""
    from demo_app.eval.domains import DOMAINS
    from demo_app.eval.leak_check import egresses
    for scn in handoffs:
        assert not egresses(scn.messages, scn.authorized_recipients,
                            DOMAINS[scn.domain].internal_at), scn.id


def test_haris_refuses_it(handoffs):
    """THE FINDING, and the one we keep. If this ever starts passing, check WHY: the
    likely cause is `flag_unknown_destination` being flipped, which hands an attacker a
    way to disable egress control by deleting one metadata key."""
    for scn in handoffs:
        assert haris(scn).stopped, f"{scn.id}: expected the fail-closed refusal here"


def test_both_baselines_get_it_right(handoffs):
    """The uncomfortable half, and it belongs in the report. The heuristic has no
    recipient to object to; the scanner has no egress to inspect. Both allow it, Haris
    does not — the mirror image of subject_forgery, and the honest price of treating an
    undeclared destination as untrusted."""
    for scn in handoffs:
        assert not metadata_heuristic(scn).stopped, scn.id
        assert not content_scanner(scn).stopped, scn.id


def test_declaring_an_internal_recipient_resolves_it(handoffs):
    """The deployment-era fix, demonstrated. Bind `recipient` at the interception adapter
    and the same traffic passes — so the false positive is a property of undeclared
    metadata, not of lineage tracking."""
    from demo_app.eval.domains import DOMAINS
    scn = handoffs[0]
    internal = DOMAINS[scn.domain].internal_recipient
    original = scn.messages
    scn.messages = [
        m if i == 0 else m.model_copy(
            update={"metadata": {**m.metadata, "recipient": internal}})
        for i, m in enumerate(original)
    ]
    try:
        assert not haris(scn).stopped, (
            "binding the recipient should make this hop unremarkable")
    finally:
        scn.messages = original
