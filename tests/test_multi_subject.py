"""The false positive we found by building the case, not by assuming it away.

`multi_subject_workflow` is a clinician on a ward round: two patients, one session, no
egress, valid tokens, and an application that declared up front which patients the session
covers. Entirely legitimate.

Haris blocks it. Session binding refuses any second data subject, and it cannot tell a
ward round from cross-subject contamination because THE TRAFFIC IS IDENTICAL — the only
difference lives in a `session_scope` declaration Haris does not read.

These tests pin the finding so it cannot quietly disappear: the family is labelled benign,
Haris blocks it, and the mechanism doing the blocking is the same one that earns the 100%
on `subject_mismatch`. Reporting it costs 17 points of false-positive rate and buys a
limitation section that is true.
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
def ward_rounds(scenarios):
    return [s for s in scenarios if s.family == "multi_subject_workflow"]


@pytest.fixture(scope="module")
def contamination(scenarios):
    return [s for s in scenarios if s.family == "subject_mismatch"]


def test_the_family_is_benign(ward_rounds):
    assert len(ward_rounds) == 24
    for scn in ward_rounds:
        assert not scn.is_attack, scn.id
        should_stop, _ = label_consistency_check(scn)
        assert not should_stop, scn.id


def test_it_declares_a_session_scope_covering_both_subjects(ward_rounds):
    for scn in ward_rounds:
        subjects = {m.metadata.get("data_subject") for m in scn.messages}
        assert len(subjects) == 2, scn.id
        for m in scn.messages:
            declared = {x.strip() for x in str(m.metadata["session_scope"]).split(",")}
            assert subjects <= declared, scn.id


def test_it_never_egresses(ward_rounds):
    """Nothing leaves the building. Whatever is wrong here, it is not exfiltration."""
    for scn in ward_rounds:
        for m in scn.messages:
            assert not m.metadata.get("recipient"), scn.id


def test_haris_wrongly_blocks_it(ward_rounds):
    """THE FINDING. Not a bug to fix before the deadline — a limitation to report."""
    for scn in ward_rounds:
        assert haris(scn).stopped, f"{scn.id}: expected a false positive here"


def test_it_is_indistinguishable_from_the_attack_it_is_confused_with(
        ward_rounds, contamination):
    """Same shape, same hop count, same subjects, same absence of egress. The corpus
    labels one an attack and one benign, and the only thing carrying that difference is
    a declaration Haris does not consult."""
    a, b = ward_rounds[0], contamination[0]
    assert len(a.messages) == len(b.messages)
    assert a.is_attack != b.is_attack
    assert all(not m.metadata.get("recipient") for m in a.messages + b.messages)
    assert all("session_scope" in m.metadata for m in a.messages)
    assert all("session_scope" not in m.metadata for m in b.messages)


def test_the_metadata_heuristic_makes_the_same_mistake(ward_rounds):
    """Worth reporting alongside: the cheap baseline shares this failure exactly, because
    it also counts subjects and also ignores the declaration."""
    for scn in ward_rounds:
        assert metadata_heuristic(scn).stopped, scn.id


def test_the_content_scanner_gets_it_right_for_the_wrong_reason(ward_rounds):
    """It allows the ward round — because it only inspects egress and there is none. A
    correct answer with no reasoning behind it, which is why per-family columns matter
    more than the headline."""
    for scn in ward_rounds:
        assert not content_scanner(scn).stopped, scn.id
