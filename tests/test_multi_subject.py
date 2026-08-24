"""Declared session scope: the false positive we found, and the one we took to close it.

THE FINDING (measured, tag `fp-before-session-scope`). `multi_subject_workflow` is a
clinician on a ward round: two patients, one session, no egress, valid tokens, and an
application declaring up front which patients the session covers. Entirely legitimate —
and session binding refused all 24 of them, a 17% false-positive rate, because it treats
every second data subject as contamination. It cannot tell a ward round from an attack:
THE TRAFFIC IS IDENTICAL, and the difference lives outside it.

THE FIX. Binding 3 honours the declaration. A session covering A and B accepts both and
still refuses C; a session that declares nothing falls back to first-subject binding, so
`subject_mismatch` is caught exactly as before.

THE COST, MEASURED NOT ASSERTED. `session_scope` is sender-supplied, which
THREAT_MODEL.md §2.3 already calls attacker-controllable. `forged_session_scope` is the
contamination attack with a scope the attacker wrote themselves, and it walks through.
Both numbers belong in §6: the fix removed 24 false positives and admitted 24 misses,
and the real remedy is binding the field at the adapter, not in this agent.
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


def test_haris_now_allows_it(ward_rounds):
    """The fix. Before binding 3 this was 24/24 blocked — a 17% false-positive rate."""
    for scn in ward_rounds:
        assert not haris(scn).stopped, f"{scn.id}: legitimate ward round refused"


def test_a_session_scope_does_not_admit_a_third_subject():
    """Honouring a declaration must not become 'allow any subject'. A scope naming two
    patients still refuses a third."""
    from haris.agents.subject_binding import SubjectBindingAgent
    from haris.schemas.message import Message
    from haris.schemas.verdict import Label

    agent = SubjectBindingAgent(known_subjects=("patient-A", "patient-B", "patient-C"))
    md = {"data_subject": "patient-C", "session_scope": "patient-A,patient-B",
          "auth_token": "t"}
    m = Message(session_id="s", sender="a", receiver="b",
                content="unremarkable note", metadata=md)
    assert agent.check(m, {"history": []}).label is Label.BLOCK


def test_an_empty_declaration_is_not_a_declaration():
    """A blank field must not refuse every subject including the session's own — nobody
    means that by leaving a value empty."""
    from haris.agents.subject_binding import SubjectBindingAgent
    from haris.schemas.message import Message
    from haris.schemas.verdict import Label

    agent = SubjectBindingAgent(known_subjects=("patient-A",))
    m = Message(session_id="s", sender="a", receiver="b", content="note",
                metadata={"data_subject": "patient-A", "session_scope": "  ",
                          "auth_token": "t"})
    assert agent.check(m, {"history": []}).label is Label.PASS


def test_the_attack_without_a_declaration_is_still_caught(contamination):
    """The fallback. subject_mismatch declares no scope, so binding 1 still applies and
    the 100% on that family survives the fix."""
    for scn in contamination:
        assert haris(scn).stopped, scn.id


def test_a_forged_declaration_walks_through(scenarios):
    """THE COST, pinned. session_scope is sender-supplied metadata; an attacker who
    writes their own scope defeats binding 3 completely. Measured here rather than
    footnoted, because the fix belongs at the adapter and is not in this agent's power.
    """
    forged = [s for s in scenarios if s.family == "forged_session_scope"]
    assert len(forged) == 24
    for scn in forged:
        assert scn.is_attack
        assert not haris(scn).stopped, (
            f"{scn.id}: if this starts passing, the trade-off changed — re-measure")


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


def test_the_metadata_heuristic_still_makes_the_mistake(ward_rounds):
    """Worth reporting alongside: the cheap baseline shares the ORIGINAL failure, because
    it counts subjects and ignores the declaration. Haris no longer does — so the ward
    round is a benign family where Haris is right and the heuristic is wrong, the mirror
    image of subject_forgery."""
    for scn in ward_rounds:
        assert metadata_heuristic(scn).stopped, scn.id


def test_the_content_scanner_gets_it_right_for_the_wrong_reason(ward_rounds):
    """It allows the ward round — because it only inspects egress and there is none. A
    correct answer with no reasoning behind it, which is why per-family columns matter
    more than the headline."""
    for scn in ward_rounds:
        assert not content_scanner(scn).stopped, scn.id