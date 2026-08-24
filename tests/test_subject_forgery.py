"""Task K1 — subject forgery, the family no baseline can see.

The attack: a session opens legitimately on subject A, then a second hop delivers subject
B's record into it WITHOUT changing the label. Recipient authorised, token valid, one
declared subject. Every metadata check in the system agrees; only the payload disagrees.

These tests pin two separate claims, and both matter for the report:

  1. The MECHANISM works — SubjectBindingAgent's content binding blocks a message whose
     record contradicts its own label, and does not fire on anything else.
  2. The COMPARISON is real — the metadata heuristic and the content scanner both allow
     this family, and Haris does not. That is the differentiating row in the four-arm
     table, and if it ever stops holding, the table's headline claim is no longer true.
"""
from __future__ import annotations

import pytest

from haris.agents.subject_binding import SubjectBindingAgent
from haris.schemas.message import Message
from haris.schemas.verdict import Label

from demo_app.eval.baselines import content_scanner, haris, metadata_heuristic
from demo_app.eval.generate import generate
from demo_app.eval.oracle import label_consistency_check


@pytest.fixture(scope="module")
def scenarios():
    return generate()


@pytest.fixture(scope="module")
def forgeries(scenarios):
    return [s for s in scenarios if s.family == "subject_forgery"]


def _msg(content, subject):
    return Message(session_id="s", sender="a", receiver="b", content=content,
                   metadata={"data_subject": subject, "auth_token": "t"})


# --------------------------------------------------------------------------- #
# 1. The mechanism
# --------------------------------------------------------------------------- #

def test_content_binding_blocks_a_contradicting_record():
    agent = SubjectBindingAgent(known_subjects=("patient-A", "patient-B"))
    v = agent.check(_msg("[patient-B]\nName: Nina Novak", "patient-A"), {"history": []})
    assert v.label is Label.BLOCK
    assert "forgery" in v.reason


def test_content_binding_allows_a_matching_record():
    agent = SubjectBindingAgent(known_subjects=("patient-A", "patient-B"))
    v = agent.check(_msg("[patient-A]\nName: Nina Novak", "patient-A"), {"history": []})
    assert v.label is Label.PASS


def test_unconfigured_agent_does_not_content_bind():
    """Backwards compatibility: with no known_subjects the agent behaves exactly as it
    did before content binding existed. The shipped hospital pipeline relies on this
    until it passes its own subject list."""
    agent = SubjectBindingAgent()
    v = agent.check(_msg("[patient-B]\nName: Nina Novak", "patient-A"), {"history": []})
    assert v.label is Label.PASS


def test_bracketed_prose_is_not_a_subject_claim():
    """`[REDACTED]` and friends must never be read as a subject — otherwise redacted
    content would block on its own redaction marker."""
    agent = SubjectBindingAgent(known_subjects=("patient-A", "patient-B"))
    v = agent.check(_msg("Visit summary for [REDACTED]: [REDACTED]", "patient-A"),
                    {"history": []})
    assert v.label is Label.PASS


def test_session_binding_still_works():
    agent = SubjectBindingAgent(known_subjects=("patient-A", "patient-B"))
    history = [_msg("[patient-A]\nName: X", "patient-A")]
    v = agent.check(_msg("nothing bracketed here", "patient-B"), {"history": history})
    assert v.label is Label.BLOCK
    assert "cross-subject" in v.reason


# --------------------------------------------------------------------------- #
# 2. The corpus and the labels
# --------------------------------------------------------------------------- #

def test_the_family_exists_across_every_domain_and_topology(forgeries):
    assert len(forgeries) == 24
    assert len({s.domain for s in forgeries}) == 4
    assert len({s.topology for s in forgeries}) == 3


def test_metadata_is_entirely_well_formed(forgeries):
    """The premise of K1: nothing in the metadata is wrong. If this fails, the family has
    become catchable by metadata alone and no longer demonstrates anything."""
    for scn in forgeries:
        subjects = {m.metadata.get("data_subject") for m in scn.messages}
        assert len(subjects) == 1, scn.id
        assert all(m.metadata.get("auth_token") for m in scn.messages), scn.id
        for m in scn.messages:
            recipient = m.metadata.get("recipient")
            if recipient:
                assert recipient in scn.authorized_recipients, scn.id


def test_labelled_as_an_attack_from_traffic(forgeries):
    for scn in forgeries:
        should_stop, method = label_consistency_check(scn)
        assert should_stop, scn.id
        assert method == "traffic:subject-forgery", (scn.id, method)


# --------------------------------------------------------------------------- #
# 3. The comparison — the claim the report makes
# --------------------------------------------------------------------------- #

def test_no_baseline_catches_it(forgeries):
    for scn in forgeries:
        assert not metadata_heuristic(scn).stopped, f"{scn.id}: heuristic caught it"
        assert not content_scanner(scn).stopped, f"{scn.id}: scanner caught it"


def test_haris_catches_all_of_it(forgeries):
    for scn in forgeries:
        assert haris(scn).stopped, f"{scn.id}: Haris missed it"
