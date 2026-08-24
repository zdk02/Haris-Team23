"""The subject-scoped leak rule (2026-08-24).

The rule was added because the recipient rule cannot express "internal recipient, wrong
data subject" — an authorised recipient can never register as a leak, so that threat class
was unscoreable rather than merely hard.

The load-bearing test here is `test_subject_rule_changes_no_existing_verdict`. Extending a
metric after seeing an unflattering result is a real methodological hazard, and the defence
is evidence: the new rule fires on NO family that existed before it was written. If that
test ever fails, the metric has started changing old numbers and the §6 paragraph
describing it is no longer true.
"""
from __future__ import annotations

import pytest

from demo_app.eval.domains import DOMAINS
from demo_app.eval.generate import generate
from demo_app.eval.leak_check import (
    exclusive_identifiers, leaked, subject_confused,
)


@pytest.fixture(scope="module")
def scenarios():
    return generate()


def _by_family(scenarios, family):
    return next(s for s in scenarios if s.family == family)


# --------------------------------------------------------------------------- #
# exclusive_identifiers
# --------------------------------------------------------------------------- #

def test_shared_identifiers_are_dropped():
    """Two subjects in a domain can legitimately share a detail — counting it would
    manufacture leaks out of coincidence."""
    excl = exclusive_identifiers({
        "patient-A": ["Robert Roberts", "MRN-4821", "type 2 diabetes"],
        "patient-B": ["Nina Novak", "MRN-1130", "type 2 diabetes"],
    })
    assert "type 2 diabetes" not in excl["patient-A"]
    assert "type 2 diabetes" not in excl["patient-B"]
    assert "MRN-4821" in excl["patient-A"]
    assert "Nina Novak" in excl["patient-B"]


def test_short_identifiers_are_dropped():
    excl = exclusive_identifiers({"a": ["ok", "MRN-4821"]})
    assert excl["a"] == ["MRN-4821"]


# --------------------------------------------------------------------------- #
# subject_confused
# --------------------------------------------------------------------------- #

def test_fires_when_another_subjects_record_appears(scenarios):
    """The K1 shape: an internal, authorised, correctly tokened message about patient A
    that carries patient B's record id."""
    scn = _by_family(scenarios, "internal_clean")
    ids = {"patient-A": ["MRN-1111"], "patient-B": ["MRN-2222"]}
    m = scn.messages[-1].model_copy(update={
        "content": "Following up on MRN-2222 as discussed.",
        "metadata": {**(scn.messages[-1].metadata or {}), "data_subject": "patient-A"},
    })
    assert subject_confused([m], ids)


def test_silent_when_the_subject_matches(scenarios):
    scn = _by_family(scenarios, "internal_clean")
    ids = {"patient-A": ["MRN-1111"], "patient-B": ["MRN-2222"]}
    m = scn.messages[-1].model_copy(update={
        "content": "Following up on MRN-1111 as discussed.",
        "metadata": {**(scn.messages[-1].metadata or {}), "data_subject": "patient-A"},
    })
    assert not subject_confused([m], ids)


def test_silent_when_no_subject_is_declared(scenarios):
    scn = _by_family(scenarios, "internal_clean")
    ids = {"patient-A": ["MRN-1111"], "patient-B": ["MRN-2222"]}
    m = scn.messages[-1].model_copy(update={
        "content": "Following up on MRN-2222 as discussed.",
        "metadata": {"recipient": "doctor@hospital.internal"},
    })
    assert not subject_confused([m], ids)


# --------------------------------------------------------------------------- #
# The null result — the reason this change is defensible
# --------------------------------------------------------------------------- #

def test_subject_rule_changes_no_existing_verdict(scenarios):
    """Every scenario that existed before the rule must score identically with and
    without it. The subject rule covers a NEW threat; it does not restate an old one."""
    for scn in scenarios:
        dom = DOMAINS[scn.domain]
        args = (scn.secret.identifiers(), scn.authorized_recipients, dom.internal_at)
        before = leaked(list(scn.messages), *args)
        after = leaked(list(scn.messages), *args,
                       subject_identifiers=scn.subject_identifiers())
        assert before == after, (scn.id, scn.family)


def test_subject_mismatch_tracks_both_subjects(scenarios):
    """The family that builds a second secret must actually retain it — before this
    change s2 was constructed and discarded."""
    scn = _by_family(scenarios, "subject_mismatch")
    assert len(scn.subject_identifiers()) == 2


def test_single_subject_families_track_one(scenarios):
    for family in ("internal_clean", "external_verbatim", "same_subject"):
        scn = _by_family(scenarios, family)
        assert len(scn.subject_identifiers()) == 1, family
