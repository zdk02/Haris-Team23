"""Task I4 — the benign family where lineage is MORE precise, not just more thorough.

`near_miss_benign` was a byte-identical copy of `internal_derived` until 2026-08-25: same
flow, same content style, same recipient. Twenty-four scenarios that tested nothing.

It is now a referral-form template quoted in a message to an outside address — a name and
a record id in exactly the shape of the real thing, belonging to nobody, never read in the
session. Sending it is ordinary: this is how a form gets documented.

WHY THIS FAMILY MATTERS MORE THAN ITS SIZE SUGGESTS.
Before it, every benign family in the corpus was either allowed by all four arms or
refused by Haris alone. Nothing measured the OTHER half of the argument for lineage: that
knowing where data came from lets you refuse less, not only catch more. A stateless
detector has to choose between missing derived leaks and flagging anything that looks like
an identifier. Haris does not, and this is where that shows up as a number.
"""
from __future__ import annotations

import pytest

from demo_app.eval.baselines import content_scanner, haris, metadata_heuristic
from demo_app.eval.domains import DOMAINS
from demo_app.eval.generate import TEMPLATE_NAME, TEMPLATE_SUFFIX, generate
from demo_app.eval.leak_check import leaked
from demo_app.eval.oracle import label_consistency_check


@pytest.fixture(scope="module")
def scenarios():
    return generate()


@pytest.fixture(scope="module")
def templates(scenarios):
    return [s for s in scenarios if s.family == "near_miss_benign"]


# --------------------------------------------------------------------------- #
# The template must be fake, and must stay fake
# --------------------------------------------------------------------------- #

def test_the_template_identifiers_belong_to_nobody(scenarios):
    """The load-bearing property. If a generated record ever drew `-0000`, the template
    would silently become somebody's real identifier and this benign family would turn
    into an undetected leak — with the corpus asserting it was fine."""
    for scn in scenarios:
        assert not scn.secret.record_id.endswith(f"-{TEMPLATE_SUFFIX}"), scn.id
        assert scn.secret.name != TEMPLATE_NAME, scn.id


def test_the_message_quotes_the_template_and_nothing_real(templates):
    for scn in templates:
        text = scn.messages[-1].content
        assert TEMPLATE_NAME in text
        assert f"{DOMAINS[scn.domain].id_label}-{TEMPLATE_SUFFIX}" in text
        assert scn.secret.name not in text, scn.id
        assert scn.secret.record_id not in text, scn.id


def test_it_is_addressed_outside_the_boundary(templates):
    """The difficulty is the destination. Sent internally this would be unremarkable for
    every arm; sent outside, it is indistinguishable from an exfiltration by content."""
    for scn in templates:
        assert scn.messages[-1].metadata["recipient"] == \
            DOMAINS[scn.domain].external_recipient, scn.id


def test_it_is_benign_and_labelled_so(templates):
    assert len(templates) == 24
    for scn in templates:
        assert not scn.is_attack, scn.id
        should_stop, method = label_consistency_check(scn)
        assert not should_stop, (scn.id, method)


def test_nothing_actually_leaks(templates):
    for scn in templates:
        dom = DOMAINS[scn.domain]
        assert not leaked(list(scn.messages), scn.all_identifiers(),
                          scn.authorized_recipients, dom.internal_at), scn.id


# --------------------------------------------------------------------------- #
# The disagreement — the reason the family exists
# --------------------------------------------------------------------------- #

def test_the_content_scanner_wrongly_refuses_it(templates):
    """It sees `MRN-0000` heading outside and cannot know the value was never read. This
    is not a strawman failing: it is the honest limit of judging a message alone."""
    for scn in templates:
        assert content_scanner(scn).stopped, scn.id


def test_the_metadata_heuristic_wrongly_refuses_it(templates):
    """It sees an unauthorised recipient and never looks further."""
    for scn in templates:
        assert metadata_heuristic(scn).stopped, scn.id


def test_haris_allows_it(templates):
    """THE POINT. Nothing from the session's lineage resurfaces, so there is nothing to
    refuse — and Haris can tell, because it knows what was read.

    If this ever starts failing, the taint matcher has begun firing on shape rather than
    on provenance, and the derived-leak result needs re-measuring alongside it.
    """
    for scn in templates:
        assert not haris(scn).stopped, f"{scn.id}: a form template was refused"


def test_this_is_the_only_benign_family_where_the_arms_disagree(scenarios):
    """Stated as a test so it stops being true loudly rather than quietly. If another
    benign family joins, the report's claim about this one being the sole precision
    evidence needs updating."""
    disagreeing = set()
    for scn in scenarios:
        if scn.is_attack:
            continue
        arms = {
            "scanner": content_scanner(scn).stopped,
            "metadata": metadata_heuristic(scn).stopped,
            "haris": haris(scn).stopped,
        }
        if len(set(arms.values())) > 1:
            disagreeing.add(scn.family)
    assert disagreeing == {"near_miss_benign", "internal_handoff",
                           "multi_subject_workflow"}, disagreeing
