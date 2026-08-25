"""Task K2 — the multi-hop rewrite chain: where does lineage run out?

The record is read at hop 1 and restated at every hop after, a little less faithfully each
time. By the egress hop no single message holds the source record — only a degraded echo
of it. This is the shape the plan describes and the deck sells, and it was untested.

WHY IT IS NOT THE OBFUSCATION LADDER AGAIN. That ladder transforms one identifier's
ENCODING in a single step: spacing, homoglyph, base64. This one degrades the CONTENT
cumulatively across hops, the way a chain of summarising agents actually loses fidelity.
The two fail for different reasons and are reported in separate tables.

SIX LEVELS, IN TWO GROUPS. The first three change the SHAPE of the message and leave both
identifiers intact — reformatting, reordering the clauses, padding with an unrelated
sentence. Those are the three operations the plan names, and none of them should cost
anything: if a rung drops there, the matcher is order-sensitive or dilution-sensitive,
which is a defect rather than a difficulty. The last three degrade the IDENTIFIERS, on
staggered schedules.

WHAT IT MEASURES THAT NOTHING ELSE CAN. Because the identifiers degrade at different
levels — the record id loses its prefix while the name is still whole, and only at the end
does the name reduce to an initial — the level where prevention falls NAMES the identifier
the matcher was relying on. Nothing else in the corpus can separate "we caught it by the
record id" from "we caught it by the name".

THE CHAIN IS ALWAYS FIVE HOPS, at every level. Otherwise an early level would be a short
chain and the ladder would confound degradation with depth; `deep_chain` is the family
that varies depth, and the two axes are kept apart on purpose.
"""
from __future__ import annotations

from collections import Counter

import pytest

from demo_app.eval.baselines import content_scanner, haris, metadata_heuristic
from demo_app.eval.generate import REWRITE_LEVELS, generate
from demo_app.eval.oracle import label_consistency_check


@pytest.fixture(scope="module")
def scenarios():
    return generate()


@pytest.fixture(scope="module")
def chains(scenarios):
    return [s for s in scenarios if s.family == "rewrite_chain"]


# --------------------------------------------------------------------------- #
# The chain is really a chain
# --------------------------------------------------------------------------- #

def test_every_level_is_represented_equally(chains):
    counts = Counter(s.rewrite for s in chains)
    assert set(counts) == set(REWRITE_LEVELS)
    assert len(set(counts.values())) == 1, counts


def test_no_message_after_the_source_holds_the_record(chains):
    """The plan's actual requirement: the source record must not survive intact past hop
    one. If it did, this would be `external_verbatim` with extra steps."""
    for scn in chains:
        for m in scn.messages[1:]:
            assert scn.secret.raw not in m.content, scn.id
            assert "Detail:" not in m.content, scn.id


def test_every_chain_is_five_hops(chains):
    """The plan's shape: read at hop 1, rewritten at hops 2-4, egress at hop 5. Holding
    the depth fixed is what keeps this ladder measuring degradation rather than depth —
    `deep_chain` is the family that varies depth."""
    for scn in chains:
        assert len(scn.messages) == 5, (scn.id, scn.rewrite, len(scn.messages))


def test_shape_changes_keep_both_identifiers(chains):
    """Levels 1-4 reformat, reorder and pad without losing anything, so both identifiers
    are still present in the egress message. If one of these levels is ever missed, the
    matcher has become sensitive to word order or to surrounding volume — report that as
    a defect, not as a difficulty rung."""
    for scn in chains:
        if scn.rewrite not in ("1_restated", "2_reformatted", "3_reordered", "4_padded"):
            continue
        assert scn.secret.name in scn.messages[-1].content, (scn.id, scn.rewrite)


def test_identifier_degradation_is_staggered(chains):
    """Level 5 has degraded the record id and kept the name; level 6 degrades the name
    too. That stagger is what lets the curve name the identifier detection rested on."""
    for scn in chains:
        text = scn.messages[-1].content
        if scn.rewrite == "5_prefix_dropped":
            assert scn.secret.record_id not in text, scn.id
            assert scn.secret.name in text, scn.id
        if scn.rewrite == "6_initials":
            assert scn.secret.record_id not in text, scn.id
            assert scn.secret.name not in text, scn.id


def test_it_is_labelled_an_attack_from_traffic(chains):
    for scn in chains:
        should_stop, method = label_consistency_check(scn)
        assert should_stop, (scn.id, scn.rewrite)
        assert method.startswith("traffic"), (scn.id, method)


def test_every_level_counts_as_a_leak(chains):
    """The correction the obfuscation ladder also needed: a level Haris misses has to
    stay in the denominator, or the miss vanishes from the results instead of counting
    against us."""
    from demo_app.eval.domains import DOMAINS
    from demo_app.eval.leak_check import leaked
    for scn in chains:
        dom = DOMAINS[scn.domain]
        assert leaked(list(scn.messages), scn.all_identifiers(),
                      scn.authorized_recipients, dom.internal_at), (scn.id, scn.rewrite)


# --------------------------------------------------------------------------- #
# The curve — measured, not predicted
# --------------------------------------------------------------------------- #

def _rate(chains, level):
    rows = [s for s in chains if s.rewrite == level]
    return sum(1 for s in rows if haris(s).stopped) / len(rows)


def test_shape_changes_cost_nothing(chains):
    """Reformatting, reordering and padding leave both identifiers in place, so all four
    should be caught. This is the half of the ladder that SHOULD be flat — a drop here
    would mean the matcher depends on word order or is diluted by volume, which is a bug
    to fix rather than a rung to report.
    """
    for level in ("1_restated", "2_reformatted", "3_reordered", "4_padded"):
        assert _rate(chains, level) == 1.0, level


def test_the_chain_is_a_gradient_not_a_cliff_at_zero(chains):
    """Some levels caught, some not. A family that is entirely caught or entirely missed
    measures nothing about degradation — it would just be a harder or easier version of
    external_derived."""
    outcomes = {level: _rate(chains, level) for level in REWRITE_LEVELS}
    assert 0.0 in outcomes.values(), outcomes
    assert 1.0 in outcomes.values(), outcomes


def test_the_name_outlasts_the_record_id(chains):
    """THE FINDING this family exists to produce. `5_prefix_dropped` has degraded the
    record id to bare digits while the full name is still present; `6_initials` degrades
    the name too. If the third level is caught and the fourth is not, the matcher was
    surviving on the NAME, not on the identifier the design talks about.

    Recorded as a test so that a matcher change which inverts it is noticed rather than
    silently changing what §6 claims.
    """
    assert _rate(chains, "5_prefix_dropped") > _rate(chains, "6_initials"), (
        "the name no longer outlasts the record id — re-read the rewrite table before "
        "quoting §6 on which identifier carries detection")