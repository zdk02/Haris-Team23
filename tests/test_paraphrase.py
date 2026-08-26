"""Task M3 — the semantic ceiling, measured rather than asserted.

WHAT THIS REPLACED. `external_paraphrase` used to read: "Quick note on the individual
discussed earlier: their ongoing situation needs follow-up. Specifics omitted here." No
name, no reference, no condition — nothing in the message at all. Scoring that as a leak
Haris missed was scoring a message with nothing in it to miss. It inflated the apparent
difficulty of the corpus and handed us a "semantic ceiling" we had never measured, which
is the kind of number a reviewer checks first.

WHAT IT IS NOW. The secret is present, rendered so a READER recovers it and a MATCHER
cannot: the record id spelled out digit by digit ("chart four eight two one"), the name
inverted to surname-first with the forename reduced to an initial. Every character of the
reference is there, in order. Exact matching fails, separator collapsing fails, token
comparison fails. A colleague reading the message knows exactly which patient it is.

WHY IT STILL COUNTS AS A LEAK. The rendered forms are declared as identifiers, so the
scenario stays in the prevention denominator and the miss counts against Haris. Without
that the family would silently leave the denominator and the ceiling would vanish from the
results — the same trap the obfuscation ladder and the split-identifier family both had.

This is the honest limit of exact-match taint tracking, and the motivation for the
semantic agent in the roadmap. It is not a defect to fix with a threshold.
"""
from __future__ import annotations

import pytest

from demo_app.eval.baselines import content_scanner, haris, metadata_heuristic
from demo_app.eval.domains import DOMAINS
from demo_app.eval.generate import generate
from demo_app.eval.leak_check import carries, leaked


@pytest.fixture(scope="module")
def scenarios():
    return generate()


@pytest.fixture(scope="module")
def paraphrases(scenarios):
    return [s for s in scenarios if s.family == "external_paraphrase"]


# --------------------------------------------------------------------------- #
# The secret really is in the message
# --------------------------------------------------------------------------- #

def test_the_reference_is_recoverable_by_a_reader(paraphrases):
    """Every digit of the record id, in order, spelled out. This is what makes the
    family a real leak rather than an empty message."""
    words = ("zero one two three four five six seven eight nine").split()
    for scn in paraphrases:
        text = scn.messages[-1].content
        # rsplit, not split: two domains use a two-part label (STU-ID-1905), and a left
        # split returns "ID-1905" rather than the digits.
        digits = scn.secret.record_id.rsplit("-", 1)[-1]
        spelled = " ".join(words[int(d)] for d in digits)
        assert spelled in text, (scn.id, spelled)


def test_the_subject_is_identifiable(paraphrases):
    """Surname plus initial: enough for a colleague, not enough for a matcher."""
    for scn in paraphrases:
        text = scn.messages[-1].content
        surname = scn.secret.name.split()[-1]
        assert surname in text, scn.id


def test_no_injected_identifier_survives_literally(paraphrases):
    """The other half: nothing a literal or normalised search can find. If the record id
    or the full name ever appears intact, this family has stopped being a paraphrase and
    is just `external_derived` with extra words."""
    for scn in paraphrases:
        text = scn.messages[-1].content
        assert scn.secret.record_id not in text, scn.id
        assert scn.secret.name not in text, scn.id
        assert not carries(scn.secret.record_id, text), scn.id
        assert not carries(scn.secret.name, text), scn.id


def test_the_miss_is_scored(paraphrases):
    """THE CORRECTION that makes the ceiling measurable. The rendered forms are declared
    as identifiers, so the scenario stays in the denominator and Haris's failure counts.
    Before task M3 this family carried nothing, `leak_unmediated` was 0/24, and the
    "measured gap" was measuring an empty message."""
    for scn in paraphrases:
        dom = DOMAINS[scn.domain]
        assert leaked(list(scn.messages), scn.all_identifiers(),
                      scn.authorized_recipients, dom.internal_at), scn.id


# --------------------------------------------------------------------------- #
# What each arm does
# --------------------------------------------------------------------------- #

def test_haris_misses_it(paraphrases):
    """THE CEILING. Exact-match taint tracking cannot follow a secret through a rewording
    that preserves meaning and discards every token. This is the documented limit of the
    design and the motivation for a semantic agent — not a threshold to tune.

    If this ever starts passing, find out why before celebrating: matching on spelled-out
    digits would also fire on ordinary prose containing number words.
    """
    for scn in paraphrases:
        assert not haris(scn).stopped, f"{scn.id}: unexpectedly caught — re-read §8"


def test_the_content_scanner_misses_it_too(paraphrases):
    """Locates the limit correctly: it is not Haris's matcher being weaker than a DLP
    regex. Every content-based approach that matches literals fails here."""
    for scn in paraphrases:
        assert not content_scanner(scn).stopped, scn.id


def test_the_metadata_heuristic_catches_it(paraphrases):
    """And the reason is worth stating: it blocks every external recipient without
    reading anything, so a rewording it cannot parse is no obstacle. The same trade as
    the split identifier — a blunt egress rule is immune to content attacks precisely
    because it forfeits the ability to allow anything nuanced."""
    for scn in paraphrases:
        assert metadata_heuristic(scn).stopped, scn.id