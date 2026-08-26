"""Task N2 — does detection depend on the wording, or on the identifiers?

THE CRITICISM. The corpus was built from about eight authored templates, so every scenario
of a given style carried the same sentence. A detection rate measured that way is partly a
property of our prose: if the matcher were sensitive to the words around an identifier, the
corpus could not tell us.

THE ANSWER. Four phrasings per leak style, rotated by position. They differ in tone,
structure and length — a curt reference, a chase-up, a formal note, a casual aside. What
they hold constant is exactly what the threat consists of: which identifiers appear.

If the rates are identical across all four, detection rests on the identifiers rather than
on the sentence. That is the "survives the summarizer rewriting everything" claim turned
into something falsifiable, and it is the more interesting result — a system whose numbers
moved with phrasing would be reporting an accident.

SCOPE, STATED. N2 also asks for the source RECORD to be rewritten in 3-5 formats across the
whole corpus. That axis is measured in the `record_format` family instead (task N1), where
the finding is stark: narrative and chat records defeat the structured fallback entirely.
Rotating formats corpus-wide would degrade only Haris — the baselines judge the egress
message, which is unchanged — and would also break `subject_forgery`, whose content binding
reads a bracketed subject that a narrative record does not have. That is a real limitation
and belongs in §8; discovering it by moving every number in the report five days before
submission is the wrong way to learn it.
"""
from __future__ import annotations

from collections import defaultdict

import pytest

from demo_app.eval.baselines import haris
from demo_app.eval.generate import _content, generate


@pytest.fixture(scope="module")
def scenarios():
    return generate()


# --------------------------------------------------------------------------- #
# The phrasings are genuinely different
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("style", ["verbatim", "derived", "credential", "clean"])
def test_each_style_has_four_distinct_phrasings(style, scenarios):
    secret = scenarios[0].secret
    texts = {_content(style, secret, v) for v in range(4)}
    assert len(texts) == 4, f"{style}: phrasings collapsed to {len(texts)}"


def test_the_phrasings_differ_by_more_than_a_word(scenarios):
    """A rotation that only changes punctuation tests nothing. Require the sentences to
    differ in length and in opening words, so the variation is real."""
    secret = scenarios[0].secret
    for style in ("derived", "credential", "clean"):
        texts = [_content(style, secret, v) for v in range(4)]
        openings = {t.split()[0].lower() for t in texts}
        assert len(openings) >= 3, (style, openings)
        if style != "clean":
            assert max(len(t) for t in texts) > min(len(t) for t in texts) * 1.2, style


def test_every_phrasing_keeps_the_identifiers(scenarios):
    """The control. Varying the prose must not vary WHAT LEAKS, or a difference in
    detection would tell us nothing about phrasing."""
    secret = scenarios[0].secret
    for v in range(4):
        derived = _content("derived", secret, v)
        assert secret.record_id in derived, v
        assert secret.name in derived, v
        cred = _content("credential", secret, v)
        assert secret.credential in cred, v
        clean = _content("clean", secret, v)
        assert secret.record_id not in clean and secret.name not in clean, v


def test_the_corpus_actually_uses_all_four(scenarios):
    """Rotated by position, so every phrasing should appear many times. If one never
    does, the rotation is broken and three quarters of the variation is imaginary."""
    seen = defaultdict(set)
    for scn in scenarios:
        if scn.family != "external_derived":
            continue
        seen["derived"].add(scn.messages[-1].content.split()[0].lower())
    assert len(seen["derived"]) >= 3, seen["derived"]


# --------------------------------------------------------------------------- #
# And detection does not care
# --------------------------------------------------------------------------- #

def test_detection_is_identical_across_phrasings(scenarios):
    """THE RESULT. Same identifiers, four different sentences, one answer.

    This is the claim the project makes about surviving a summarizer, and until now it
    was asserted rather than measured — every scenario of a style carried the same words,
    so the corpus could not have detected sensitivity to them.

    If this ever fails, the matcher has become sensitive to context and the reported rates
    are partly a property of our prose. That would be worth knowing immediately.
    """
    rows = [s for s in scenarios if s.family == "external_derived"]
    by_opening = defaultdict(list)
    for scn in rows:
        by_opening[scn.messages[-1].content.split()[0].lower()].append(scn)

    rates = {k: sum(1 for s in v if haris(s).stopped) / len(v)
             for k, v in by_opening.items()}
    assert len(rates) >= 3, rates
    assert len(set(rates.values())) == 1, (
        f"detection varies with phrasing: {rates} — the reported rate is partly a "
        "property of the sentences we wrote, not of the system")


def test_benign_phrasings_are_all_allowed(scenarios):
    """The mirror: four ways of saying nothing must all be allowed. A false positive that
    depended on wording would be the same defect from the other side."""
    rows = [s for s in scenarios if s.family == "internal_clean"]
    for scn in rows:
        assert not haris(scn).stopped, scn.id
