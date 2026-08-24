"""Task M2 — the obfuscation ladder is a real difficulty axis, not one transform.

Before this, `_obfuscate` was `s.replace("-", " - ")` and the report's "100% obfuscation
resistance" rested on that single line. These tests pin the three properties that make the
replacement worth reporting:

  1. the rungs are ORDERED — layout changes first, encodings after, and the distinction is
     mechanical (collapsing separators recovers a layout change and cannot recover an
     encoding), not a matter of taste;
  2. the counts are EQUAL and seed-independent, because rungs are assigned by position;
  3. the hard rungs are SCORED — a base64'd identifier is still counted as a leak, so a
     rung Haris misses counts against it instead of dropping out of the denominator.

Property 3 is the one that would fail silently. Without it the ladder would look flattering
for exactly the wrong reason.
"""
from __future__ import annotations

from collections import Counter

import pytest

from demo_app.eval.domains import DOMAINS
from demo_app.eval.generate import (
    OBFUSCATION_LADDER, _rung_base64, _rung_digit_spacing, _rung_homoglyph,
    _rung_html_entity, _rung_reordered, _rung_spacing, generate,
)
from demo_app.eval.leak_check import carries, leaked
from demo_app.eval.oracle import label_consistency_check

MRN = "MRN-4821"


@pytest.fixture(scope="module")
def scenarios():
    return generate()


@pytest.fixture(scope="module")
def ladder(scenarios):
    return [s for s in scenarios if s.family == "external_obfuscated"]


# --------------------------------------------------------------------------- #
# 1. The transforms do what they say
# --------------------------------------------------------------------------- #

def test_each_transform_changes_the_identifier():
    for name, fn in OBFUSCATION_LADDER:
        assert fn(MRN) != MRN, name


def test_layout_rungs_preserve_the_characters():
    """Rungs 1-2 only move separators, so stripping non-alphanumerics recovers the
    original exactly. That is why a collapse matcher catches them."""
    import re
    collapse = lambda s: re.sub(r"[^a-z0-9]", "", s.lower())
    for fn in (_rung_spacing, _rung_digit_spacing):
        assert collapse(fn(MRN)) == collapse(MRN)


def test_reordering_is_not_recoverable_by_collapsing():
    """Rung 3 is the first that a collapse match cannot undo: collapsing preserves
    order, and this rung changes it."""
    import re
    collapse = lambda s: re.sub(r"[^a-z0-9]", "", s.lower())
    assert collapse(_rung_reordered(MRN)) != collapse(MRN)


def test_encoding_rungs_replace_the_characters():
    """Rungs 4-6 change the bytes themselves. No separator handling recovers them."""
    for fn in (_rung_homoglyph, _rung_html_entity, _rung_base64):
        assert not carries(MRN, fn(MRN)), fn.__name__


def test_homoglyph_renders_as_the_original():
    """BR-2's point: this is worse than a silent miss. The string a human sees is the
    real identifier, so a reviewer looking at the flagged message waves it through."""
    out = _rung_homoglyph(MRN)
    assert out != MRN
    assert len(out) == len(MRN)          # visually identical, byte-wise different
    assert any(ord(c) > 127 for c in out)


def test_base64_is_recoverable_by_the_receiver():
    import base64
    assert base64.b64decode(_rung_base64(MRN)).decode() == MRN


# --------------------------------------------------------------------------- #
# 2. Equal counts, assigned by position
# --------------------------------------------------------------------------- #

def test_every_rung_is_represented_equally(ladder):
    counts = Counter(s.rung for s in ladder)
    assert set(counts) == {name for name, _ in OBFUSCATION_LADDER}
    assert len(set(counts.values())) == 1, counts


def test_rungs_are_stable_across_runs():
    """Assigned by position, never drawn from the RNG — so the curve is reproducible
    under any seed, which the deleted `fake.boolean()` coin flip was not (task M1)."""
    a = {s.id: s.rung for s in generate() if s.rung}
    b = {s.id: s.rung for s in generate() if s.rung}
    assert a == b and a


def test_no_coin_flip_remains():
    """Task M1: rung selection must come from POSITION, never from the RNG.

    Matched as an assignment rather than a bare substring — the module docstring
    explains what was deleted and why, and a plain substring search hits that prose.
    """
    import inspect
    import re

    from demo_app.eval import generate as gen

    assert not re.search(r"=\s*fake\.boolean\(", inspect.getsource(gen)), \
        "task M1: the coin flip is back"


# --------------------------------------------------------------------------- #
# 3. Hard rungs are scored, not dropped
# --------------------------------------------------------------------------- #

def test_the_transformed_form_is_declared_as_an_identifier(ladder):
    for scn in ladder:
        assert scn.extra_identifiers, scn.id
        blob = "\n".join(m.content for m in scn.messages)
        assert scn.extra_identifiers[0] in blob, scn.id


def test_every_rung_counts_as_a_leak_unmediated(ladder):
    """The load-bearing one. If a hard rung stops registering as a leak it leaves the
    prevention denominator, and Haris's miss disappears from the results instead of
    counting against it."""
    for scn in ladder:
        dom = DOMAINS[scn.domain]
        assert leaked(list(scn.messages), scn.all_identifiers(),
                      scn.authorized_recipients, dom.internal_at), (scn.id, scn.rung)


def test_every_rung_is_labelled_an_attack_from_traffic(ladder):
    for scn in ladder:
        should_stop, method = label_consistency_check(scn)
        assert should_stop, (scn.id, scn.rung, method)


def test_the_message_carries_only_the_transformed_identifier(ladder):
    """No name, no second identifier — otherwise the rung is masked by something easier
    to catch and the curve measures nothing."""
    for scn in ladder:
        egress = scn.messages[-1].content
        assert scn.secret.name not in egress, scn.id
        assert scn.secret.record_id not in egress or scn.rung == "1_spacing", scn.id