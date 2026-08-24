"""Seed sensitivity — the corpus is reproducible, and the structural results do not
depend on which names Faker drew.

Two claims the report makes, pinned here:

  1. The default seed is fixed, so every committed number reproduces exactly.
  2. Changing the seed changes the CONTENT and not the STRUCTURE — same families, same
     counts, same ladder rungs, different strings. That is what makes the sweep in
     seed_sweep.py a test of string sensitivity specifically, and it is also the reason
     the sweep must not be described as evidence of generalisation.
"""
from __future__ import annotations

from collections import Counter

from demo_app.eval.generate import SEED, generate


def test_the_default_seed_is_fixed():
    assert [s.id for s in generate()] == [s.id for s in generate(seed=SEED)]


def test_a_different_seed_redraws_the_content():
    a, b = generate(), generate(seed=SEED + 1)
    names_a = {s.secret.name for s in a}
    names_b = {s.secret.name for s in b}
    assert names_a != names_b, "a new seed should draw new names"

    ids_a = {s.secret.record_id for s in a}
    ids_b = {s.secret.record_id for s in b}
    assert ids_a != ids_b


def test_a_different_seed_preserves_the_structure():
    """The families, their sizes and the ladder rungs are positional, not drawn — so a
    sweep varies the strings and holds everything else fixed. If this ever fails, the
    sweep is comparing different corpora and its spread means nothing."""
    a, b = generate(), generate(seed=SEED + 1)
    assert len(a) == len(b)
    assert Counter(s.family for s in a) == Counter(s.family for s in b)
    assert Counter(s.rung for s in a if s.rung) == Counter(s.rung for s in b if s.rung)
    assert [s.id for s in a] == [s.id for s in b]
    assert (sum(s.is_attack for s in a)) == (sum(s.is_attack for s in b))


def test_every_seed_keeps_facts_inside_their_domain():
    """Task I1 must hold under any seed, not just the committed one."""
    from demo_app.eval.domains import DOMAINS
    for seed in (SEED, SEED + 1, SEED + 2):
        for scn in generate(seed=seed):
            assert scn.secret.fact in DOMAINS[scn.domain].facts, (seed, scn.id)
