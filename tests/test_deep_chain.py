"""Task K2 — how far does lineage reach, and what does it cost?

The record is read at hop 1. Every hop in between carries ordinary coordination prose
with no identifier in it. The identifier reappears only at the final hop, on its way
outside. Nothing in the intermediate traffic connects the two ends, so catching it
requires remembering hop 1 while standing at hop 8.

WHAT THIS FAMILY IS NOT. It does not differentiate Haris from the baselines, and it was
not built to. The final hop is externally addressed and carries the identifier in the
clear, so the metadata heuristic blocks it on the recipient alone and the content scanner
blocks it on the string. The plan expected the scanner to collapse on a long chain; it
does not, because depth is a property of the content and a rule that never reads content
is indifferent to how many times it was rewritten. That prediction was wrong and the
corpus now says so.

WHAT IT IS FOR. Two things nothing else in the corpus tested. Whether taint survives a
chain of hops that carry nothing identifying — the claim the demo makes as "catches a leak
nine steps later", which the corpus could not support while nothing exceeded three hops.
And what remembering costs: the orchestrator replays session history on every hop, so a
deeper chain does strictly more work, and the growth had never been measured.
"""
from __future__ import annotations

import pytest

from demo_app.eval.baselines import content_scanner, haris, metadata_heuristic
from demo_app.eval.generate import CHAIN_DEPTHS, generate
from demo_app.eval.oracle import label_consistency_check


@pytest.fixture(scope="module")
def scenarios():
    return generate()


@pytest.fixture(scope="module")
def chains(scenarios):
    return [s for s in scenarios if s.family == "deep_chain"]


# --------------------------------------------------------------------------- #
# The corpus finally has depth
# --------------------------------------------------------------------------- #

def test_every_depth_is_represented_equally(chains):
    from collections import Counter
    counts = Counter(s.depth for s in chains)
    assert set(counts) == set(CHAIN_DEPTHS)
    assert len(set(counts.values())) == 1, counts


def test_the_hop_count_matches_the_declared_depth(chains):
    for scn in chains:
        assert len(scn.messages) == scn.depth, scn.id


def test_the_corpus_now_reaches_beyond_three_hops(scenarios):
    """The gap this family closes. Everything else tops out at three, so the deck's
    'nine steps later' had nothing behind it."""
    assert max(len(s.messages) for s in scenarios) >= 8


# --------------------------------------------------------------------------- #
# The middle of the chain carries nothing
# --------------------------------------------------------------------------- #

def test_no_identifier_travels_through_the_middle(chains):
    """The property that makes the family a test of MEMORY rather than of matching. If
    an identifier leaked into an intermediate hop, catching the leak would need no
    lineage at all — the last hop alone would give it away."""
    for scn in chains:
        for m in scn.messages[1:-1]:
            for ident in scn.secret.identifiers():
                if ident == scn.secret.subject:
                    continue        # the subject label is metadata, not content
                assert ident not in m.content, (scn.id, ident)


def test_the_identifier_resurfaces_only_at_the_end(chains):
    for scn in chains:
        assert scn.secret.record_id in scn.messages[-1].content, scn.id
        assert scn.messages[-1].metadata.get("recipient"), scn.id


def test_it_is_labelled_an_attack_from_traffic(chains):
    for scn in chains:
        should_stop, method = label_consistency_check(scn)
        assert should_stop, scn.id
        assert method.startswith("traffic"), (scn.id, method)


# --------------------------------------------------------------------------- #
# The result
# --------------------------------------------------------------------------- #

def test_lineage_survives_every_depth(chains):
    """THE CLAIM. Read at hop 1, caught at hop 8, with nothing identifying in between."""
    for scn in chains:
        assert haris(scn).stopped, f"{scn.id}: lineage lost the source at depth {scn.depth}"


def test_the_deepest_chain_is_caught(chains):
    deepest = [s for s in chains if s.depth == max(CHAIN_DEPTHS)]
    assert deepest
    for scn in deepest:
        assert haris(scn).stopped, scn.id


def test_the_baselines_catch_it_too_and_that_is_the_point(chains):
    """Recorded rather than hidden: depth is not a differentiator. Both baselines stop
    this family — the heuristic on the external recipient, the scanner on the identifier
    in the final message. A report claiming long chains defeat a regex scanner would be
    contradicted by its own corpus, and this test is why we will not claim it."""
    for scn in chains:
        assert metadata_heuristic(scn).stopped, scn.id
        assert content_scanner(scn).stopped, scn.id
