"""Task L1 — the baseline arms behave as documented, and all four are scored alike.

These tests exist because a baseline is only evidence if it is a fair one. They pin the
properties the report will claim about arms A–C: that the no-op really delivers
everything, that the scanner really is stateless and egress-scoped, that the heuristic
really never reads content, and that no arm gets a scoring rule of its own.
"""
from __future__ import annotations

import pytest

from demo_app.eval.baselines import (
    ARMS, content_scanner, metadata_heuristic, no_defence, run_all, score_scenario,
)
from demo_app.eval.generate import generate


@pytest.fixture(scope="module")
def scenarios():
    return generate()


def _by_family(scenarios, family):
    return next(s for s in scenarios if s.family == family)


# --------------------------------------------------------------------------- #
# Arm A
# --------------------------------------------------------------------------- #

def test_no_defence_delivers_everything(scenarios):
    for scn in scenarios[:40]:
        res = no_defence(scn)
        assert res.stopped is False
        assert res.detected is False
        assert len(res.delivered) == len(scn.messages)


def test_no_defence_leaks_wherever_the_corpus_does(scenarios):
    """Arm A's leak column must equal leak_unmediated by construction — if it ever
    diverges, the scoring rule is not being applied identically across arms."""
    for scn in scenarios[:40]:
        row = score_scenario(scn)
        assert row["arms"]["none"]["leaked"] == row["leak_unmediated"], scn.id


# --------------------------------------------------------------------------- #
# Arm B
# --------------------------------------------------------------------------- #

def test_scanner_catches_a_credential_at_egress(scenarios):
    scn = _by_family(scenarios, "external_credential")
    assert content_scanner(scn).stopped, "AKIA-shaped key at an external recipient"


def test_scanner_ignores_internal_hops(scenarios):
    """The source read carries the full record but goes nowhere unauthorised. A scanner
    that flagged it would score a false positive on every scenario in the corpus."""
    scn = _by_family(scenarios, "internal_clean")
    assert not content_scanner(scn).stopped


def test_scanner_is_stateless(scenarios):
    """No cross-message memory: running the same scenario twice, and running its
    messages in isolation, must give the same per-message verdicts."""
    from demo_app.eval.baselines import _scanner_flags
    scn = _by_family(scenarios, "external_verbatim")
    first = [_scanner_flags(m.content) for m in scn.messages]
    second = [_scanner_flags(m.content) for m in reversed(list(scn.messages))]
    assert first == list(reversed(second))


def test_scanner_cannot_see_a_bare_name(scenarios):
    """The documented limitation, pinned so it cannot silently change: arm B has no NER,
    so a message carrying only a personal name does not flag. This favours Haris and is
    reported alongside the table."""
    from demo_app.eval.baselines import _scanner_flags
    assert not _scanner_flags("Please follow up with Robert Roberts about the case.")


# --------------------------------------------------------------------------- #
# Arm C
# --------------------------------------------------------------------------- #

def test_heuristic_blocks_unauthorised_recipients(scenarios):
    scn = _by_family(scenarios, "external_derived")
    assert metadata_heuristic(scn).stopped


def test_heuristic_blocks_a_missing_token(scenarios):
    scn = _by_family(scenarios, "spoof")
    assert metadata_heuristic(scn).stopped


def test_heuristic_blocks_a_second_subject(scenarios):
    scn = _by_family(scenarios, "subject_mismatch")
    assert metadata_heuristic(scn).stopped


def test_heuristic_allows_authorised_internal_traffic(scenarios):
    for family in ("internal_clean", "internal_derived", "near_miss_benign",
                   "same_subject"):
        scn = _by_family(scenarios, family)
        assert not metadata_heuristic(scn).stopped, family


def test_heuristic_never_reads_content(scenarios):
    """Rewriting every message body must not change the heuristic's decision."""
    scn = _by_family(scenarios, "external_verbatim")
    before = metadata_heuristic(scn).stopped
    scrubbed = scn.messages
    scn.messages = [m.model_copy(update={"content": "x"}) for m in scrubbed]
    try:
        assert metadata_heuristic(scn).stopped == before
    finally:
        scn.messages = scrubbed


# --------------------------------------------------------------------------- #
# The table
# --------------------------------------------------------------------------- #

def test_every_arm_is_scored_on_every_scenario(scenarios):
    row = score_scenario(scenarios[0])
    assert set(row["arms"]) == {a.key for a in ARMS}
    for cell in row["arms"].values():
        assert set(cell) == {"stopped", "detected", "leaked", "latencies"}


def test_run_all_covers_the_corpus():
    rows = run_all()
    assert len(rows) == 312
