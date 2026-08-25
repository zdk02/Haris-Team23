"""Task I5 — exfiltration and boundary crossings are different claims.

A single "leak prevention" rate over every attack that goes wrong mixes two things:

  EXFILTRATION        an identifier reaches an address outside the trust boundary. Data
                      left the building. This is what a reader hears when we say "leak".
  BOUNDARY CROSSING   one patient's record reaches a workflow bound to another, or a
                      partner whose agreement does not cover them. A real violation, and
                      nothing left the building at all.

Reported together, "we prevented 152 leaks" is heard as the first when a third of the
denominator is the second. These tests pin that the two are counted separately and that
neither is quietly empty.

WHAT THE SPLIT REVEALED. The combined rate said Haris 90%, heuristic 71% — a clean win.
Split, it says the heuristic prevents 100% of exfiltration and Haris 87%, while Haris
takes 100% of boundary crossings and the heuristic 0%. Both halves are true and the
combined number showed neither. A blunt egress block cannot be beaten by rewriting content
it never reads; it also cannot allow a partner referral, a form template or a ward round,
and it cannot see a record handed to the wrong workflow. That is the trade the report
should argue, and it only became visible when the denominators came apart.
"""
from __future__ import annotations

import pytest

from demo_app.eval.baselines import (
    ARMS, _boundary_ci, _exfiltration_ci, run_all,
)


@pytest.fixture(scope="module")
def rows():
    return run_all(include_secrets=False)


def test_the_two_denominators_partition_the_leaking_attacks(rows):
    """Every leaking attack belongs to exactly one claim — no scenario is counted twice,
    and none is dropped between them."""
    leaking = [r for r in rows if r["label_attack"] and r["leak_unmediated"]]
    exfil = [r for r in leaking if r["egresses"]]
    boundary = [r for r in leaking if not r["egresses"]]
    assert len(exfil) + len(boundary) == len(leaking)
    assert exfil and boundary, "a claim with an empty denominator is not a claim"


def test_both_claims_are_reported_for_every_arm(rows):
    for arm in ARMS:
        assert _exfiltration_ci(rows, arm.key) is not None, arm.key
        assert _boundary_ci(rows, arm.key) is not None, arm.key


def test_the_boundary_claim_is_where_the_arms_separate(rows):
    """The reason the split earns its place. Both baselines score zero on boundary
    crossings — the metadata is faultless and nothing egresses for a scanner to read —
    while Haris catches them. Combined with exfiltration, that difference is diluted by
    families every arm handles."""
    assert _boundary_ci(rows, "haris").rate == 1.0
    assert _boundary_ci(rows, "scanner").rate == 0.0
    assert _boundary_ci(rows, "metadata").rate == 0.0


def test_the_heuristic_beats_haris_on_exfiltration(rows):
    """THE TRADE, and the reason the split was worth making.

    The metadata heuristic prevents 100% of exfiltration: it blocks every external
    recipient unconditionally, so obfuscation, encoding and paraphrase are all irrelevant
    to it — you cannot defeat a rule by rewriting content it never reads. Haris scores
    lower, and the whole difference is the four encoding rungs of the obfuscation ladder.

    That is not a defect to fix by blocking more. Haris reads payloads because it PERMITS
    things the heuristic cannot: the partner referral that carries a real patient record
    outside the boundary, the form template that looks like a leak, the ward round with
    two patients. Reading payloads is what makes those allowable, and it is also what
    encoding defeats.

    The combined rate hid both halves of this. Asserted as a test so that if it ever
    inverts, the report's §6 argument is re-examined rather than quietly outdated.
    """
    haris = _exfiltration_ci(rows, "haris").rate
    metadata = _exfiltration_ci(rows, "metadata").rate
    assert metadata == 1.0, "the blunt egress block should catch everything that egresses"
    assert haris < metadata, (
        "Haris now matches or beats the heuristic on exfiltration — check whether the "
        "obfuscation ladder still has encoding rungs, and update §6")


def test_haris_wins_where_reading_payloads_is_the_only_option(rows):
    """The other side of the same trade. Both baselines score zero on boundary crossings;
    Haris takes all of them. Quoting either column alone misdescribes the system."""
    assert _boundary_ci(rows, "haris").rate == 1.0
    assert _boundary_ci(rows, "metadata").rate == 0.0


def test_the_content_scanner_is_the_worst_of_both(rows):
    """Worth recording: the arm closest to a real deployed DLP filter is beaten by six
    lines of metadata checks on exfiltration AND scores zero on boundary crossings. It
    reads content without lineage, which is the combination that buys least."""
    assert _exfiltration_ci(rows, "scanner").rate < _exfiltration_ci(rows, "metadata").rate
    assert _boundary_ci(rows, "scanner").rate == 0.0


def test_the_no_defence_arm_prevents_nothing_in_either_claim(rows):
    """The denominator check: if the zero line is not zero, the split has miscounted."""
    assert _exfiltration_ci(rows, "none").rate == 0.0
    assert _boundary_ci(rows, "none").rate == 0.0