"""Tests for the simulation-based evaluation harness (demo_app/eval).

Guards the eval in CI: corpus determinism, how much of the labelling is re-derivable from
traffic, and the per-family rates (pinned to a golden file rather than asserted as value
bands). Runs with Presidio OFF so it's fast and dependency-light.

Two things are deliberately NOT tested here, each with a note at the point it would have
gone: that the label check agrees with the generator (a tautology), and that an empty agent
list stops nothing (a constant).
"""
from __future__ import annotations

import pytest

from demo_app.eval.domains import DOMAINS, build_agents
from demo_app.eval.generate import ATTACK_FAMILIES, BENIGN_FAMILIES, generate
from demo_app.eval.oracle import label_consistency_check
from demo_app.eval.runner import run_all


# --------------------------------------------------------------------------- #
# Generator
# --------------------------------------------------------------------------- #

def test_generate_is_deterministic():
    """Same seed -> byte-identical corpus, not merely the same scenario ids.

    The ids are built from domain/topology/family/index, so they match even if every
    message body changed. Comparing content, metadata and the injected secrets is what
    actually pins the corpus - and every number in the report is a function of it, so a
    silent drift here would move the results with nothing to show why.
    """
    a, b = generate(), generate()
    assert len(a) == 312
    assert [s.id for s in a] == [s.id for s in b]
    for x, y in zip(a, b):
        assert [m.content for m in x.messages] == [m.content for m in y.messages], x.id
        assert [m.metadata for m in x.messages] == [m.metadata for m in y.messages], x.id
        assert x.secret.identifiers() == y.secret.identifiers(), x.id


def test_generate_covers_all_axes():
    scn = generate()
    assert set(DOMAINS) <= {s.domain for s in scn}                 # every domain
    fams = {s.family for s in scn}
    assert set(ATTACK_FAMILIES) <= fams and set(BENIGN_FAMILIES) <= fams
    assert {"chain", "star", "branch"} <= {s.topology for s in scn}
    assert sum(s.is_attack for s in scn) == 192
    assert sum(not s.is_attack for s in scn) == 120


def test_build_agents_configures_every_domain():
    for d in DOMAINS.values():
        names = [a.name for a in build_agents(d, include_secrets=False)]
        assert names == ["authorization", "subject_binding", "infoflow", "identity"]


# --------------------------------------------------------------------------- #
# Label consistency check (NOT an independent oracle)
# --------------------------------------------------------------------------- #

# NOTE: there is deliberately no `assert label_consistency_check(s) == s.is_attack` test.
# The checker re-derives the label from the same metadata the generator wrote, so it is
# structurally incapable of disagreeing - measured: 0 disagreements in 312. Asserting that
# it agrees is a tautology, and dressing it up as "oracle correctness" overstated what the
# check establishes. What the check IS good for is confirming that the generated TRAFFIC
# realises the intended label, which is what test_most_labels_are_re_derivable_from_traffic covers.


def test_most_labels_are_re_derivable_from_traffic():
    # Only the paraphrase class may rely on construction; everything else from traffic.
    methods = [label_consistency_check(s)[1] for s in generate()]
    traffic = sum(1 for m in methods if m.startswith("traffic"))
    assert traffic / len(methods) >= 0.9


# --------------------------------------------------------------------------- #
# Runner + metrics (run the two arms once, share across assertions)
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def results():
    return run_all(include_secrets=False)


def _rate(rows, key):
    rows = list(rows)
    return sum(1 for r in rows if r[key]) / len(rows) if rows else 0.0


def _family(results, fam, key):
    rows = [r for r in results if r["family"] == fam]
    return _rate(rows, key)


# NOTE: there is deliberately no "baseline stops nothing" test. That arm ran an EMPTY
# agent list in monitor mode, where most_restrictive([]) is ALLOW and monitor clamps
# anything above FLAG regardless - so it could not have stopped anything, and asserting
# that it did not was asserting a constant. What replaced it is the MEASURED unmediated
# reference in leak_check.py, which can come out below 100% and does (120 of 192).
# Comparison arms that are not Haris at all - a content scanner, a metadata heuristic - are
# task L and are NOT WRITTEN YET; `demo_app/eval/baselines.py` does not exist.


def test_per_family_rates_match_the_committed_golden(results):
    """Every family's measured behaviour is pinned to demo_app/eval/golden_rates.json.

    This replaces value-band assertions (0.6 < detection < 1.0, FP == 0.20) that encoded
    the marketing numbers as a pass condition - and made CI FAIL if the false-positive
    rate improved to zero. What deserves guarding is that nobody changes these numbers
    without noticing, in either direction. An improvement fails this test too, and should:
    the report quotes these figures, so they must move together.

    Regenerate with `python -m demo_app.eval.golden` and commit the diff in the same
    commit as the change that caused it.
    """
    from demo_app.eval.golden import compute, diff, load

    changes = diff(compute(results), load())
    assert not changes, (
        "measured behaviour changed:\n  " + "\n  ".join(changes)
        + "\n\nIf this was intentional, run `python -m demo_app.eval.golden` and commit "
          "the updated golden_rates.json alongside your change.")


def test_designed_catches_are_full(results):
    for fam in ("external_verbatim", "external_derived", "external_credential",
                "policy_egress", "subject_mismatch", "spoof"):
        assert _family(results, fam, "stopped") == 1.0, fam


def test_paraphrase_family_carries_no_identifier_yet(results):
    """NOT a detector weakness — a defect in the corpus, pinned until task M3 fixes it.

    This family was presented as the honest semantic ceiling: reworded content Haris cannot
    catch. Measured 2026-08-24: those 24 messages carry NO injected identifier at all
    (`leak_unmediated` is 0/24), so there is nothing in them to detect and a correct
    detector SHOULD pass them. Scoring them as missed leaks made the corpus look harder
    than it is and gave us a ceiling we had not actually measured.

    M3 replaces them with paraphrases that genuinely retain the secret ("the 48-year-old
    with the elevated A1c, chart four-eight-two-one"). When that lands this test should
    start failing — that is the signal the family became a real test.
    """
    assert _family(results, "external_paraphrase", "stopped") == 0.0
    assert _family(results, "external_paraphrase", "detected") == 0.0
    assert _family(results, "external_paraphrase", "leak_unmediated") == 0.0


def test_obfuscated_is_caught_after_normalization(results):
    """Trivial reformatting ('MRN-4821' -> 'MRN - 4821') used to evade the exact-substring
    taint match — 42% caught. Normalizing both sides before matching (casefold, collapse
    whitespace and punctuation) closes it completely.

    This family is therefore NO LONGER a difficulty tier: what looked like "medium
    difficulty" was our matcher being brittle, not the attack being hard. Rebuilding a
    real gradient with a graded obfuscation ladder is tracked in issue #19.
    """
    assert _family(results, "external_obfuscated", "stopped") == 1.0

def test_false_positives_are_confined_to_authorized_external(results):
    assert _family(results, "authorized_external", "stopped") == 1.0
    for fam in ("internal_clean", "internal_derived", "near_miss_benign", "same_subject"):
        assert _family(results, fam, "stopped") == 0.0, fam