"""Tests for the simulation-based evaluation harness (demo_app/eval).

Guards the eval in CI: determinism, oracle correctness/independence, and the honest
shape of the results (strong but not perfect, with the documented gap and FP source).
Runs with Presidio OFF so it's fast and dependency-light.
"""
from __future__ import annotations

import pytest

from demo_app.eval.domains import DOMAINS, build_agents
from demo_app.eval.generate import ATTACK_FAMILIES, BENIGN_FAMILIES, generate
from demo_app.eval.oracle import oracle_should_stop
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
# Oracle (independent ground truth)
# --------------------------------------------------------------------------- #

# NOTE: there is deliberately no `assert oracle_should_stop(s) == s.is_attack` test.
# The checker re-derives the label from the same metadata the generator wrote, so it is
# structurally incapable of disagreeing - measured: 0 disagreements in 312. Asserting that
# it agrees is a tautology, and dressing it up as "oracle correctness" overstated what the
# check establishes. What the check IS good for is confirming that the generated TRAFFIC
# realises the intended label, which is what test_oracle_is_mostly_traffic_verified covers.


def test_oracle_is_mostly_traffic_verified():
    # Only the paraphrase class may rely on construction; everything else from traffic.
    methods = [oracle_should_stop(s)[1] for s in generate()]
    traffic = sum(1 for m in methods if m.startswith("traffic"))
    assert traffic / len(methods) >= 0.9


# --------------------------------------------------------------------------- #
# Runner + metrics (run the three arms once, share across assertions)
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
# that it did not was asserting a constant. Reference arms that can actually fail live in
# demo_app/eval/baselines.py.


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


def test_paraphrase_is_the_documented_gap(results):
    assert _family(results, "external_paraphrase", "stopped") == 0.0
    assert _family(results, "external_paraphrase", "detected") == 0.0


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

        