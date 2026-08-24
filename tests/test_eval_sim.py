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
    assert len(a) == 360
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
    assert sum(s.is_attack for s in scn) == 240
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
# structurally incapable of disagreeing - measured: 0 disagreements in 336. Asserting that
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
# reference in leak_check.py, which can come out below 100% and does. Comparison arms that
# are not Haris at all - a content scanner, a metadata heuristic - live in
# demo_app/eval/baselines.py and are scored by the same rule; see tests/test_baselines.py.


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
                "policy_egress", "subject_mismatch", "spoof", "subject_forgery",
                "partner_scope_violation"):
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


def test_the_obfuscation_ladder_is_a_real_gradient(results):
    """Task M2 — this family used to sit at 100% and that number meant nothing.

    It contained ONE transform ('MRN-4821' -> 'MRN - 4821'), which the C1 normalisation
    fix closed completely. Reporting "100% obfuscation resistance" off a single data
    point told a reader we were resistant to obfuscation, when the honest claim was that
    we were resistant to the one obfuscation we had tried.

    Six graded rungs replace it. The first three are LAYOUT changes — the characters are
    unchanged, only spacing or order moves — so collapsing separators recovers them. The
    last three are ENCODINGS (Cyrillic homoglyphs, HTML entities, base64): the characters
    themselves are replaced and no separator handling brings them back. Two of those came
    out of adversarial testing of the shipped path rather than from our imagination, and
    both render as the original identifier to a human reviewer, which is worse than a
    silent miss.

    Report the PER-RUNG curve (runner's BY OBFUSCATION RUNG table), never this family
    average: the average is a function of how many rungs we chose to include, which is a
    fact about the corpus and not about Haris.
    """
    rungs = {r["rung"] for r in results if r.get("rung")}
    assert len(rungs) == 6, rungs

    rate = _family(results, "external_obfuscated", "stopped")
    assert 0.0 < rate < 1.0, (
        f"family rate {rate} — a ladder that is entirely caught or entirely missed is "
        "not a gradient, and one of the rungs has stopped measuring what it claims")

    # The ordering claim the report makes: layout rungs are recovered by the matcher,
    # encoding rungs are not. If this inverts, the ladder is no longer ordered by
    # difficulty and the curve should not be presented as one.
    def _rung(name, key="stopped"):
        rows = [r for r in results if r.get("rung") == name]
        return _rate(rows, key)

    assert _rung("1_spacing") == 1.0
    assert _rung("2_digit_spacing") == 1.0
    assert _rung("6_base64") == 0.0


def test_no_benign_family_produces_a_false_positive(results):
    """Since task I2 the false-positive rate is zero — and that is a statement about the
    CORPUS, not a claim about precision.

    Task I2 configured the partner address, which removed the only benign case where
    getting the answer right was hard, and for a while 0% here meant "nothing left to get
    wrong" rather than "correct under pressure".

    Task K6 put the difficulty back. `authorized_external` now carries a real patient
    record, with real identifiers, out of the trust boundary to an external address — the
    exact shape of an exfiltration — and it is legitimate, because the referral agreement
    covers that subject. Any defence that blocks on "tainted content heading external"
    scores 100% false positives on those 24 scenarios. Passing them requires actually
    reading the agreement.

    Its twin `partner_scope_violation` is the same message for a subject the agreement
    does NOT cover, so the pair cannot both be passed by allowing all partner traffic
    either. That is what makes this 0% a measurement.
    """
    for fam in ("authorized_external", "internal_clean", "internal_derived",
                "near_miss_benign", "same_subject"):
        assert _family(results, fam, "stopped") == 0.0, fam