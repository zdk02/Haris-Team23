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
    assert len(a) == 432
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
    assert sum(s.is_attack for s in scn) == 264
    assert sum(not s.is_attack for s in scn) == 168


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


def test_only_the_two_indistinguishable_families_rest_on_construction():
    """Most labels are re-derivable from the traffic. Exactly two are not, and in both
    cases that IS the finding rather than a shortcut.

    `external_paraphrase` carries no exact identifier, so there is nothing in the message
    to match against ground truth. `forged_session_scope` is byte-for-byte identical to a
    legitimate ward round — the attacker wrote a declaration that looks exactly like a
    true one — so no reading of the traffic can separate them, which is precisely the
    limitation the family exists to measure.

    Asserted as a SET rather than a percentage: the old form was a 0.9 threshold that
    quietly assumed paraphrase was the only such family, and it would have absorbed a
    third one without anyone noticing. If a family ever joins this set, the question to
    ask is whether it was constructed to be unfalsifiable.
    """
    methods: dict[str, set] = {}
    for s in generate():
        methods.setdefault(s.family, set()).add(label_consistency_check(s)[1])

    by_construction = {fam for fam, ms in methods.items()
                       if any(m.startswith("construction") for m in ms)}
    assert by_construction == {"external_paraphrase", "forged_session_scope"}, \
        by_construction

    flat = [label_consistency_check(s)[1] for s in generate()]
    assert sum(1 for m in flat if m.startswith("traffic")) / len(flat) >= 0.85


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


def test_the_only_false_positive_is_the_one_we_chose(results):
    """FP is 24/168 (14%) and every one of them is `internal_handoff` — a derived
    agent-to-agent summary with no declared recipient, which is the commonest message
    shape in a multi-agent pipeline.

    It is refused because `flag_unknown_destination` defaults True. That is a deliberate
    security property, not an oversight: `recipient` is sender-supplied and an absent one
    cannot be told from a deleted one, so relaxing the check would let an attacker switch
    off egress control by removing a key. We keep the property, measure what it costs,
    and name the deployment-era fix (bind `recipient` at the interception adapter).

    Every other benign family must stay clean, including the two that are hard:
    `authorized_external` carries a real record out of the trust boundary, and
    `multi_subject_workflow` is traffic identical to an attack. Both were blocked by an
    earlier version of Haris and are passed now by reading a policy rather than a
    pattern — which is what stops this column being an artefact of an easy corpus.
    """
    assert _family(results, "internal_handoff", "stopped") == 1.0

    for fam in ("authorized_external", "internal_clean", "internal_derived",
                "near_miss_benign", "same_subject", "multi_subject_workflow"):
        assert _family(results, fam, "stopped") == 0.0, fam


def test_the_cost_of_trusting_a_declared_scope_is_reported(results):
    """`session_scope` is sender-supplied, so an attacker can write their own and defeat
    binding 3 entirely. That is 24 misses, and they are in the corpus and in the tables
    rather than in a footnote. The remedy is binding the field at the interception
    adapter (THREAT_MODEL.md §2.3), which is deployment work, not agent work.
    """
    assert _family(results, "forged_session_scope", "stopped") == 0.0
    assert _family(results, "subject_mismatch", "stopped") == 1.0


def test_the_hard_benign_family_is_still_hard(results):
    """`authorized_external` carries a real record, with real identifiers, out of the
    trust boundary to an external address — the exact shape of an exfiltration — and is
    correct to allow, because the referral agreement covers that subject (task K6).

    Any egress filter that blocks tainted content leaving the boundary refuses all 24.
    Haris allows them by reading the agreement, and its twin `partner_scope_violation`
    stops the pair being passable by a blanket allow. That is what makes the
    false-positive column a measurement rather than an artefact of an easy corpus.
    """
    assert _family(results, "authorized_external", "stopped") == 0.0
    assert _family(results, "partner_scope_violation", "stopped") == 1.0