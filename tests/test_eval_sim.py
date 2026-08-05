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
    a, b = generate(), generate()
    assert [s.id for s in a] == [s.id for s in b]        # same seed -> same scenarios
    assert len(a) == 312


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

def test_oracle_reproduces_every_label():
    for s in generate():
        should_stop, method = oracle_should_stop(s)
        assert should_stop == s.is_attack, (s.id, method)


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


def test_baseline_stops_nothing(results):
    attacks = [r for r in results if r["oracle_attack"]]
    assert not any(r["baseline_stopped"] for r in attacks)   # no-Haris leaks everything


def test_headline_is_strong_but_not_perfect(results):
    attacks = [r for r in results if r["oracle_attack"]]
    benign = [r for r in results if not r["oracle_attack"]]
    assert 0.6 < _rate(attacks, "detected") < 1.0     # a real gap exists (not rigged)
    assert 0.6 < _rate(attacks, "stopped") < 1.0
    assert _rate(benign, "stopped") == pytest.approx(0.20, abs=0.01)  # honest FP


def test_designed_catches_are_full(results):
    for fam in ("external_verbatim", "external_derived", "external_credential",
                "policy_egress", "subject_mismatch", "spoof"):
        assert _family(results, fam, "stopped") == 1.0, fam


def test_paraphrase_is_the_documented_gap(results):
    assert _family(results, "external_paraphrase", "stopped") == 0.0
    assert _family(results, "external_paraphrase", "detected") == 0.0


def test_obfuscated_is_partially_caught(results):
    assert _family(results, "external_obfuscated", "stopped") < 1.0   # a hard class


def test_false_positives_are_confined_to_authorized_external(results):
    assert _family(results, "authorized_external", "stopped") == 1.0
    for fam in ("internal_clean", "internal_derived", "near_miss_benign", "same_subject"):
        assert _family(results, fam, "stopped") == 0.0, fam
