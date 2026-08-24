"""Task M4 — every rate carries the uncertainty its sample size implies.

The tables print percentages computed from between 4 and 168 observations in the same
format, so nothing distinguishes a solid result from a suggestive one. These tests pin the
properties that make the intervals worth printing — in particular the two degenerate cases
(0/n and n/n) where the obvious implementations claim certainty they have not earned.
"""
from __future__ import annotations

import pytest

from demo_app.eval.stats import Interval, bootstrap, rate_ci


def test_the_interval_brackets_the_point_estimate():
    for outcomes in ([True] * 152 + [False] * 16,
                     [True] * 24 + [False] * 144,
                     [True, False] * 12):
        ci = bootstrap(outcomes)
        assert ci.low <= ci.rate <= ci.high, ci


def test_a_unanimous_sample_does_not_claim_certainty():
    """THE ONE THAT MATTERS. A normal approximation gives ±0 at p=0 and p=1, and so does
    a naive bootstrap — every resample of 24 identical outcomes is identical. Both would
    print [0-0] for a family we saw fail 24 times out of 24, which asserts the opposite
    of what a sample of 24 supports."""
    zero = bootstrap([False] * 24)
    assert zero.rate == 0.0
    assert zero.high > 0.0, "0/24 must not claim a true rate of exactly zero"

    one = bootstrap([True] * 24)
    assert one.rate == 1.0
    assert one.low < 1.0, "24/24 must not claim a true rate of exactly one"


def test_more_evidence_narrows_the_interval():
    small = bootstrap([False] * 4)
    large = bootstrap([False] * 168)
    assert large.width < small.width
    assert small.high > 0.5, "four observations should support almost anything"


def test_tiny_samples_are_flagged_as_uninformative():
    """The obfuscation ladder runs at n=4 per rung, which is the whole reason this flag
    exists: the report presents that curve as a shape, not as six percentages."""
    assert not bootstrap([False] * 4).is_informative
    assert not bootstrap([True] * 4).is_informative
    assert bootstrap([True] * 152 + [False] * 16).is_informative


def test_it_is_deterministic():
    """A confidence interval that moved between runs would be one more number nobody
    could reproduce — the same objection that retired the value-band assertions."""
    outcomes = [True] * 30 + [False] * 20
    assert bootstrap(outcomes) == bootstrap(outcomes)


def test_an_empty_sample_has_no_rate():
    """A family with nothing in it must return None rather than 0%, which would be a
    fabricated measurement rather than an absent one."""
    assert bootstrap([]) is None


def test_rate_ci_reads_the_runner_records():
    rows = [{"stopped": True}, {"stopped": False}, {"stopped": True}]
    ci = rate_ci(rows, "stopped")
    assert ci.n == 3
    assert ci.rate == pytest.approx(2 / 3)


def test_the_printed_form_shows_the_range():
    out = Interval(rate=0.9048, low=0.857, high=0.946, n=168).pct()
    assert out.startswith("90%")
    assert "[" in out and "-" in out
