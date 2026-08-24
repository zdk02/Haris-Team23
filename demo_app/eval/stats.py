"""Confidence intervals for the evaluation's rates (task M4).

WHY EVERY RATE IN THIS REPORT NEEDS ONE.
The tables report percentages computed from between 4 and 168 observations, and nothing in
them says which is which. "100% on the spacing rung" and "90% leak prevention" are printed
in the same format, but the first rests on FOUR scenarios and the second on 168. A reader
has no way to tell that the first is barely evidence and the second is solid — and the
obfuscation ladder, which is the figure the report leads with for difficulty, is the worst
offender at n=4 per rung.

An interval fixes that without changing a single measurement. It states what the sample can
support, which is the honest form of a result: 0/24 is not "0%", it is "0%, and the data is
consistent with anything up to about 14%".

WHY BOOTSTRAP RATHER THAN A FORMULA.
The normal approximation (p ± 1.96·√(p(1-p)/n)) collapses at exactly the values this
evaluation is full of: at p=0 or p=1 it produces a zero-width interval, which would claim
perfect certainty from four observations. Bootstrapping resamples the observed outcomes and
reports the spread of the resampled rates, so a degenerate sample produces a degenerate
interval and the reader can see it.

For p=0 and p=1 even the bootstrap gives a zero-width interval — every resample of 24
identical outcomes is identical — so those cases fall back to the RULE OF THREE
(upper bound ≈ 3/n for 0 successes, mirrored for n successes), which is the standard answer
to "we saw none, how many might there be?". Without that fallback a 0/24 family would print
[0%, 0%] and quietly claim the opposite of what it should.

DETERMINISM. The resampling is seeded, so the same records always produce the same
interval; a CI that moved between runs would be one more number nobody could reproduce.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Optional, Sequence

DEFAULT_RESAMPLES = 10_000
DEFAULT_CONFIDENCE = 0.95
SEED = 23  # same seed the generator uses; reproducibility is the point


@dataclass(frozen=True)
class Interval:
    """A rate and the range the sample actually supports."""
    rate: float
    low: float
    high: float
    n: int

    def pct(self, places: int = 0) -> str:
        """'90% [85-94]' — the form the tables print."""
        f = f"{{:.{places}f}}"
        return (f"{f.format(self.rate * 100)}% "
                f"[{f.format(self.low * 100)}-{f.format(self.high * 100)}]")

    @property
    def width(self) -> float:
        return self.high - self.low

    @property
    def is_informative(self) -> bool:
        """A interval wider than 30 points is a sample size, not a result.

        Not a rule about what may be published — a flag for what must be described as
        indicative. The per-rung ladder numbers all land here at n=4, which is why the
        report presents the SHAPE of that curve (layout recovered, encodings not) rather
        than the percentages.
        """
        return self.width <= 0.30


def _rule_of_three(successes: int, n: int, confidence: float) -> tuple[float, float]:
    """Bounds for a sample with no variation at all.

    When every observation is the same, resampling cannot produce anything else, so the
    bootstrap interval is a point and would assert certainty we do not have. The rule of
    three answers the actual question — "we observed none in n trials, what rate is still
    consistent with that?" — with 3/n at 95%, which is the textbook approximation of
    1 - (1-p)^n = 0.05.
    """
    if n <= 0:
        return 0.0, 1.0
    bound = min(1.0, 3.0 / n) if confidence >= 0.95 else min(1.0, 2.3 / n)
    if successes == 0:
        return 0.0, bound
    return max(0.0, 1.0 - bound), 1.0


def bootstrap(outcomes: Sequence[bool], *,
              resamples: int = DEFAULT_RESAMPLES,
              confidence: float = DEFAULT_CONFIDENCE,
              seed: int = SEED) -> Optional[Interval]:
    """Percentile bootstrap CI for the proportion of True in `outcomes`.

    Returns None for an empty sample — a family with nothing in it has no rate, and
    printing 0% for it would be a fabrication rather than a measurement.
    """
    n = len(outcomes)
    if n == 0:
        return None

    successes = sum(1 for o in outcomes if o)
    rate = successes / n

    if successes in (0, n):
        low, high = _rule_of_three(successes, n, confidence)
        return Interval(rate=rate, low=low, high=high, n=n)

    rng = random.Random(seed)
    flags = [1 if o else 0 for o in outcomes]
    rates = sorted(sum(rng.choices(flags, k=n)) / n for _ in range(resamples))
    tail = (1.0 - confidence) / 2.0
    low = rates[int(tail * resamples)]
    high = rates[min(resamples - 1, int((1.0 - tail) * resamples))]
    return Interval(rate=rate, low=low, high=high, n=n)


def rate_ci(rows: Sequence[dict], key: str, **kw) -> Optional[Interval]:
    """CI for a boolean column of the runner's records."""
    return bootstrap([bool(r[key]) for r in rows], **kw)


def _selftest() -> None:
    print("bootstrap CIs — sanity checks\n")
    cases = [
        ("24 of 24 caught", [True] * 24),
        ("0 of 24 caught", [False] * 24),
        ("0 of 4 caught (a ladder rung)", [False] * 4),
        ("4 of 4 caught (a ladder rung)", [True] * 4),
        ("152 of 168 prevented", [True] * 152 + [False] * 16),
        ("24 of 168 false positives", [True] * 24 + [False] * 144),
        ("0 of 168 false positives", [False] * 168),
    ]
    for label, outcomes in cases:
        ci = bootstrap(outcomes)
        flag = "" if ci.is_informative else "   <- too wide to quote as a rate"
        print(f"  {label:<32} {ci.pct():<18} n={ci.n:<4}{flag}")
    print("\nNote how the n=4 rungs come out: the point estimates are 0% and 100%, and the")
    print("intervals say the sample supports almost anything. That is the honest reading,")
    print("and it is why the ladder is reported as a shape rather than six percentages.")


if __name__ == "__main__":
    _selftest()
