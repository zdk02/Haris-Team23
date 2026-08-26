"""Mediation latency, measured properly (task O3).

WHAT WAS WRONG WITH THE NUMBER WE HAD. The runner reports a per-hop latency as a
by-product of the correctness run, and three things made it unquotable:

  * NO DENOMINATOR. It timed Haris and reported the result as "mediation cost", but a
    hop costs something even with no agents at all — constructing the message, writing
    the lineage record, resolving an empty verdict list. Without measuring that floor we
    were attributing the harness's own overhead to mediation.

  * A WARM-UP THAT WARMED ONE FAMILY. Five scenarios, all `external_verbatim`, all
    structured records. Every other family's first scenario paid its own cold-start —
    the spaCy pipeline, the tag cache, the regex compilations — and those costs landed in
    the reported average.

  * ONE RUN. A single sample of a noisy quantity, reported as a mean, with no spread.
    Machine load, thermal state and GC timing all move it, and a mean hides that a few
    slow hops dominate.

WHAT THIS DOES INSTEAD. A no-agents arm as the floor, one warm-up scenario per family,
three repetitions, and median with interquartile range rather than a mean. The median
because the distribution is right-skewed — a handful of hops that hit a cold cache or a
GC pause pull a mean upward and describe nothing typical. The IQR because a latency figure
without a spread is a claim about one machine on one afternoon.

The CPU is printed because these numbers are not portable and quoting them without the
hardware is how a reader ends up comparing them to something incomparable.

    python -m demo_app.eval.latency              # structural agents only
    python -m demo_app.eval.latency --secrets    # add Presidio (minutes per repetition)
    python -m demo_app.eval.latency --json report/appendix/latency.json
"""
from __future__ import annotations

import argparse
import json
import platform
import statistics
from dataclasses import dataclass, field
from typing import Optional, Sequence

from haris.schemas.policy import Mode

from demo_app.eval.domains import DOMAINS, build_agents
from demo_app.eval.generate import Scenario, generate
from demo_app.eval.runner import _run_arm

REPETITIONS = 3


@dataclass
class Sample:
    """Every per-hop measurement for one arm, across every repetition."""
    label: str
    hops: list[float] = field(default_factory=list)
    per_rep_median: list[float] = field(default_factory=list)

    @property
    def median(self) -> float:
        return statistics.median(self.hops) if self.hops else 0.0

    @property
    def iqr(self) -> tuple[float, float]:
        if len(self.hops) < 4:
            return (0.0, 0.0)
        q = statistics.quantiles(self.hops, n=4)
        return (q[0], q[2])

    @property
    def p95(self) -> float:
        if not self.hops:
            return 0.0
        s = sorted(self.hops)
        return s[min(len(s) - 1, int(0.95 * len(s)))]

    @property
    def run_to_run_spread(self) -> float:
        """How much the median moved between repetitions. If this is large relative to
        the median, the measurement is dominated by machine state and the figure should
        be quoted as a range rather than a value."""
        if len(self.per_rep_median) < 2:
            return 0.0
        return max(self.per_rep_median) - min(self.per_rep_median)


def _agents_for(scn: Scenario, arm: str, include_secrets: bool) -> list:
    """The no-agents arm is the DENOMINATOR, not a defence.

    It measures what a hop costs with mediation removed but everything else intact: the
    orchestrator, the state store, the lineage write, the policy engine resolving an
    empty verdict list. Subtracting it is what turns a wall-clock figure into a claim
    about the cost of mediation specifically.

    Note this is a legitimate use of an empty agent list, unlike the deleted "without
    Haris" PREVENTION arm — there, an empty list could not stop anything and its 100%
    leak rate was a constant rather than a measurement. Here it is exactly the right
    control, because the quantity being measured is time and time is spent either way.
    """
    if arm == "none":
        return []
    return build_agents(DOMAINS[scn.domain], include_secrets)


def _one_pass(scenarios: Sequence[Scenario], arm: str, include_secrets: bool) -> list[float]:
    hops: list[float] = []
    for scn in scenarios:
        agents = _agents_for(scn, arm, include_secrets)
        _, _, lat, _ = _run_arm(scn, agents, Mode.ENFORCE, want_latency=True)
        hops.extend(lat)
    return hops


def _warm_up(scenarios: Sequence[Scenario], arm: str, include_secrets: bool) -> None:
    """One scenario per FAMILY, not five from one family.

    Each family has its own first-time costs — a record format the extractor has not
    parsed before, a message shape that compiles a different regex path, and with Presidio
    on, the spaCy pipeline itself. Warming one family left every other family's cold start
    inside the measurement.
    """
    seen: set[str] = set()
    for scn in scenarios:
        if scn.family in seen:
            continue
        seen.add(scn.family)
        _run_arm(scn, _agents_for(scn, arm, include_secrets), Mode.ENFORCE,
                 want_latency=True)


def measure(arm: str, include_secrets: bool, repetitions: int = REPETITIONS) -> Sample:
    scenarios = generate()
    sample = Sample(label=arm)
    for _ in range(repetitions):
        _warm_up(scenarios, arm, include_secrets)
        hops = _one_pass(scenarios, arm, include_secrets)
        sample.hops.extend(hops)
        sample.per_rep_median.append(statistics.median(hops) if hops else 0.0)
    return sample


def _machine() -> dict:
    return {
        "cpu": platform.processor() or platform.machine() or "unknown",
        "machine": platform.machine(),
        "platform": platform.platform(),
        "python": platform.python_version(),
    }


def report(samples: list[Sample], include_secrets: bool, repetitions: int) -> None:
    m = _machine()
    print("Haris — mediation latency (task O3)\n")
    print(f"  CPU        : {m['cpu']}")
    print(f"  platform   : {m['platform']}")
    print(f"  python     : {m['python']}")
    print(f"  repetitions: {repetitions} · warm-up: one scenario per family")
    print(f"  Presidio   : {'ON' if include_secrets else 'OFF'}")
    print( "  These figures are not portable. Quote them with the CPU or not at all.\n")

    print(f"  {'arm':<28}{'median':>10}{'IQR':>20}{'p95':>10}{'hops':>8}")
    for s in samples:
        lo, hi = s.iqr
        print(f"  {s.label:<28}{s.median:>9.3f}ms{f'{lo:.3f}-{hi:.3f}':>20}"
              f"{s.p95:>9.3f}{len(s.hops):>8}")

    floor = next((s for s in samples if s.label.startswith("no agents")), None)
    if floor:
        print()
        for s in samples:
            if s is floor:
                continue
            cost = s.median - floor.median
            share = (cost / s.median * 100) if s.median else 0.0
            print(f"  mediation cost, {s.label}: {cost:.3f} ms per hop "
                  f"({share:.0f}% of the measured hop)")
        print( "  = arm median minus the no-agents floor. The floor is the orchestrator,")
        print( "  the state store and an empty policy resolution; attributing it to")
        print( "  mediation would overstate the cost.")

    print()
    for s in samples:
        spread = s.run_to_run_spread
        if s.median and spread > 0.2 * s.median:
            print(f"  (!) {s.label}: the median moved {spread:.3f} ms between "
                  f"repetitions, which is more than a fifth of the value. Quote a range.")
        else:
            print(f"  {s.label}: stable across repetitions "
                  f"(median moved {spread:.3f} ms).")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--secrets", action="store_true",
                    help="include the Presidio Secrets/PII agent (slow)")
    ap.add_argument("--repetitions", type=int, default=REPETITIONS)
    ap.add_argument("--json", metavar="PATH", help="also write the figures as JSON")
    args = ap.parse_args()

    import logging
    logging.disable(logging.INFO)

    floor = measure("none", include_secrets=False, repetitions=args.repetitions)
    floor.label = "no agents (floor)"

    haris = measure("haris", include_secrets=args.secrets,
                    repetitions=args.repetitions)
    haris.label = "Haris" + (" + Presidio" if args.secrets else "")

    report([floor, haris], args.secrets, args.repetitions)

    if args.json:
        out = {
            "machine": _machine(),
            "repetitions": args.repetitions,
            "presidio": args.secrets,
            "arms": {
                s.label: {
                    "median_ms": round(s.median, 4),
                    "iqr_ms": [round(s.iqr[0], 4), round(s.iqr[1], 4)],
                    "p95_ms": round(s.p95, 4),
                    "hops": len(s.hops),
                    "per_repetition_median_ms": [round(x, 4) for x in s.per_rep_median],
                } for s in (floor, haris)
            },
        }
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()
