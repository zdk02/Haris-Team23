"""Seed sensitivity: which of our numbers are about Haris, and which about the corpus?

THE QUESTION THIS ANSWERS.
Every figure in the evaluation comes from a single seed. Seed 23 drew one particular set of
names, record ids and credentials, and every rate we report is conditioned on that draw. A
reader is entitled to ask whether "false positives 14%" describes the system or describes
the afternoon Faker had — and until this module existed, we could not answer.

WHAT CHANGING THE SEED DOES, AND WHAT IT DOES NOT.
It redraws surface CONTENT: names, record ids, credentials, which fact each record carries,
which subject each scenario is about. It does NOT change structure — the families, their
counts, the hop shapes, the ladder rungs (assigned by position, task M2) and the metadata
are identical under every seed.

So this sweep probes exactly one thing: sensitivity to the particular strings. That is a
narrow question, and stating it narrowly is the point. It is NOT evidence that the corpus
generalises to real traffic, and averaging over seeds does not turn an authored corpus into
a sampled one. Anyone reporting a seed-averaged rate as if it broadened the result would be
overselling this module.

WHY IT MATTERS MOST WITH PRESIDIO ON.
Haris's structural checks — recipient, token, subject binding, taint on exact identifiers —
do not care what a patient is called, so the Presidio-OFF numbers should be flat across
seeds. Presidio's NER very much does care: it recognises some names and not others, and
finding PA-3 recorded that non-Anglo surnames fare worse in the default spaCy model. If the
Presidio-ON rates move between seeds, that variance IS the recall limitation, quantified
instead of anecdotal.

    python -m demo_app.eval.seed_sweep                 # structural arms, fast
    python -m demo_app.eval.seed_sweep --secrets       # the shipped configuration, slow
    python -m demo_app.eval.seed_sweep --seeds 23 24 25 26 27
"""
from __future__ import annotations

import argparse
import statistics
from typing import Sequence

from demo_app.eval.runner import run_all
from demo_app.eval.stats import rate_ci

DEFAULT_SEEDS = (23, 24, 25, 26, 27)


def measure(seed: int, include_secrets: bool) -> dict[str, float]:
    """The headline rates for one seed."""
    records = run_all(include_secrets=include_secrets, seed=seed)
    attacks = [r for r in records if r["label_attack"]]
    benign = [r for r in records if not r["label_attack"]]
    real = [r for r in attacks if r["leak_unmediated"]]

    prevented = sum(1 for r in real if not r["leak_haris"])
    return {
        "prevention": prevented / len(real) if real else 0.0,
        "detection": sum(1 for r in attacks if r["detected"]) / len(attacks),
        "false_positive": sum(1 for r in benign if r["stopped"]) / len(benign),
        "n_leaking": float(len(real)),
        "n_benign": float(len(benign)),
    }


def report(seeds: Sequence[int], include_secrets: bool) -> None:
    config = "Presidio ON (the shipped configuration)" if include_secrets \
        else "Presidio OFF (structural agents only)"
    print(f"Seed sensitivity — {config}")
    print(f"seeds: {list(seeds)}\n")
    print("  A seed redraws every name, record id and credential. It does not change the")
    print("  families, their counts, or the structure of any scenario — so this measures")
    print("  sensitivity to the STRINGS, and nothing wider. It is not evidence that the")
    print("  corpus generalises to real traffic.\n")

    if len(seeds) < 2:
        # A spread computed from one sample is trivially zero, and the verdict below
        # would read "invariant" — a claim of stability from a measurement that cannot
        # detect instability. Say so instead of implying it (issue #23).
        print("  (!) ONE SEED. The spread below is zero by construction, not by evidence:")
        print("      a single sample cannot show that a rate is stable. Pass at least two")
        print("      seeds before reading the verdict, e.g. --seeds 23 24 25.\n")

    rows = [(s, measure(s, include_secrets)) for s in seeds]

    print(f"  {'seed':>6}{'prevention':>14}{'detection':>14}{'false pos':>14}")
    for seed, m in rows:
        print(f"  {seed:>6}{m['prevention']*100:>13.1f}%"
              f"{m['detection']*100:>13.1f}%{m['false_positive']*100:>13.1f}%")

    print()
    for metric in ("prevention", "detection", "false_positive"):
        vals = [m[metric] for _, m in rows]
        spread = max(vals) - min(vals)
        if len(seeds) < 2:
            verdict = "UNKNOWN — one seed cannot establish stability"
        else:
            verdict = ("invariant" if spread == 0 else
                       "stable" if spread <= 0.02 else
                       "SENSITIVE — report the range, not a point")
        mean = statistics.mean(vals)
        print(f"  {metric:<16} mean={mean*100:5.1f}%  "
              f"range={min(vals)*100:5.1f}–{max(vals)*100:5.1f}%  "
              f"spread={spread*100:4.1f} pts   {verdict}")

    print()
    if len(seeds) < 2:
        print("  Run again with several seeds. With one, every 'spread' above is the")
        print("  difference between a number and itself.")
    elif all(max(m[k] for _, m in rows) == min(m[k] for _, m in rows)
             for k in ("prevention", "detection", "false_positive")):
        print("  Every rate is identical across seeds. That is the expected result for the")
        print("  structural agents — recipient, token, subject binding and exact-identifier")
        print("  taint do not care what a patient is called — and it means the reported")
        print("  numbers are not an artefact of one lucky draw. It also means this sweep")
        print("  cannot tell you anything about generalisation, only about string choice.")
    else:
        print("  The rates MOVE between seeds, so at least one detector's answer depends on")
        print("  which names were drawn. Report the range rather than the seed-23 point,")
        print("  and name the mechanism: with Presidio on, this is NER recall (finding")
        print("  PA-3 — non-Anglo surnames are recognised less reliably).")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--secrets", action="store_true",
                    help="run with Presidio ON (slow: minutes per seed)")
    ap.add_argument("--seeds", type=int, nargs="+", default=list(DEFAULT_SEEDS))
    args = ap.parse_args()

    import logging
    logging.disable(logging.INFO)
    report(args.seeds, args.secrets)


if __name__ == "__main__":
    main()
