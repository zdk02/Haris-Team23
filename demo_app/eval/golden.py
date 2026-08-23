"""Golden per-family rates — the evaluation's regression guard.

WHY A GOLDEN FILE INSTEAD OF VALUE BANDS.
The tests this replaces asserted `0.6 < detection < 1.0` and `FP == approx(0.20)`. Those
are not invariants, they are the marketing numbers written down as a pass condition — and
the second one meant **CI failed if the false-positive rate improved to zero**. A test that
punishes progress is worse than no test, and a comment saying "not rigged" does not make it
so.

What is actually worth guarding is that nobody changes the measured behaviour of the system
WITHOUT NOTICING. So this records what every family currently does, and the test fails on
any change in either direction. An improvement fails the test too — and should, because the
report quotes these numbers and they have to be updated together.

Regenerate after an intentional change:

    python -m demo_app.eval.golden

and commit the resulting diff in the SAME commit as the change that caused it. The diff is
then the record of what your change did to the evaluation, which is exactly what belongs in
a report.
"""
from __future__ import annotations

import json
import pathlib
from typing import Any

GOLDEN_PATH = pathlib.Path(__file__).with_name("golden_rates.json")


def _rate(rows: list[dict], key: str) -> float:
    return round(sum(1 for r in rows if r[key]) / len(rows), 4) if rows else 0.0


def compute(records: list[dict]) -> dict[str, Any]:
    """Per-family detection and stop rates, plus the scenario counts.

    `stopped` on an attack family is leak prevention; on a benign family it is the false
    positive rate. Both are the same measurement, so they share a field and the family
    name tells you which claim it supports.
    """
    families: dict[str, Any] = {}
    for fam in sorted({r["family"] for r in records}):
        rows = [r for r in records if r["family"] == fam]
        families[fam] = {
            "n": len(rows),
            "is_attack": bool(rows[0]["oracle_attack"]),
            "detected": _rate(rows, "detected"),
            "stopped": _rate(rows, "stopped"),
        }
    return {
        "scenarios": len(records),
        "attacks": sum(1 for r in records if r["oracle_attack"]),
        "benign": sum(1 for r in records if not r["oracle_attack"]),
        "families": families,
    }


def load() -> dict[str, Any]:
    return json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))


def diff(current: dict[str, Any], golden: dict[str, Any]) -> list[str]:
    """Human-readable differences, empty when they match."""
    out: list[str] = []
    for k in ("scenarios", "attacks", "benign"):
        if current[k] != golden.get(k):
            out.append(f"{k}: {golden.get(k)} -> {current[k]}")
    cur_f, gold_f = current["families"], golden.get("families", {})
    for fam in sorted(set(cur_f) | set(gold_f)):
        if fam not in gold_f:
            out.append(f"{fam}: NEW family")
            continue
        if fam not in cur_f:
            out.append(f"{fam}: REMOVED")
            continue
        for field in ("n", "detected", "stopped"):
            if cur_f[fam][field] != gold_f[fam][field]:
                out.append(f"{fam}.{field}: {gold_f[fam][field]} -> {cur_f[fam][field]}")
    return out


def main() -> None:
    from demo_app.eval.runner import run_all

    current = compute(run_all(include_secrets=False))
    if GOLDEN_PATH.exists():
        changes = diff(current, load())
        print("\n".join(changes) if changes else "no change")
    GOLDEN_PATH.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print(f"wrote {GOLDEN_PATH}")


if __name__ == "__main__":
    main()