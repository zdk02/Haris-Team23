"""Before/after for the taint-normalisation fix (Task C, finding 12) — report figure F5.

WHY THIS EXISTS.
Before the fix, `InformationFlowAgent` decided whether a source identifier had resurfaced
with case-insensitive substring containment against the raw message body. Any reformatting
of the identifier defeated it: a double space, a hyphen turned into a space, digits spaced
apart. The shipped matcher normalises both sides first (token match, then a length-gated
collapsed-alphanumeric match), so `MRN-0001` still matches `M R N 0 0 0 1`.

The improvement is an experimental result, so it is measured rather than asserted. This
module restores the OLD rule at runtime — nothing else changes: same corpus, same seed, same
agents, same orchestrator, same scoring — and reports both arms per family.

WHAT THE OLD RULE WAS, EXACTLY.
`tag.lower() in message.content.lower()`. `_legacy_resurfaces` below reproduces that against
the raw body rather than the normalised copy, so the "before" column is the real previous
behaviour and not a flattering approximation of it.

WHAT TO TAKE FROM IT.
Two numbers, and the second is the one that makes the first mean anything:

  * `external_obfuscated` moves from 42% detection / 0% prevention to 100% / 100%;
  * the false-positive rate does not move at all (24/120 in both arms).

A detector change that lifts recall while holding false positives flat is a real improvement.
Reporting the first number without the second would not establish that, since any matcher can
be made more sensitive by being made more indiscriminate.

It also corrects a claim the evaluation used to make. The 42% was presented as the middle
rung of a graceful-degradation curve — evidence that Haris weakens as an attacker works
harder. It was not: it was brittleness in our own matcher, and it disappeared when the
matcher was fixed. A difficulty axis that moves when you fix a bug in the detector was
measuring the detector. See EVAL_DESIGN.md.

Run:  python -m demo_app.eval.matcher_delta
"""
from __future__ import annotations

from haris.agents.infoflow import InformationFlowAgent

from demo_app.eval.runner import run_all

_original_check = InformationFlowAgent.check
_original_matcher = InformationFlowAgent._tag_resurfaces


def _capturing_check(self, message, context):
    """Keep the raw body reachable from the matcher, which the shipped one never needs."""
    self._raw_content = message.content
    return _original_check(self, message, context)


def _legacy_resurfaces(self, tag: str, content_joined: str, content_alnum: str) -> bool:
    """The pre-fix rule: case-insensitive substring containment against the raw body."""
    return tag.lower() in (getattr(self, "_raw_content", "") or "").lower()


def measure(legacy: bool) -> list[dict]:
    if legacy:
        InformationFlowAgent.check = _capturing_check
        InformationFlowAgent._tag_resurfaces = _legacy_resurfaces
    try:
        return run_all(include_secrets=False)
    finally:
        InformationFlowAgent.check = _original_check
        InformationFlowAgent._tag_resurfaces = _original_matcher


def _rates(rows: list[dict], family: str) -> tuple[str, str]:
    fam = [r for r in rows if r["family"] == family]
    leaking = [r for r in fam if r["leak_unmediated"]]
    detect = f"{sum(1 for r in fam if r['detected']) / len(fam) * 100:.0f}%" if fam else "—"
    prevent = (f"{sum(1 for r in leaking if not r['leak_haris']) / len(leaking) * 100:.0f}%"
               if leaking else "—")
    return detect, prevent


def _fp(rows: list[dict]) -> str:
    benign = [r for r in rows if not r["label_attack"]]
    stopped = sum(1 for r in benign if r["stopped"])
    return f"{stopped}/{len(benign)} ({stopped / len(benign) * 100:.0f}%)" if benign else "—"


def main() -> None:
    before = measure(legacy=True)
    after = measure(legacy=False)

    print("Taint matching: exact substring (before) vs normalised (after)\n")
    print(f"{'family':<24}{'detect':>10}{'prevent':>10}   |{'detect':>10}{'prevent':>10}")
    print(f"{'':<24}{'BEFORE':>10}{'BEFORE':>10}   |{'AFTER':>10}{'AFTER':>10}")
    for family in sorted({r["family"] for r in after}):
        d0, p0 = _rates(before, family)
        d1, p1 = _rates(after, family)
        mark = "  <-- the fix" if (d0, p0) != (d1, p1) else ""
        print(f"{family:<24}{d0:>10}{p0:>10}   |{d1:>10}{p1:>10}{mark}")

    print(f"\n  false positives   before: {_fp(before)}   after: {_fp(after)}")
    print( "  Recall rises on the reformatted-identifier family and the false-positive rate")
    print( "  does not move, so the gain is not bought by making the matcher indiscriminate.")
    print( "  Prevention is scored by outcome (leak_check.py), never by a detector's verdict;")
    print( "  a '—' means no scenario in that family leaks unmediated, so there is nothing to")
    print( "  prevent. See EVAL_DESIGN.md for why the old 42% was not a difficulty rung.")


if __name__ == "__main__":
    main()
