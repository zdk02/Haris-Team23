"""One-command entry point for the simulation-based evaluation (Step 12 of the plan).

Runs the whole pipeline end-to-end — generate scenarios -> label with the traffic-derived
label check -> run the arms -> report + (optionally) export the metrics — with a fixed
seed so the numbers reproduce exactly.

    python -m demo_app.eval.simulate                 # print the report (Presidio off)
    python -m demo_app.eval.simulate --secrets       # add the Presidio Secrets/PII agent
    python -m demo_app.eval.simulate --json out.json # also write the metrics for the report

Presidio is off by default so the run is deterministic and dependency-free. Turning it on
adds the Secrets/PII agent's contribution and raises latency from ~0.07 ms per hop to
~9.5 ms.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict

from demo_app.eval.runner import _rate, report, run_all


def summarize(records: list[dict]) -> dict:
    """Structured metrics for the report and figures.

    THE HEADLINE FIELDS ARE OUTCOME-BASED AND SPLIT IN TWO (task I5). This export used to
    emit a single `leak_prevention_rate` computed from `stopped` — the fraction of attack
    scenarios where some agent returned a blocking verdict. Two things were wrong with it.

    It counted VERDICTS rather than outcomes, so a message that was flagged and partially
    redacted scored as prevented even though an identifier still reached the recipient
    (four scenarios do exactly that; see report/RESULTS.md §6). And it pooled two
    different claims: data leaving the trust boundary, and one patient's record reaching
    the wrong workflow with nothing leaving at all. A reader hearing "leak prevention"
    understands the first, and a sixth of the denominator was the second.

    The result was a JSON file reporting 87.5% from the same run where the runner printed
    76% and 100%. Two headline numbers in one repository, and whichever a reader found
    first, the other contradicted it. The fields below match what
    `demo_app/eval/runner.py` prints, so the two agree by construction.

    `leak_prevention_rate` is kept, marked, and defined as the verdict-based figure it
    always was — deleting it would silently change the meaning of any older snapshot
    somebody still has.
    """
    attacks = [r for r in records if r["label_attack"]]
    benign = [r for r in records if not r["label_attack"]]
    lat = sorted(x for r in records for x in r["latencies"])

    # The two claims, each over its own denominator. `leak_unmediated` marks the
    # scenarios that actually leak when nothing intervenes; `egresses` splits them by
    # whether anything left the trust boundary.
    exfil = [r for r in attacks if r["leak_unmediated"] and r["egresses"]]
    boundary = [r for r in attacks if r["leak_unmediated"] and not r["egresses"]]

    def prevented(rows: list[dict]) -> float | None:
        if not rows:
            return None
        return round(sum(1 for r in rows if not r["leak_haris"]) / len(rows), 4)

    def group(key: str) -> dict:
        g: dict = defaultdict(list)
        for r in records:
            g[r[key]].append(r)
        out = {}
        for k, rs in g.items():
            atk = [r for r in rs if r["label_attack"]]
            ben = [r for r in rs if not r["label_attack"]]
            out[k] = {
                "n": len(rs),
                "detection": round(_rate(atk, "detected"), 4) if atk else None,
                "prevention": round(_rate(atk, "stopped"), 4) if atk else None,
                "false_positive": round(_rate(ben, "stopped"), 4) if ben else None,
            }
        return out

    return {
        "scenarios": len(records),
        "attacks": len(attacks),
        "benign": len(benign),

        # --- the headline, matching runner.py ---
        "exfiltration_prevented": prevented(exfil),
        "exfiltration_n": len(exfil),
        "boundary_crossings_caught": prevented(boundary),
        "boundary_crossings_n": len(boundary),
        "detection_rate": round(_rate(attacks, "detected"), 4),
        "false_positive_rate": round(_rate(benign, "stopped"), 4),
        "utility_rate": round(1 - _rate(benign, "stopped"), 4),
        "latency_avg_ms": round(sum(lat) / len(lat), 4) if lat else 0.0,
        "latency_p95_ms": round(lat[min(len(lat) - 1, int(0.95 * len(lat)))], 4) if lat else 0.0,

        # Verdict-based, kept for continuity with snapshots taken before task I5 and
        # named so nobody mistakes it for the headline. It counts a scenario as prevented
        # when an agent said "block" or "redact", whether or not an identifier still
        # reached the recipient, and it pools exfiltration with boundary crossings.
        "leak_prevention_rate_verdict_based": round(_rate(attacks, "stopped"), 4),

        "by_leak_style": group("leak_style"),
        "by_domain": group("domain"),
        "by_topology": group("topology"),
        "by_difficulty": {k: v for k, v in group("difficulty").items() if k},
        "by_family": group("family"),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the Haris simulation-based evaluation.")
    ap.add_argument("--secrets", action="store_true",
                    help="enable the Presidio Secrets/PII agent (needs the spaCy model)")
    ap.add_argument("--json", metavar="PATH",
                    help="write the metrics summary to a JSON file for the report/figures")
    args = ap.parse_args()

    import logging
    logging.disable(logging.INFO)

    print(f"Haris — simulation-based evaluation  "
          f"(Presidio {'ON' if args.secrets else 'OFF'}, fixed seed)\n")
    records = run_all(include_secrets=args.secrets)
    report(records)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(summarize(records), f, indent=2)
        print(f"\nwrote metrics summary -> {args.json}")


if __name__ == "__main__":
    main()
