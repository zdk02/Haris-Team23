"""One-command entry point for the simulation-based evaluation (Step 12 of the plan).

Runs the whole pipeline end-to-end — generate scenarios -> label with the independent
oracle -> run the three arms -> report + (optionally) export the metrics — with a fixed
seed so the numbers reproduce exactly.

    python -m demo_app.eval.simulate                 # print the report (Presidio off)
    python -m demo_app.eval.simulate --secrets       # add the Presidio Secrets/PII agent
    python -m demo_app.eval.simulate --json out.json # also write the metrics for the report

Presidio is off by default so the run is deterministic and dependency-free. Turning it on
adds the Secrets/PII agent's contribution (and raises latency toward the deck's ~11 ms).
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict

from demo_app.eval.runner import _rate, report, run_all


def summarize(records: list[dict]) -> dict:
    """Structured metrics for the report/figures (first-class Step 11 export)."""
    attacks = [r for r in records if r["oracle_attack"]]
    benign = [r for r in records if not r["oracle_attack"]]
    lat = sorted(x for r in records for x in r["latencies"])

    def group(key: str) -> dict:
        g: dict = defaultdict(list)
        for r in records:
            g[r[key]].append(r)
        out = {}
        for k, rs in g.items():
            atk = [r for r in rs if r["oracle_attack"]]
            ben = [r for r in rs if not r["oracle_attack"]]
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
        "detection_rate": round(_rate(attacks, "detected"), 4),
        "leak_prevention_rate": round(_rate(attacks, "stopped"), 4),
        "false_positive_rate": round(_rate(benign, "stopped"), 4),
        "latency_avg_ms": round(sum(lat) / len(lat), 4) if lat else 0.0,
        "latency_p95_ms": round(lat[min(len(lat) - 1, int(0.95 * len(lat)))], 4) if lat else 0.0,
        "by_leak_style": group("leak_style"),
        "by_domain": group("domain"),
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
