"""Latency NFR report — how much delay Haris adds per inter-agent hop.

Runs the threat battery through the full agent stack and prints the average and p95
latency Haris adds per message. A warm-up pass runs first (inside run_battery), so the
number reflects steady-state overhead, not the one-time Presidio/spaCy model load — an
honest figure for the performance non-functional requirement.

Run:  python -m demo_app.hospital.latency_report
"""
from __future__ import annotations

from demo_app.dashboard_data import (
    _display_records, compute_kpis, presidio_available, run_battery,
)
from haris.schemas.policy import Mode


def main() -> None:
    import logging
    logging.disable(logging.INFO)

    include_secrets = presidio_available()
    audit = run_battery(Mode.ENFORCE, include_secrets=include_secrets)
    records = _display_records(audit)
    k = compute_kpis(records)
    latencies = [r["latency_ms"] for r in records]

    stack = ("Secrets/PII + Authorization + Data-Subject + Info-Flow" if include_secrets
             else "Authorization + Data-Subject + Info-Flow (Presidio off)")
    print("=== Haris latency — steady-state overhead added per inter-agent hop ===")
    print(f"  agent stack       : {stack}")
    print(f"  messages measured : {k['inspected']}")
    print(f"  avg latency / hop : {k['latency_avg_ms']:.2f} ms")
    print(f"  p95 latency / hop : {k['latency_p95_ms']:.2f} ms")
    print(f"  min / max         : {min(latencies):.2f} / {max(latencies):.2f} ms")
    print(f'\n  For the evaluation table: "Haris adds ~{k["latency_avg_ms"]:.1f} ms per '
          f'inter-agent message (p95 {k["latency_p95_ms"]:.1f} ms)."')


if __name__ == "__main__":
    main()
