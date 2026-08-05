"""Three-arm runner + first-cut metrics (Steps 9 and 11 of the plan).

Runs every generated scenario through Haris three ways and compares the result against the
independent oracle:

  * no-Haris  (agents=[], monitor)   -> baseline: nothing is stopped (the app leaks).
  * monitor   (agents, MONITOR)      -> DETECTION: did any agent raise a concern (flag/block)?
  * enforce   (agents, ENFORCE)      -> PREVENTION: was the message actually blocked/redacted?

Then it reports, overall and broken down by leak-style / domain / family:
  * detection rate       (of oracle-attacks, fraction detected in monitor)
  * leak-prevention rate (of oracle-attacks, fraction stopped in enforce)
  * false-positive rate  (of oracle-benign, fraction wrongly stopped in enforce)
  * latency              (avg + p95 per hop, from the tamper-evident audit log)

Presidio is OFF by default so the run is deterministic and dependency-free (Info-flow's
structured taint carries verbatim/derived/credential). Pass include_secrets=True on a box
with the spaCy model to add the Secrets/PII agent's contribution.

Run:  python -m demo_app.eval.runner
"""
from __future__ import annotations

from collections import defaultdict

from haris.audit import AuditLog
from haris.orchestrator.orchestrator import Orchestrator
from haris.schemas.decision import HarisBlocked
from haris.schemas.policy import Mode, Policy
from haris.state.graph_store import GraphStateStore

from demo_app.eval.domains import DOMAINS, build_agents
from demo_app.eval.generate import Scenario, generate
from demo_app.eval.oracle import oracle_should_stop

STOPPED = {"block", "redact"}


def _run_arm(scn: Scenario, agents: list, mode: Mode, want_latency: bool = False):
    """Return (stopped, detected, latencies) for one scenario under one arm."""
    audit = AuditLog() if want_latency else None
    orch = Orchestrator(GraphStateStore(), agents=agents,
                        policy=Policy(mode=mode), audit_log=audit)
    stopped = detected = False
    for m in scn.messages:
        try:
            d = orch.process(m)
            if d.action.value in STOPPED:
                stopped = True
            if any(v.label.name != "PASS" for v in d.verdicts):
                detected = True
        except HarisBlocked:          # enforce-mode block halts the flow (correct semantics)
            stopped = detected = True
            break
    latencies = [r.latency_ms for r in audit.records()] if audit else []
    return stopped, detected, latencies


def run_scenario(scn: Scenario, include_secrets: bool = False) -> dict:
    agents = build_agents(DOMAINS[scn.domain], include_secrets)
    oracle_attack, _ = oracle_should_stop(scn)
    none_stopped, _, _ = _run_arm(scn, [], Mode.MONITOR)               # baseline
    _, detected, _ = _run_arm(scn, agents, Mode.MONITOR)              # detection
    stopped, _, lat = _run_arm(scn, agents, Mode.ENFORCE, want_latency=True)  # prevention
    return {
        "id": scn.id, "domain": scn.domain, "topology": scn.topology,
        "family": scn.family, "leak_style": scn.leak_style,
        "oracle_attack": oracle_attack,
        "baseline_stopped": none_stopped, "detected": detected, "stopped": stopped,
        "latencies": lat,
    }


def run_all(include_secrets: bool = False) -> list[dict]:
    scenarios = generate()
    # small warm-up so reported latency is steady-state, not cold-start
    for scn in scenarios[:5]:
        _run_arm(scn, build_agents(DOMAINS[scn.domain], include_secrets), Mode.ENFORCE, True)
    return [run_scenario(scn, include_secrets) for scn in scenarios]


# --------------------------------------------------------------------------- #
# Metrics (first cut of Step 11)
# --------------------------------------------------------------------------- #

def _rate(rows, key) -> float:
    return (sum(1 for r in rows if r[key]) / len(rows)) if rows else 0.0


def _pct(x) -> str:
    return f"{x*100:.0f}%"


def report(records: list[dict]) -> None:
    attacks = [r for r in records if r["oracle_attack"]]
    benign = [r for r in records if not r["oracle_attack"]]
    all_lat = sorted(x for r in records for x in r["latencies"])

    baseline_leaks = sum(1 for r in attacks if not r["baseline_stopped"])  # == len(attacks)
    prevented = sum(1 for r in attacks if r["stopped"])

    print(f"scenarios: {len(records)}  (attacks {len(attacks)} · benign {len(benign)})\n")
    print("HEADLINE")
    print(f"  without Haris : {baseline_leaks}/{len(attacks)} attacks leak "
          f"({_pct(baseline_leaks/len(attacks))})")
    print(f"  with Haris    : {prevented}/{len(attacks)} stopped  -> "
          f"leak-prevention {_pct(prevented/len(attacks))}")
    print(f"  detection     : {_pct(_rate(attacks, 'detected'))}  (monitor arm)")
    print(f"  false positive: {_pct(_rate(benign, 'stopped'))}  "
          f"({sum(1 for r in benign if r['stopped'])}/{len(benign)} benign wrongly stopped)")
    if all_lat:
        p95 = all_lat[min(len(all_lat) - 1, int(0.95 * len(all_lat)))]
        print(f"  latency/hop   : {sum(all_lat)/len(all_lat):.2f} ms avg · {p95:.2f} ms p95")

    def breakdown(title, key, rows):
        print(f"\n{title}")
        groups = defaultdict(list)
        for r in rows:
            groups[r[key]].append(r)
        for g in sorted(groups):
            rs = groups[g]
            atk = [r for r in rs if r["oracle_attack"]]
            ben = [r for r in rs if not r["oracle_attack"]]
            det = _pct(_rate(atk, "detected")) if atk else "—"
            prev = _pct(_rate(atk, "stopped")) if atk else "—"
            fp = _pct(_rate(ben, "stopped")) if ben else "—"
            print(f"  {str(g):<20} detect={det:<5} prevent={prev:<5} fp={fp:<5} (n={len(rs)})")

    breakdown("BY LEAK STYLE  (paraphrase = the honest gap)", "leak_style", records)
    breakdown("BY DOMAIN  (consistency = generalization)", "domain", records)
    breakdown("BY FAMILY", "family", records)


if __name__ == "__main__":
    import logging
    logging.disable(logging.INFO)
    report(run_all(include_secrets=False))
