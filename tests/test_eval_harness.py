"""The evaluation harness itself is CI-checked: every staged attack is caught and no
benign flow is disturbed. Runs without Presidio (include_secrets=False) so it's
deterministic and needs no spaCy model."""
from __future__ import annotations

from demo_app.hospital.eval_harness import run_evaluation


def test_all_covered_attacks_caught_and_no_false_positives():
    r = run_evaluation(include_secrets=False)
    missed = [c["id"] for c in r["cases"] if c["is_attack"] and not c["stopped"]]
    false_pos = [c["id"] for c in r["cases"] if not c["is_attack"] and c["stopped"]]
    assert r["detection_rate"] == 1.0, f"attacks that slipped through: {missed}"
    assert r["false_positive_rate"] == 0.0, f"benign flows wrongly stopped: {false_pos}"


def test_metrics_and_audit_are_well_formed():
    r = run_evaluation(include_secrets=False)
    assert r["messages_measured"] > 0
    assert r["latency_avg_ms"] >= 0.0 and r["latency_p95_ms"] >= 0.0
    assert r["audit_chain_intact"] is True          # the eval run is itself auditable
    assert r["tp"] + r["fn"] == 5 and r["fp"] + r["tn"] == 4   # 5 staged attacks, 4 benign
