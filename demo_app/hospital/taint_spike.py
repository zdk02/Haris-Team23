"""Step 5 SPIKE (runnable): coarse data-lineage / taint tracking, measured honestly.

Registers the InformationFlowAgent in the real hospital pipeline and runs the
threat-model cases through it, printing a scorecard of what taint-by-lineage CATCHES
versus what a naive whole-record scanner catches. The point of a spike is an honest
answer, so the semantic-paraphrase false negative is printed too.

Run:  pip install langgraph && python -m demo_app.hospital.taint_spike
"""
from __future__ import annotations

from demo_app.hospital.app import (
    EXTERNAL_EXAMPLE, format_record, record_reader, summarizer,
)
from demo_app.hospital.records import load_record
from demo_app.hospital.haris_pipeline import build_haris_graph
from haris.agents.infoflow import InformationFlowAgent
from haris.orchestrator.orchestrator import Orchestrator
from haris.schemas.policy import Mode, Policy
from haris.state.graph_store import GraphStateStore


def _raw_summary(subject: str, leak: str) -> str:
    """The summary as the summarizer produced it, BEFORE Haris touches it -- this is
    what a naive per-message scanner would actually see."""
    state = {"subject": subject}
    state.update(record_reader(state))
    state.update(summarizer({**state, "leak": leak}))
    return state["summary"]

CASES = [
    ("TC1 clean",      "patient-A", "clean"),
    ("TC2 verbatim",   "patient-A", "verbatim"),
    ("TC3 identified", "patient-A", "identified"),
    ("paraphrase",     "patient-A", "paraphrase"),
]


def _run(name: str, subject: str, leak: str):
    store = GraphStateStore()
    orch = Orchestrator(store, agents=[InformationFlowAgent()],
                        policy=Policy(mode=Mode.ENFORCE))
    graph, haris = build_haris_graph(orch)
    final = graph.invoke({"session_id": name, "subject": subject,
                          "recipient": EXTERNAL_EXAMPLE, "leak": leak})
    summary_decision = haris.decisions[-1]        # the summarizer -> emailer hop
    record_text = format_record(load_record(subject))
    # Baseline runs on the RAW summary (pre-Haris), not the delivered one -- otherwise
    # we'd be scanning content Haris already redacted and understate the baseline.
    naive_catch = record_text.strip() in _raw_summary(subject, leak)
    return final, summary_decision, naive_catch


def main() -> None:
    print("Step 5 spike -- taint-by-lineage vs naive whole-record scan (enforce mode)\n")
    print(f"{'case':16} {'taint':10} {'naive':8} action")
    delivered_tc3 = None
    for name, subject, leak in CASES:
        final, decision, naive = _run(name, subject, leak)
        taint = "CATCH" if decision.action.value != "allow" else "pass"
        print(f"{name:16} {taint:10} {('CATCH' if naive else 'miss'):8} "
              f"{decision.action.value}")
        if name.startswith("TC3"):
            delivered_tc3 = final["sent"]["body"]

    print("\nWhat actually reached the emailer for TC3 (redacted by info-flow):")
    print("  " + (delivered_tc3 or "").replace("\n", "\n  "))
    print("\nReading: TC3 is the flagship -- taint CATCHES it, the naive scanner "
          "MISSES it. TC1 stays clean (no false positive). 'paraphrase' is the "
          "honest ceiling: the condition leaks semantically with no exact identifier "
          "token, so coarse taint misses it -> roadmap semantic agent.")


if __name__ == "__main__":
    main()