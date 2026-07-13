"""Step 4: the hospital app running end-to-end through Haris.

This is the milestone that turns everything into "fill in the boxes". It takes the
vulnerable hospital graph from Step 3 and the interception layer from Step 2 and
wires them together: every inter-agent hop now flows Message -> Orchestrator ->
Decision before continuing.

With an orchestrator that has ZERO agents in monitor mode, nothing is blocked or
changed -- the hospital app behaves identically (it still leaks), but Haris now sees
and records every message. That is the pass-through spine. Later steps only add
agents to the orchestrator; NONE of the wiring here changes.

The two hops carry different fields, which is why each is wrapped with its own
message_key:
    record_reader --record(PHI)--> summarizer --summary--> emailer

Run:  pip install langgraph && python -m demo_app.hospital.haris_pipeline
"""
from __future__ import annotations

from typing import Optional

from demo_app.hospital.app import (
    State, record_reader, summarizer, emailer,
    INTERNAL_DOCTOR, EXTERNAL_EXAMPLE,
)
from demo_app.interception import InterceptionAdapter
from demo_app.langgraph_interception import HarisLangGraph
from haris.orchestrator.orchestrator import Orchestrator
from haris.schemas.policy import Policy
from haris.state.memory import InMemoryStateStore


def build_haris_graph(orchestrator: Orchestrator):
    """Compile the hospital graph with Haris wrapped around each inter-agent hop.

    Returns (compiled_graph, haris) so callers can inspect haris.decisions after a run.
    """
    from langgraph.graph import StateGraph, START, END

    haris = HarisLangGraph(InterceptionAdapter(orchestrator))

    b = StateGraph(State)
    # hop 1: record_reader emits `record` (PHI) to summarizer
    b.add_node("record_reader", haris.wrap(
        record_reader, "record_reader", "summarizer",
        data_type="PHI", message_key="record",
        state_metadata_keys=["subject"],
    ))
    # hop 2: summarizer emits `summary` to emailer; carry recipient + subject so the
    # authorization / subject-aware agents (added later) can see them.
    b.add_node("summarizer", haris.wrap(
        summarizer, "summarizer", "emailer",
        data_type="summary", message_key="summary",
        state_metadata_keys=["recipient", "subject"],
    ))
    # emailer is the sink -- it does not hand a message to a further agent, so it is
    # not wrapped. (Whether a send to an external address is allowed is an
    # authorization-agent concern in a later step, not part of the pass-through spine.)
    b.add_node("emailer", emailer)

    b.add_edge(START, "record_reader")
    b.add_edge("record_reader", "summarizer")
    b.add_edge("summarizer", "emailer")
    b.add_edge("emailer", END)
    return b.compile(), haris


def run_through_haris(session_id: str, subject: str, recipient: str,
                      leak: str = "identified",
                      policy: Optional[Policy] = None):
    """Run one hospital scenario through a do-nothing Haris. Returns (final_state, haris, store)."""
    store = InMemoryStateStore()
    orchestrator = Orchestrator(state_store=store, agents=[], policy=policy)  # ZERO agents
    graph, haris = build_haris_graph(orchestrator)
    final = graph.invoke({"session_id": session_id, "subject": subject,
                          "recipient": recipient, "leak": leak})
    return final, haris, store


def main() -> None:
    import logging
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    print("=== Hospital app through a do-nothing Haris (zero agents, monitor) ===\n")
    final, haris, store = run_through_haris(
        "demo-1", "patient-A", EXTERNAL_EXAMPLE, leak="verbatim")

    print("\n--- what Haris observed ---")
    for d in haris.decisions:
        print(f"  action={d.action.value}  enforced={d.enforced}")
    print("hops intercepted:", len(haris.decisions))
    print("lineage recorded:", len(store.get_lineage("demo-1")))
    print("app still leaked (monitor mode never blocks):",
          "MRN-0001" in final["sent"]["body"])
    print("\nNothing was blocked -- monitor mode is safe. Haris saw every hop. "
          "Add agents to the orchestrator and the boxes fill in.")


if __name__ == "__main__":
    main()