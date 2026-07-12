"""Milestone check: one real message flows end-to-end through a do-nothing Haris."""
from __future__ import annotations

import logging

from demo_app.interception import InterceptionAdapter
from haris.orchestrator.orchestrator import Orchestrator
from haris.state.memory import InMemoryStateStore


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    store = InMemoryStateStore()
    orchestrator = Orchestrator(state_store=store, agents=[])  # zero agents
    haris = InterceptionAdapter(orchestrator)

    original = "Patient Jane Doe, DOB 1980-01-01, summary of visit ..."
    delivered, decision = haris.intercept(
        session_id="demo-1",
        sender="record_reader",
        receiver="summarizer",
        content=original,
    )

    print("\n--- result ---")
    print("action:", decision.action.value, "| enforced:", decision.enforced)
    print("passed through unchanged:", delivered == original)
    print("lineage length:", len(store.get_lineage("demo-1")))


if __name__ == "__main__":
    main()
