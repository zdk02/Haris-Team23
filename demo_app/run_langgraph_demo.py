"""Step 2 milestone: a real 2-node LangGraph graph, every hop through real Haris.

This is the LangGraph counterpart of run_demo.py. Where run_demo.py pushed one
hand-built Message through the adapter, this builds an actual compiled LangGraph
graph (agent_a -> agent_b) and lets Haris intercept every inter-node message via
the same InterceptionAdapter -> Orchestrator -> Decision spine.

The orchestrator here has ZERO agents and runs in monitor mode, so nothing is
blocked or changed -- this proves the plumbing. In Step 4 the same graph shape is
replaced by the hospital app and the orchestrator gains real agents; nothing about
the interception layer changes.

Run:  pip install langgraph && python -m demo_app.run_langgraph_demo
"""
from __future__ import annotations

import logging
from typing import TypedDict

from langgraph.graph import StateGraph, START, END

from demo_app.interception import InterceptionAdapter
from demo_app.langgraph_interception import HarisLangGraph
from haris.orchestrator.orchestrator import Orchestrator
from haris.state.memory import InMemoryStateStore


class State(TypedDict):
    session_id: str
    message: str


def agent_a(state: State) -> dict:
    # A stand-in agent. In Step 3 this becomes record_reader reading a real record.
    return {"message": "hello from A -- SECRET=sk-12345"}


def agent_b(state: State) -> dict:
    # A stand-in agent. In Step 3 this becomes summarizer / emailer.
    return {"message": f"B received <{state['message']}> and forwards a summary"}


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    store = InMemoryStateStore()
    orchestrator = Orchestrator(state_store=store, agents=[])  # zero agents, monitor
    haris = HarisLangGraph(InterceptionAdapter(orchestrator))

    builder = StateGraph(State)
    builder.add_node("agent_a", haris.wrap(agent_a, "agent_a", "agent_b", data_type="PHI"))
    builder.add_node("agent_b", haris.wrap(agent_b, "agent_b", "emailer", data_type="summary"))
    builder.add_edge(START, "agent_a")
    builder.add_edge("agent_a", "agent_b")
    builder.add_edge("agent_b", END)
    graph = builder.compile()

    final = graph.invoke({"session_id": "demo-1", "message": ""})

    print("\n--- result ---")
    print("final message:", final["message"])
    print("hops Haris saw:", [(d.action.value, d.enforced) for d in haris.decisions])
    print("lineage length:", len(store.get_lineage("demo-1")))
    print("passed through unchanged:", "sk-12345" in final["message"])


if __name__ == "__main__":
    main()