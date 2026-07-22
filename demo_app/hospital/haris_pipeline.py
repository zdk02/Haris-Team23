"""The hospital app running end-to-end through Haris.

Step 4 wired the vulnerable hospital graph (Step 3) to the interception layer
(Step 2): every inter-agent hop flows Message -> Orchestrator -> Decision before
continuing. With ZERO agents in monitor mode that is a transparent pass-through
(`run_through_haris`) -- the app still leaks, but Haris sees and records every hop.

PHASE 3 (this module's `run_secured`) fills in the boxes: the SAME graph, the SAME
interception seam, but now the orchestrator holds all three real security agents
(Secrets/PII + Authorization + Information-flow) over the NetworkX GraphStateStore,
and the policy mode is configurable so enforce mode can block/redact for real. The
wiring here does NOT change between the two -- only the orchestrator's agent list,
state store, and mode do.

The two hops carry different fields, which is why each is wrapped with its own
message_key:
    record_reader --record(PHI)--> summarizer --summary--> emailer

Run:  pip install langgraph && python -m demo_app.hospital.haris_pipeline
"""
from __future__ import annotations

from typing import Any, Optional

from demo_app.hospital.app import (
    State, record_reader, summarizer, emailer,
    INTERNAL_DOCTOR, EXTERNAL_EXAMPLE,
)
from demo_app.interception import InterceptionAdapter
from demo_app.langgraph_interception import HarisLangGraph
from haris.agents.authorization import AuthorizationAgent
from haris.agents.infoflow import InformationFlowAgent
from haris.agents.secrets_pii import SecretsPIIAgent
from haris.orchestrator.orchestrator import Orchestrator
from haris.schemas.decision import HarisBlocked
from haris.schemas.policy import Mode, Policy
from haris.state.graph_store import GraphStateStore
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
    # authorization / subject-aware agents can see them.
    b.add_node("summarizer", haris.wrap(
        summarizer, "summarizer", "emailer",
        data_type="summary", message_key="summary",
        state_metadata_keys=["recipient", "subject"],
    ))
    # emailer is the sink -- it hands no message to a further agent, so it is not wrapped.
    b.add_node("emailer", emailer)

    b.add_edge(START, "record_reader")
    b.add_edge("record_reader", "summarizer")
    b.add_edge("summarizer", "emailer")
    b.add_edge("emailer", END)
    return b.compile(), haris


# --------------------------------------------------------------------------- #
# Phase 3: the real security stack wired into the live pipeline                #
# --------------------------------------------------------------------------- #

def build_hospital_agents(include_secrets: bool = True) -> list:
    """The canonical hospital agent line-up, in orchestrator order.

    Single source of truth for "which agents run in the hospital demo". Order affects
    only redaction composition + audit readability; the policy engine's most-restrictive
    rule is order-independent.

      1. SecretsPIIAgent    - Presidio/detect-secrets content scan (destination-agnostic).
                              Needs Presidio + the spaCy model; pass include_secrets=False
                              for a no-Presidio run (the other two still work).
      2. AuthorizationAgent - stateless relationship + external-egress check (TC5).
      3. InformationFlowAgent - lineage-based derived-leak / info-flow check (TC3),
                              conditioned on the PHI origin in the GraphStateStore.
    """
    agents: list = []
    if include_secrets:
        agents.append(SecretsPIIAgent())
    agents.append(AuthorizationAgent())
    agents.append(InformationFlowAgent())
    return agents


def run_secured(
    session_id: str,
    subject: str,
    recipient: str,
    *,
    leak: str = "identified",
    mode: Mode = Mode.ENFORCE,
    include_secrets: bool = True,
    thresholds: Optional[dict[str, float]] = None,
    agents: Optional[list] = None,
) -> dict[str, Any]:
    """Run one hospital scenario through the FULL secured pipeline.

    Same graph + same interception seam as `run_through_haris`, but the orchestrator
    now holds the three real agents over a `GraphStateStore`, in the requested mode.

    In enforce mode a BLOCK raises `HarisBlocked` inside the graph and halts it (the
    correct enforce semantics: the message never reaches the next node). We catch it so
    a caller gets a structured result instead of an exception.

    Returns a dict:
      final          -> final graph state, or None if a hop was blocked
      blocked        -> True if a hop was blocked in enforce mode
      block_decision -> the Decision that blocked (with its contributing verdicts), or None
      decisions      -> haris.decisions: the Decision for every hop that completed, in order
      store          -> the GraphStateStore (has .graph / lineage for the dashboard)
      haris          -> the HarisLangGraph wrapper (observability side-channel)
    """
    store = GraphStateStore()
    policy = Policy(mode=mode, thresholds=thresholds or {})
    agent_list = agents if agents is not None else build_hospital_agents(include_secrets)
    orchestrator = Orchestrator(state_store=store, agents=agent_list, policy=policy)
    graph, haris = build_haris_graph(orchestrator)

    final: Optional[dict] = None
    blocked = False
    block_decision = None
    try:
        final = graph.invoke({"session_id": session_id, "subject": subject,
                              "recipient": recipient, "leak": leak})
    except HarisBlocked as exc:      # enforce-mode block halts the graph -- expected
        blocked = True
        block_decision = exc.decision

    return {
        "final": final,
        "blocked": blocked,
        "block_decision": block_decision,
        "decisions": haris.decisions,
        "store": store,
        "haris": haris,
    }


def run_through_haris(session_id: str, subject: str, recipient: str,
                      leak: str = "identified",
                      policy: Optional[Policy] = None):
    """Run one hospital scenario through a DO-NOTHING Haris (zero agents, monitor).

    Kept unchanged as the Phase-1 pass-through spine (and the smoke-test fixture).
    For the real secured run, use `run_secured`. Returns (final_state, haris, store).
    """
    store = InMemoryStateStore()
    orchestrator = Orchestrator(state_store=store, agents=[], policy=policy)  # ZERO agents
    graph, haris = build_haris_graph(orchestrator)
    final = graph.invoke({"session_id": session_id, "subject": subject,
                          "recipient": recipient, "leak": leak})
    return final, haris, store


# --------------------------------------------------------------------------- #
# Demo                                                                          #
# --------------------------------------------------------------------------- #

def _presidio_available() -> bool:
    """True if the Secrets/PII agent's Presidio path is usable, so the demo runs
    everywhere: with Presidio we run all three agents; without it, the other two."""
    try:
        SecretsPIIAgent().pii.analyze("warm up")
        return True
    except Exception:
        return False


def _summarize_hop(decision) -> str:
    contributors = ", ".join(
        f"{v.agent_name}:{v.label.value}" for v in decision.verdicts) or "no agents"
    return f"action={decision.action.value} enforced={decision.enforced} [{contributors}]"


def main() -> None:
    import logging
    logging.basicConfig(level=logging.WARNING, format="%(message)s")

    include_secrets = _presidio_available()
    print("=== Hospital app through the SECURED Haris (all agents, ENFORCE) ===")
    print("    Secrets/PII agent:",
          "ON (Presidio available)" if include_secrets
          else "OFF (Presidio not installed) -- Authorization + Info-flow only", "\n")

    scenarios = [
        ("TC1  clean    -> internal", "patient-A", INTERNAL_DOCTOR, "clean"),
        ("TC2  verbatim -> external", "patient-A", EXTERNAL_EXAMPLE, "verbatim"),
        ("TC3  derived  -> external", "patient-A", EXTERNAL_EXAMPLE, "identified"),
        ("TC5  derived  -> internal", "patient-B", INTERNAL_DOCTOR, "identified"),
    ]
    for i, (label, subject, recipient, leak) in enumerate(scenarios):
        r = run_secured(f"demo-{i}", subject, recipient, leak=leak,
                        mode=Mode.ENFORCE, include_secrets=include_secrets)
        print(label)
        for hop, d in enumerate(r["decisions"], start=1):
            print(f"    hop{hop}  {_summarize_hop(d)}")
        if r["blocked"]:
            print(f"    hop{len(r['decisions']) + 1}  BLOCKED -- {_summarize_hop(r['block_decision'])}")
            print("    -> leak stopped; message never reached the recipient.")
        else:
            leaked = "MRN-0001" in (r["final"] or {}).get("sent", {}).get("body", "")
            print(f"    -> delivered to {recipient}; raw MRN present in body: {leaked}")
        print()


if __name__ == "__main__":
    main()
