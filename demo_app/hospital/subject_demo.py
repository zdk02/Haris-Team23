"""Data-subject authorization demo (threat-model TC4).

Haris allows patient A's record to flow in patient A's session, but BLOCKS patient B's
record from leaking into it. This is the differentiator a per-agent guardrail cannot do:
the block depends on WHOSE data this is versus whose case the session is about — not on
the agents involved or the data_type.

The base hospital app is single-patient, so the mixed-patient case is staged here through
the real Orchestrator + GraphStateStore (the same way the dashboard and the integration
tests stage scenarios). No Presidio/langgraph needed.

Run:  python -m demo_app.hospital.subject_demo
"""
from __future__ import annotations

from demo_app.hospital.haris_pipeline import build_hospital_agents
from demo_app.hospital.records import format_record, load_record
from haris.orchestrator.orchestrator import Orchestrator
from haris.schemas.decision import HarisBlocked
from haris.schemas.message import Message
from haris.schemas.policy import Mode, Policy
from haris.state.graph_store import GraphStateStore


def _phi(session_id: str, subject: str) -> Message:
    return Message(session_id=session_id, sender="record_reader", receiver="summarizer",
                   content=format_record(load_record(subject)),
                   metadata={"data_type": "PHI", "data_subject": subject})


def main() -> None:
    import logging
    logging.disable(logging.INFO)   # keep the demo output clean

    store = GraphStateStore()
    orch = Orchestrator(store, agents=build_hospital_agents(include_secrets=False),
                        policy=Policy(mode=Mode.ENFORCE))
    session = "case-patient-A"

    print("=== Data-subject authorization (TC4) — this session is about patient-A ===\n")

    # 1. Patient A's own record enters patient A's session -> allowed (binds the session).
    d = orch.process(_phi(session, "patient-A"))
    print(f"patient-A's record -> patient-A's session : {d.action.value.upper()}  (allowed — session now bound to patient-A)")

    # 2. Patient B's record tries to enter the SAME session -> blocked.
    try:
        orch.process(_phi(session, "patient-B"))
        print("patient-B's record -> patient-A's session : NOT BLOCKED  (unexpected!)")
    except HarisBlocked as exc:
        reason = next((v.reason for v in exc.decision.verdicts
                       if v.agent_name == "subject_binding"), exc.decision.reason)
        print("patient-B's record -> patient-A's session : BLOCKED")
        print(f"    why: {reason}")

    print("\nHaris bound the session to patient-A on the first record, then blocked "
          "patient-B's\ndata from entering it — an instance-level authorization decision "
          "a per-agent\nguardrail cannot make.")


if __name__ == "__main__":
    main()
