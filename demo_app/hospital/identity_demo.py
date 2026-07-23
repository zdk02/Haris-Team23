"""Per-agent identity demo (authentication — threat-model Problem F, task 9).

Haris verifies that a message really is from the agent it claims to be. A message carrying
the sender's issued token is accepted; a spoofed message (claiming to be record_reader but
without its token, or with a guessed one) is blocked — so "sender = A" is checked, not
self-declared.

Run:  python -m demo_app.hospital.identity_demo
"""
from __future__ import annotations

from haris.agents.identity import IdentityAgent
from haris.orchestrator.orchestrator import Orchestrator
from haris.schemas.decision import HarisBlocked
from haris.schemas.message import Message
from haris.schemas.policy import Mode, Policy
from haris.state.graph_store import GraphStateStore

# Tokens Haris issues to the trusted agents (a real deployment stores these securely).
TOKENS = {"record_reader": "rr-secret-9f2c", "summarizer": "sm-secret-4a71"}


def _msg(sender: str, token: str | None) -> Message:
    md = {"data_type": "PHI", "data_subject": "patient-A"}
    if token is not None:
        md["auth_token"] = token
    return Message(session_id="id-demo", sender=sender, receiver="summarizer",
                   content="PATIENT RECORD [patient-A] ...", metadata=md)


def main() -> None:
    import logging
    logging.disable(logging.INFO)

    orch = Orchestrator(GraphStateStore(), agents=[IdentityAgent(TOKENS)],
                        policy=Policy(mode=Mode.ENFORCE))
    print("=== Per-agent identity (authentication) — is this really Agent A? ===\n")

    d = orch.process(_msg("record_reader", TOKENS["record_reader"]))
    print(f"record_reader + its real token      -> {d.action.value.upper()}   (identity verified)")

    for label, token in [("no token", None), ("a guessed token", "totally-wrong")]:
        try:
            orch.process(_msg("record_reader", token))
            print(f"attacker spoofs record_reader ({label}) -> NOT BLOCKED (unexpected!)")
        except HarisBlocked as exc:
            reason = next((v.reason for v in exc.decision.verdicts
                           if v.agent_name == "identity"), exc.decision.reason)
            print(f"attacker spoofs record_reader ({label}) -> BLOCKED")
            print(f"    why: {reason}")

    print("\nWithout verified identity, an attacker could just label a message "
          "'from record_reader'\nand every relationship rule downstream would trust it. "
          "The token makes identity\nchecked, not self-declared.")


if __name__ == "__main__":
    main()
