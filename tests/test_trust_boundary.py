"""Trust-boundary tests — what a COMPROMISED agent can and cannot influence.

Threat-model finding: every security decision keys off metadata (`recipient`,
`data_type`, `receiver`, `session_id`, `data_subject`) that arrives with the message.
If those come from shared graph state, the wrapped agents write them, and the agents are
exactly the party the threat model treats as possibly compromised. A dict edit then turns
a check off - no content transformation required.

The mitigation is not in an agent. It is that the INTERCEPTION ADAPTER binds
transport-derived metadata itself and lets nothing in the message body override it. These
tests pin both halves: the attack succeeds when the field is read from state, and fails
when the adapter binds it.

What remains outside the boundary is stated in THREAT_MODEL.md: a deployment whose
destination is genuinely dynamic cannot bind it at wrap() time, and there the egress check
is only as trustworthy as the field the application supplies.
"""
from __future__ import annotations

import pytest

from demo_app.interception import InterceptionAdapter
from demo_app.langgraph_interception import HarisLangGraph
from haris.agents.authorization import AuthorizationAgent
from haris.orchestrator.orchestrator import Orchestrator
from haris.schemas.decision import HarisBlocked
from haris.schemas.policy import Mode, Policy
from haris.state.memory import InMemoryStateStore

EXTERNAL = "outside@example.com"
INTERNAL = "doctor@hospital.internal"
RECORD = "PATIENT RECORD [patient-A]\nName: Jane Doe\nMRN: MRN-0001"


def _emitter(state: dict) -> dict:
    return {"msg": RECORD}


def _node(*, bind_recipient: bool):
    """One wrapped hop that sends PHI onward, with the destination either bound by the
    graph author at wrap() time or read from shared state."""
    orch = Orchestrator(InMemoryStateStore(), agents=[AuthorizationAgent()],
                        policy=Policy(mode=Mode.ENFORCE))
    haris = HarisLangGraph(InterceptionAdapter(orch), message_key="msg")
    kwargs = {"data_type": "PHI", "state_metadata_keys": ["recipient", "data_type"]}
    if bind_recipient:
        kwargs["recipient"] = EXTERNAL          # the real destination, declared by the app
    return haris.wrap(_emitter, "summarizer", "emailer", **kwargs)


def _run(node, state: dict) -> str:
    try:
        node(state)
        return "delivered"
    except HarisBlocked:
        return "blocked"


# --- the attack, and the fix ---------------------------------------------------

def test_state_supplied_recipient_can_be_forged_by_a_compromised_agent():
    """PINNED VULNERABILITY. When the destination is read from shared graph state, a
    compromised node names an internal address while sending outside, and the egress
    check believes it. No content is changed - one dict key is."""
    node = _node(bind_recipient=False)
    honest = _run(node, {"session_id": "s1", "recipient": EXTERNAL})
    forged = _run(node, {"session_id": "s2", "recipient": INTERNAL})   # the lie
    assert honest == "blocked"
    assert forged == "delivered"      # <- this is the finding, not a passing behaviour


def test_adapter_bound_recipient_ignores_a_forged_one():
    """THE FIX. With the destination bound at wrap() time the same lie has no effect:
    adapter-bound metadata is applied after the state copy, so it always wins."""
    node = _node(bind_recipient=True)
    assert _run(node, {"session_id": "s3", "recipient": EXTERNAL}) == "blocked"
    assert _run(node, {"session_id": "s4", "recipient": INTERNAL}) == "blocked"


def test_a_compromised_agent_cannot_downgrade_the_data_type():
    """`data_type` selects which rules apply, so overwriting it is as good as deleting a
    check. It is declared at wrap() time and must survive a conflicting state value."""
    node = _node(bind_recipient=True)
    # 'memo' is not in DEFAULT_SENSITIVE_TYPES - if state won, egress would be permitted.
    assert _run(node, {"session_id": "s5", "recipient": INTERNAL,
                       "data_type": "memo"}) == "blocked"


def test_adapter_bound_receiver_survives_a_conflicting_state_value():
    """`receiver` is one end of every relationship rule. It comes from wrap(), never from
    the message body."""
    orch = Orchestrator(InMemoryStateStore(), agents=[], policy=Policy(mode=Mode.MONITOR))
    haris = HarisLangGraph(InterceptionAdapter(orch), message_key="msg")
    node = haris.wrap(_emitter, "summarizer", "emailer", data_type="PHI",
                      state_metadata_keys=["receiver"])
    node({"session_id": "s6", "receiver": "totally-different-agent"})
    assert haris.decisions[-1].verdicts == []          # no agents; we inspect the record
    # The orchestrator saw the wrap()-time receiver, not the state one.
    assert orch.state_store.get_lineage("s6")[0].receiver == "emailer"


# --- E3: a data_type label must not switch the info-flow agent off -------------

def _infoflow_leak(metadata: dict) -> str:
    """A derived message carrying identifiers from a PHI source earlier in the session."""
    from haris.agents.infoflow import InformationFlowAgent
    from haris.schemas.message import Message

    record = ("PATIENT RECORD [patient-A]\nName: Jane Doe\nMRN: MRN-0001\n"
              "Diagnosis: Type 2 diabetes")
    source = Message(session_id="s", sender="record_reader", receiver="summarizer",
                     content=record,
                     metadata={"data_type": "PHI", "data_subject": "patient-A"})
    leak = Message(session_id="s", sender="summarizer", receiver="emailer",
                   content="Visit summary for Jane Doe, MRN-0001. Follow-up advised.",
                   metadata=metadata)
    agent = InformationFlowAgent(detector=None)
    return agent.check(leak, {"history": [source, leak]}).label.value


def test_labelling_an_exfiltration_hop_as_a_source_does_not_bypass_taint():
    """A message whose data_type says PHI is exempted as an ORIGIN rather than a derived
    leak. The label is attacker-supplied, so that exemption must not be a switch: a
    compromised sender would stamp data_type=PHI on its exfiltration hop and skip the
    check entirely. The exemption now ends at the trust boundary."""
    honest = _infoflow_leak({"data_type": "summary", "recipient": EXTERNAL})
    forged = _infoflow_leak({"data_type": "PHI", "recipient": EXTERNAL})
    assert honest == "flag"
    assert forged == "flag"          # the label buys nothing on the way out


def test_a_genuine_source_hop_is_still_exempt():
    """The exemption is real and must survive: a PHI source travelling internally, or
    with no recipient at all, is an origin and not a derived leak."""
    assert _infoflow_leak({"data_type": "PHI"}) == "pass"
    assert _infoflow_leak({"data_type": "PHI", "recipient": INTERNAL}) == "pass"


# --- E4: a blocked message must not enter lineage (issue #15) ------------------

def test_a_blocked_message_cannot_bind_the_session_and_deny_service():
    """Issue #15. Lineage used to be recorded BEFORE the agents ran, so a message Haris
    refused still entered the session's history and bound it to the attacker's
    data-subject. Every legitimate message afterwards was then blocked as cross-subject
    contamination - a one-message denial of service from an attacker who cannot get a
    single message through."""
    from haris.agents.identity import IdentityAgent
    from haris.agents.subject_binding import SubjectBindingAgent
    from haris.schemas.message import Message

    orch = Orchestrator(
        InMemoryStateStore(),
        agents=[IdentityAgent({"record_reader": "good-token"}), SubjectBindingAgent()],
        policy=Policy(mode=Mode.ENFORCE))

    with pytest.raises(HarisBlocked):        # unauthenticated attacker, patient-B
        orch.process(Message(session_id="s", sender="attacker", receiver="summarizer",
                             content="record B",
                             metadata={"data_type": "PHI", "data_subject": "patient-B"}))

    # The legitimate agent's patient-A message must still get through.
    decision = orch.process(Message(
        session_id="s", sender="record_reader", receiver="summarizer", content="record A",
        metadata={"data_type": "PHI", "data_subject": "patient-A",
                  "auth_token": "good-token"}))
    assert decision.action.value == "allow"
    assert [m.sender for m in orch.state_store.get_lineage("s")] == ["record_reader"]