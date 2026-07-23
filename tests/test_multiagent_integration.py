"""Module 10 integration: all three real agents composing in one Orchestrator.

Every agent (Secrets/PII, Authorization, Information-flow) is proven in isolation in
its own test file. This file proves they COMPOSE: registered together in a single
`Orchestrator`, their verdicts flow through the real policy engine and resolve into one
coherent Decision per hop on the threat-model cases (TC2/TC3/TC5), honoring
most-restrictive precedence, redaction composition, and the monitor/enforce mode gate.

It uses the real `Orchestrator` + `resolve()` + `GraphStateStore`. Each scenario seeds
the PHI-source hop into the lineage, then processes the derived summary hop and inspects
the resulting Decision (which carries every contributing verdict).

Presidio-backed (via the real SecretsPIIAgent); skipped cleanly if Presidio/spaCy is not
installed, exactly like test_secrets_pii.py.
"""
from __future__ import annotations

import pytest

from demo_app.hospital.app import EXTERNAL_EXAMPLE, INTERNAL_DOCTOR, format_record
from demo_app.hospital.records import load_record
from haris.agents.authorization import AuthorizationAgent
from haris.agents.infoflow import InformationFlowAgent
from haris.agents.secrets_pii import SecretsPIIAgent
from haris.orchestrator.orchestrator import Orchestrator
from haris.schemas.decision import Action, HarisBlocked
from haris.schemas.message import Message
from haris.schemas.policy import Mode, Policy
from haris.state.graph_store import GraphStateStore

RECORD_A = format_record(load_record("patient-A"))
IDENTIFIED = ("Visit summary for Jane Doe: Type 2 diabetes; hypertension. "
              "Follow-up advised.")
VERBATIM = f"Visit summary. Full record follows:\n{RECORD_A}"
ALL_AGENTS = {"secrets_pii", "authorization", "infoflow"}


@pytest.fixture(scope="module", autouse=True)
def _require_presidio():
    """Skip the whole module if Presidio/spaCy is unavailable (matches test_secrets_pii)."""
    try:
        SecretsPIIAgent().pii.analyze("warm up")
    except Exception as exc:  # noqa: BLE001 - any Presidio/spaCy init failure means skip
        pytest.skip(f"Presidio/spaCy unavailable: {exc}")


def _orchestrator(mode: Mode, authz: AuthorizationAgent | None = None) -> Orchestrator:
    """One Orchestrator holding all three real agents, with the PHI source already
    recorded in the lineage so the info-flow agent has taint to trace."""
    store = GraphStateStore()
    agents = [SecretsPIIAgent(), authz or AuthorizationAgent(), InformationFlowAgent()]
    orch = Orchestrator(store, agents=agents, policy=Policy(mode=mode))
    phi = Message(session_id="s", sender="record_reader", receiver="summarizer",
                  content=RECORD_A, metadata={"data_type": "PHI",
                                              "data_subject": "patient-A"})
    orch.process(phi)  # seed lineage (records original PHI; never blocks at this hop)
    return orch


def _summary(content: str, recipient: str) -> Message:
    return Message(session_id="s", sender="summarizer", receiver="emailer",
                   content=content, metadata={"data_type": "summary",
                                              "recipient": recipient,
                                              "data_subject": "patient-A"})


def _agent_names(decision) -> set[str]:
    return {v.agent_name for v in decision.verdicts}


# --------------------------------------------------------------------------- #
# Conflicting verdicts: BLOCK (authorization) beats REDACT (pii + info-flow)   #
# --------------------------------------------------------------------------- #

def test_tc3_identified_to_external_blocks_in_enforce():
    """All three fire on the derived leak to an external recipient. Authorization
    BLOCKs the egress; most-restrictive means the composed Decision is BLOCK."""
    orch = _orchestrator(Mode.ENFORCE)
    with pytest.raises(HarisBlocked) as exc:
        orch.process(_summary(IDENTIFIED, EXTERNAL_EXAMPLE))
    d = exc.value.decision
    assert d.action is Action.BLOCK
    assert d.enforced is True
    assert _agent_names(d) == ALL_AGENTS                     # every agent contributed
    assert any(v.agent_name == "authorization" and v.label.value == "block"
               for v in d.verdicts)


def test_tc2_verbatim_to_external_blocks_in_enforce():
    """Verbatim PHI to external: PII flags, info-flow flags, authorization blocks."""
    orch = _orchestrator(Mode.ENFORCE)
    with pytest.raises(HarisBlocked) as exc:
        orch.process(_summary(VERBATIM, EXTERNAL_EXAMPLE))
    assert exc.value.decision.action is Action.BLOCK
    assert _agent_names(exc.value.decision) == ALL_AGENTS


# --------------------------------------------------------------------------- #
# Mode gate: the same three verdicts, monitor mode = decided but not enforced  #
# --------------------------------------------------------------------------- #

def test_tc3_to_external_monitor_flags_but_does_not_enforce():
    """Monitor never exceeds FLAG and never enforces, even though the underlying
    resolution was BLOCK. A false positive cannot break the app in monitor mode."""
    orch = _orchestrator(Mode.MONITOR)
    d = orch.process(_summary(IDENTIFIED, EXTERNAL_EXAMPLE))  # monitor never raises
    assert d.action is Action.FLAG
    assert d.enforced is False
    assert _agent_names(d) == ALL_AGENTS


# --------------------------------------------------------------------------- #
# TC5 recipient-dependence: same summary, internal recipient is permitted flow #
# --------------------------------------------------------------------------- #

def test_tc5_identified_to_internal_permits_flow_and_logs_pii():
    """Sent to the internal doctor: authorization permits the flow, info-flow treats an
    in-boundary destination as allowed (PASS), and the (boundary-aware) Secrets/PII agent
    DETECTS the name but only LOGS it on this safe internal hop -- it does not redact.
    So the composed action is FLAG (observed, delivered unchanged): the treating doctor
    still sees 'Jane Doe', while the same summary to an external address is caught."""
    m = _summary(IDENTIFIED, INTERNAL_DOCTOR)
    orch = _orchestrator(Mode.ENFORCE)
    d = orch.process(m)
    assert d.action is Action.FLAG                    # logged, not redacted or blocked
    assert d.final_content is None                    # nothing was rewritten
    assert "Jane Doe" in m.content                    # delivered unchanged to the doctor
    assert _agent_names(d) == ALL_AGENTS              # all three still contributed a verdict
    # Secrets/PII detected PII (FLAG) but produced no redaction on the internal hop.
    assert any(v.agent_name == "secrets_pii" and v.label.value == "flag"
               and v.redacted_content is None for v in d.verdicts)
    assert any(v.agent_name == "infoflow" and v.label.value == "pass"
               for v in d.verdicts)                          # info-flow allowed it
    assert any(v.agent_name == "authorization" and v.label.value == "pass"
               for v in d.verdicts)


# --------------------------------------------------------------------------- #
# Double redaction: two agents mask, engine unions both (no last-writer-wins)  #
# --------------------------------------------------------------------------- #

def test_double_redaction_composes_when_authorization_permits_egress():
    """A deployment where summaries MAY leave but must be scrubbed: authorization is
    configured to not treat `summary` as egress-sensitive, so it permits the flow and
    the two content-redactors (Secrets/PII masks the name, Information-flow masks the
    derived diagnosis identifiers) BOTH apply. The engine unions their masks rather
    than letting the last writer win."""
    authz = AuthorizationAgent(sensitive_types={"PHI", "credential"})  # summary not sensitive
    orch = _orchestrator(Mode.ENFORCE, authz=authz)
    d = orch.process(_summary(IDENTIFIED, EXTERNAL_EXAMPLE))

    assert d.action is Action.REDACT
    assert d.enforced is True
    body = d.final_content or ""
    assert "Jane Doe" not in body        # PII-detected name masked
    assert "diabetes" not in body        # info-flow-derived diagnosis identifier masked
    assert "[REDACTED]" in body          # engine standardized both agents' masks
    # both content-redactors actually contributed a redaction verdict
    assert any(v.agent_name == "secrets_pii" and v.redacted_content for v in d.verdicts)
    assert any(v.agent_name == "infoflow" and v.redacted_content for v in d.verdicts)
