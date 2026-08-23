"""The hospital app running end-to-end through Haris.

Step 4 wired the vulnerable hospital graph (Step 3) to the interception layer
(Step 2): every inter-agent hop flows Message -> Orchestrator -> Decision before
continuing. With ZERO agents in monitor mode that is a transparent pass-through
(`run_through_haris`) -- the app still leaks, but Haris sees and records every hop.

PHASE 3 (this module's `run_secured`) fills in the boxes: the SAME graph, the SAME
interception seam, but now the orchestrator holds the full real security line-up
(Secrets/PII + Authorization + Subject-binding + Information-flow + Identity) over the
NetworkX GraphStateStore, and the policy mode is configurable so enforce mode can
block/redact for real. The wiring here does NOT change between the two -- only the
orchestrator's agent list, state store, and mode do.

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
from haris.agents.subject_binding import SubjectBindingAgent
from haris.orchestrator.orchestrator import Orchestrator
from haris.schemas.decision import HarisBlocked
from haris.schemas.policy import Mode, Policy
from haris.state.graph_store import GraphStateStore
from haris.state.memory import InMemoryStateStore
from haris.agents.identity import IdentityAgent
from haris.audit import AuditLog
from haris.notify import Notifier
from haris.schemas.notification import Severity
from haris.notify.health import (HealthCheck, agents_present_probe, audit_chain_probe,
                                 state_store_probe)
from haris.notify.channels import BufferChannel, WebhookChannel


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
        # The graph calls it `subject`; SubjectBindingAgent reads `data_subject`. Copying
        # the name through unchanged left that agent inert on every hop.
        state_metadata_keys={"subject": "data_subject"},
        auth_token=HOSPITAL_TOKENS["record_reader"],
    ))
    # hop 2: summarizer emits `summary` to emailer; carry recipient + subject so the
    # authorization / subject-aware agents can see them.
    b.add_node("summarizer", haris.wrap(
        summarizer, "summarizer", "emailer",
        data_type="summary", message_key="summary",
        state_metadata_keys={"recipient": "recipient", "subject": "data_subject"},
        auth_token=HOSPITAL_TOKENS["summarizer"],
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

# Per-agent bearer tokens for the demo. A real deployment issues these out of band and
# loads them from its secret store; they are inline here because the demo has no such
# store, and they are the same values `identity_demo.py` and `eval_harness.py` use.
HOSPITAL_TOKENS: dict[str, str] = {
    "record_reader": "rr-secret-9f2c",
    "summarizer": "sm-secret-4a71",
}

def build_hospital_agents(include_secrets: bool = True,
                          tokens: Optional[dict[str, str]] = None) -> list:
    """The canonical hospital agent line-up, in orchestrator order.

    Single source of truth for "which agents run in the hospital demo". Order affects
    only redaction composition + audit readability; the policy engine's most-restrictive
    rule is order-independent.

      1. SecretsPIIAgent    - Presidio/detect-secrets content scan. Needs Presidio + the
                              spaCy model; pass include_secrets=False for a no-Presidio run
                              (the other four still work). Configured with the credential
                              exception -- see the comment on its construction below.
      2. AuthorizationAgent - stateless relationship + external-egress check (TC5).
      3. SubjectBindingAgent - data-subject (patient-A vs patient-B) authorization (TC4):
                              blocks data whose subject differs from the session's subject.
                              Inert on a single-subject session; only a mixed-subject
                              session trips it.
      4. InformationFlowAgent - lineage-based derived-leak / info-flow check (TC3),
                              conditioned on the PHI origin in the GraphStateStore.
      5. IdentityAgent      - per-agent authentication (TC-SPOOF): is this message really
                              FROM the sender it claims? Every other check is void without
                              it, because a spoofer just labels its message "from
                              record_reader". It was previously built, tested and claimed
                              in THREAT_MODEL.md as "Problem F (built)" while being
                              constructed ONLY by the eval harness and the demos -- so the
                              shipped pipeline had no spoof defence and the 100% SPOOF
                              detection figure came from an agent production did not run.
    """
    agents: list = []
    if include_secrets:
        # always_redact_secrets=True is the CREDENTIAL EXCEPTION, and it is the only
        # configuration under which REDACT is reachable in this demo. Default behaviour
        # rewrites content only on egress, so an internal hop carrying an API key
        # delivered it untouched and the redact path was structurally dead: the dashboard
        # shipped a redact KPI tile, a legend entry, a filter and a highlighter that could
        # never fire. Two separate problems, one fix -- a credential in an inter-agent
        # message should not propagate even inside the boundary (it is a key, not clinical
        # data the receiving agent needs), and the demo now has a case where BLOCK is the
        # wrong answer and REDACT is the right one (TC7). PII is unaffected: names and
        # diagnoses are still delivered intact on internal hops, which is what makes this
        # a redaction rather than a block.
        agents.append(SecretsPIIAgent(always_redact_secrets=True))
    agents.append(AuthorizationAgent())
    agents.append(SubjectBindingAgent())
    agents.append(InformationFlowAgent())
    agents.append(IdentityAgent(tokens if tokens is not None else HOSPITAL_TOKENS))
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
    audit_log: Optional[AuditLog] = None,
    audit_key: Optional[bytes] = None,
) -> dict[str, Any]:
    """Run one hospital scenario through the FULL secured pipeline.

    Same graph + same interception seam as `run_through_haris`, but the orchestrator
    now holds the full real agent line-up over a `GraphStateStore`, in the requested mode.

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
      audit          -> the AuditLog for this run; audit.checkpoint() gives the (head,
                        count) pair an operator holds outside the log to detect truncation
      alerts         -> the BufferChannel holding the alerts this run raised, most recent
                        first. This is the channel a blocked leak actually reaches when no
                        webhook URL is configured, which is the normal case for a local run
      health         -> the HealthCheck with its probes registered, so a caller (or a
                        /health endpoint) can re-run them after the fact
    """
    store = GraphStateStore()
    policy = Policy(mode=mode, thresholds=thresholds or {})
    agent_list = agents if agents is not None else build_hospital_agents(include_secrets)

    # Phase 4: notifier first, so the orchestrator can push crash/block alerts through it.
    #
    # Two separate defects lived here. (1) WebhookChannel defaults to min_severity=CRITICAL,
    # but a blocked leak is WARNING (schemas/notification.py), so the alert the threat model
    # promises was filtered out before routing. (2) Even with that fixed, WebhookChannel is a
    # silent no-op unless HARIS_ALERT_WEBHOOK is set -- which it is not on a local run, in
    # CI, or on a grader's machine. So "the operator is alerted" was still true of nothing.
    #
    # The BufferChannel closes that: it always accepts WARNING+, keeps the last 50 alerts in
    # memory, and is returned to the caller as `alerts`. A blocked leak therefore lands
    # somewhere observable with zero configuration, and the webhook remains the out-of-band
    # push for a deployment that configures one.
    alerts = BufferChannel()
    notifier = Notifier(channels=[alerts, WebhookChannel(min_severity=Severity.WARNING)])

    # The security audit log, wired into the SHIPPED path. Previously it existed, was
    # tested, and was documented in THREAT_MODEL.md -- and was created only by the
    # dashboard and the evaluation, so nothing the real pipeline did was ever recorded.
    # `store_delivered_content` is left at its safe default: hashes and metadata only.
    # `checkpoint_every=1` emits (head, count) to the operational log on every record, so
    # the reference needed to detect truncation lands somewhere the audit file's writer
    # does not control. A deployment sets this higher and ships that stream to CloudWatch.
    audit = audit_log if audit_log is not None else AuditLog(key=audit_key,
                                                             checkpoint_every=1)

    orchestrator = Orchestrator(state_store=store, agents=agent_list, policy=policy,
                                audit_log=audit, notifier=notifier)
    graph, haris = build_haris_graph(orchestrator)

    # Health check that notifies + drives fail-closed (task 4). The chain probe is what
    # turns "the log is tamper-evident" from a property of the code into something the
    # running system actually checks -- it was registered nowhere outside the tests.
    health = HealthCheck(notifier=notifier)
    health.register("agents", agents_present_probe(orchestrator))
    health.register("state_store", state_store_probe(store))
    health.register("audit_chain", audit_chain_probe(audit))
    health.assert_serviceable(policy.mode)

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
        "audit": audit,
        "alerts": alerts,
        "health": health,
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
    everywhere: with Presidio we run the full five-agent line-up; without it, the other
    four (authorization, subject binding, info-flow, identity)."""
    try:
        SecretsPIIAgent().pii.analyze("warm up")
        return True
    except Exception:
        return False


def _summarize_hop(decision) -> str:
    contributors = ", ".join(
        f"{v.agent_name}:{v.label.value}" for v in decision.verdicts) or "no agents"
    return f"action={decision.action.value} enforced={decision.enforced} [{contributors}]"


def configure_operational_logging() -> None:
    """Give the Tier-1 operational logger a destination.

    Separated from `main()` so it is callable (and testable) rather than buried in an entry
    point. Without it the audit checkpoints (`haris.audit.checkpoint`, INFO) are produced and
    dropped: the truncation reference THREAT_MODEL.md promises is emitted to a logger nothing
    configures, which is indistinguishable from not emitting it at all. `logging.basicConfig`
    alone does NOT cover this -- `configure_logging` sets propagate=False on the `haris`
    namespace, so the operational tier needs its own handler.
    """
    import logging

    from haris.logging_config import configure_logging
    configure_logging(level=logging.INFO)
    logging.basicConfig(level=logging.WARNING, format="%(message)s")


def main() -> None:
    configure_operational_logging()

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