"""Haris <-> LangGraph interception layer.

The seam that lets Haris watch every message passing between nodes in a LangGraph
graph and, in enforce mode, redact or block it. It wraps each node function so
that, after the node produces its outgoing message, that message is routed through
the Phase 0 spine -- InterceptionAdapter -> Orchestrator -> Decision -- and the
(possibly redacted) content continues to the next node.

This is framework glue ONLY. It adds nothing to the frozen contracts: it reuses
Message, Orchestrator, Decision and InterceptionAdapter exactly as Phase 0 froze
them. The message content is never hardcoded here -- the wrapper inspects whatever
a node emits, so it works identically for a toy string and a live LLM output.

Proven on a 2-node graph in Step 2; reused unchanged when the real hospital graph
(Step 3) is wired in (Step 4). At that point the ONLY change is that the
orchestrator has real agents instead of zero.
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from demo_app.interception import InterceptionAdapter
from haris.schemas.decision import Decision

# Which key in the graph's shared state carries the message one agent hands to the
# next, and which carries the session id. Configurable so the wrapper matches
# whatever field names the real hospital graph ends up using.
DEFAULT_MESSAGE_KEY = "message"
DEFAULT_SESSION_KEY = "session_id"


class HarisLangGraph:
    """Wraps LangGraph node functions so their outgoing messages flow through Haris.

    Usage (topology is known when you build the graph, so sender/receiver are
    supplied per node):

        haris = HarisLangGraph(InterceptionAdapter(orchestrator))
        builder.add_node("record_reader",
                         haris.wrap(record_reader, "record_reader", "summarizer",
                                    data_type="PHI"))
        builder.add_node("summarizer",
                         haris.wrap(summarizer, "summarizer", "emailer",
                                    data_type="summary"))
    """

    def __init__(
        self,
        adapter: InterceptionAdapter,
        message_key: str = DEFAULT_MESSAGE_KEY,
        session_key: str = DEFAULT_SESSION_KEY,
    ) -> None:
        self.adapter = adapter
        self.message_key = message_key
        self.session_key = session_key
        # Observability side-channel: every Decision Haris made this run, in order.
        # Kept off the graph state so we don't force extra fields into the state
        # schema; a dashboard or a test reads it directly.
        self.decisions: list[Decision] = []

    def wrap(
        self,
        fn: Callable[[dict], dict],
        sender: str,
        receiver: str,
        data_type: Optional[str] = None,
        message_key: Optional[str] = None,
        state_metadata_keys: Optional[Any] = None,
        recipient: Optional[str] = None,
        auth_token: Optional[str] = None,
    ) -> Callable[[dict], dict]:
        """Return a node that runs `fn`, then routes its outgoing message through Haris.

        The returned callable is an ordinary `state -> state-delta` function, so it
        works both inside a compiled LangGraph graph AND when called directly (which
        is how the tests exercise the real Haris path without needing langgraph).

        Args:
          sender / receiver: the two ends of this hop (for the Message + logging).
          data_type: e.g. "PHI" or "summary" -- stashed in metadata for later agents.
          message_key: which state field this node emits onward. Defaults to the
            store-wide message_key. This is what lets one graph carry different
            fields at different hops (the hospital app emits `record` then `summary`).
          state_metadata_keys: extra state fields to copy into metadata so later agents
            can see them. Either a list of names copied through unchanged, or a MAPPING
            {state_key: metadata_key} when the application's field name differs from the
            one Haris's agents read. The mapping form is not a nicety: the hospital graph
            calls its field `subject` while `SubjectBindingAgent` reads `data_subject`, and
            copying the name through unchanged left that agent inert -- it reported "no
            data_subject to bind against" on every hop and the cross-subject defence never
            ran in the shipped pipeline. Translating names is the adapter's job.
            These come from SHARED GRAPH STATE, which the agents themselves write, so
            they are inside the attacker's control (THREAT_MODEL.md, trusted metadata).
          recipient: the egress destination for this hop, BOUND HERE by the graph author
            rather than read from state. When set, a compromised node can neither forge
            nor delete it, which is what makes the authorization egress check trustworthy.
            Leave None only when the destination is genuinely dynamic -- and then say so,
            because the check is only as trustworthy as the field it reads.
          auth_token: this node's bearer token, BOUND HERE rather than read from state, for
            the same reason. An identity token carried in shared graph state is one a
            compromised node can read and replay as another sender; issued at wiring time
            it is not reachable from inside the graph.

        Behaviour:
          * Reads the session id from state[session_key] (falls back to "default").
          * Calls InterceptionAdapter.intercept(), which constructs a real Message,
            runs the Orchestrator, and returns (delivered_content, Decision).
          * Replaces the node's outgoing message with delivered_content, so any
            redaction is what the next node actually receives.
          * In enforce mode a BLOCK makes intercept() raise HarisBlocked, which
            propagates out of this node and halts the graph -- exactly the enforce
            semantics Phase 0 defined.
        """
        key = message_key or self.message_key

        def node(state: dict) -> dict:
            delta = fn(state)
            content = delta.get(key)
            if content is None:
                return delta  # this node emitted no inter-agent message; nothing to inspect

            session_id = state.get(self.session_key, "default")

            # AGENT-INFLUENCED metadata first: copied from shared graph state, which the
            # wrapped agents write. Treat every value here as attacker-controlled.
            metadata: dict[str, Any] = {}
            mapping = (state_metadata_keys if isinstance(state_metadata_keys, dict)
                       else {k: k for k in (state_metadata_keys or [])})
            for state_key, meta_key in mapping.items():
                if state_key in state:
                    metadata[meta_key] = state[state_key]

            # ADAPTER-BOUND metadata LAST, so it always wins. These describe the transport
            # and are declared by the graph author at wrap() time, so a compromised node
            # can neither forge nor delete them. Previously the state copy ran last and
            # could overwrite `receiver` and `data_type` -- the security decision was being
            # keyed off values the sender controlled.
            metadata["receiver"] = receiver
            if data_type is not None:
                metadata["data_type"] = data_type
            if recipient is not None:
                metadata["recipient"] = recipient
            if auth_token is not None:
                metadata["auth_token"] = auth_token

            # The Phase 0 spine. May raise HarisBlocked in enforce mode.
            delivered, decision = self.adapter.intercept(
                session_id=session_id,
                sender=sender,
                receiver=receiver,
                content=content,
                metadata=metadata,
            )
            self.decisions.append(decision)

            return {**delta, key: delivered}

        return node