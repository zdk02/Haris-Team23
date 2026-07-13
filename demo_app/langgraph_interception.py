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
        state_metadata_keys: Optional[list[str]] = None,
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
          state_metadata_keys: extra state fields to copy into metadata so later
            agents can see them -- e.g. ["recipient", "subject"] gives the
            authorization / subject-aware agents the recipient and data_subject.

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
            metadata: dict[str, Any] = {"receiver": receiver}
            if data_type is not None:
                metadata["data_type"] = data_type
            for sk in (state_metadata_keys or []):
                if sk in state:
                    metadata[sk] = state[sk]

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