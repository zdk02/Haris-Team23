"""GraphStateStore — Module 6 (state store: interaction graph + lineage ledger).

A concrete StateStore backed by a NetworkX MultiDiGraph. It is a **drop-in** for
InMemoryStateStore: the three frozen methods (`get_context`, `record_flow`,
`get_lineage`) behave identically — same return types, same values — so anything
that works with the in-memory store works with this one unchanged. Why use it
instead of the in-memory store: it keeps the same per-session message list AND
builds a real interaction graph on top — something a flat list can't give the
dashboard.

Parity (verified against haris/state/memory.py):
  * `get_context(session_id) -> {"history": list[Message]}`
  * `record_flow(message) -> None`  (append the Message)
  * `get_lineage(session_id) -> list[Message]`

Ordering (from haris/orchestrator): `process()` calls `record_flow(message)`
*before* `get_context(...)`, so the current hop is already the last item in
`history`. We match that exactly — do not "helpfully" exclude it.

Graph model (additive, for Module 11):
  * nodes = agents (record_reader, summarizer, emailer, ...), attr role="agent"
  * edges = one per recorded hop, carrying data_type / data_subject / content /
    timestamp read from `Message.metadata`.

Taint (additive, for Module 9): the existing infoflow spike reads `context["history"]`
and extracts its own tags off the Message objects, so it keeps working with no
change. `taint_sources()` is offered as a convenience for the promoted agent — it
is NOT part of the frozen interface. Taint is coarse and session-level per the
Step 5 finding; the identifier check in the agent is what bounds false positives.
"""

from __future__ import annotations

from typing import Any, Iterable

import networkx as nx

from haris.state.base import StateStore
from haris.schemas.message import Message


# Data types that introduce taint at their source (coarse by design; Step 5).
TAINT_ORIGIN_TYPES: frozenset[str] = frozenset({"PHI", "credential"})


class GraphStateStore(StateStore):
    """StateStore backed by a NetworkX interaction graph. Drop-in for InMemory."""

    def __init__(self, taint_origin_types: Iterable[str] = TAINT_ORIGIN_TYPES) -> None:
        # Per-session message list — mirrors InMemoryStateStore._flows exactly.
        self._flows: dict[str, list[Message]] = {}
        # Interaction graph (agents = nodes, hops = edges). Exposed for Module 11.
        self.graph: nx.MultiDiGraph = nx.MultiDiGraph()
        self._taint_origin_types = frozenset(taint_origin_types)
        # Monotonic edge key so repeated hops between the same two agents are
        # distinct and ordering is stable regardless of timestamp resolution.
        self._seq = 0

    # ------------------------------------------------------------------ #
    # Frozen contract (haris/state/base.py) — identical to InMemoryStateStore
    # ------------------------------------------------------------------ #

    def record_flow(self, message: Message) -> None:
        self._flows.setdefault(message.session_id, []).append(message)

        # Additive: mirror the hop into the interaction graph.
        md = message.metadata or {}
        self.graph.add_node(message.sender, role="agent")
        self.graph.add_node(message.receiver, role="agent")
        self.graph.add_edge(
            message.sender,
            message.receiver,
            key=self._seq,
            session_id=message.session_id,
            data_type=md.get("data_type"),
            data_subject=md.get("data_subject"),
            timestamp=message.timestamp,
            content=message.content,
        )
        self._seq += 1

    def get_context(self, session_id: str) -> dict[str, Any]:
        # Exact parity with InMemoryStateStore: {"history": [Message, ...]}.
        return {"history": list(self._flows.get(session_id, []))}

    def get_lineage(self, session_id: str) -> list[Message]:
        return list(self._flows.get(session_id, []))

    # ------------------------------------------------------------------ #
    # Additive helpers — NOT part of the frozen 3. Safe under the freeze
    # (they don't touch existing behavior), but coordinate before depending
    # on them from another module.
    # ------------------------------------------------------------------ #

    def taint_sources(self, session_id: str) -> list[dict[str, Any]]:
        """Prior hops whose data_type is a taint origin (for the Info-flow agent).

        Each entry: {origin, data_type, data_subject, content, seq-position}.
        Convenience only — the frozen path is `context["history"]`.
        """
        sources: list[dict[str, Any]] = []
        for pos, m in enumerate(self._flows.get(session_id, [])):
            md = m.metadata or {}
            if md.get("data_type") in self._taint_origin_types:
                sources.append(
                    {
                        "origin": m.sender,
                        "data_type": md.get("data_type"),
                        "data_subject": md.get("data_subject"),
                        "content": m.content,
                        "position": pos,
                    }
                )
        return sources

    def session_subgraph(self, session_id: str) -> nx.MultiDiGraph:
        """The interaction subgraph for one session (for the dashboard, Module 11)."""
        edges = [
            (u, v, k)
            for u, v, k, d in self.graph.edges(keys=True, data=True)
            if d.get("session_id") == session_id
        ]
        if not edges:
            return nx.MultiDiGraph()
        return self.graph.edge_subgraph(edges).copy()
