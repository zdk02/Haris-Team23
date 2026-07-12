"""Orchestrator: runs agents, resolves a Decision, enforces it.

process() returns a Decision, not a Message. In ENFORCE mode a BLOCK raises
HarisBlocked to the sender. In MONITOR mode nothing is ever raised.
"""
from __future__ import annotations

import logging
from typing import Optional

from haris.agents.base import SecurityAgent
from haris.policy.engine import resolve
from haris.schemas.decision import Action, Decision, HarisBlocked
from haris.schemas.message import Message
from haris.schemas.policy import Policy
from haris.state.base import StateStore

logger = logging.getLogger("haris.orchestrator")


class Orchestrator:
    def __init__(
        self,
        state_store: StateStore,
        agents: Optional[list[SecurityAgent]] = None,
        policy: Optional[Policy] = None,
    ) -> None:
        self.state_store = state_store
        self.agents = agents or []          # ZERO agents in the skeleton
        self.policy = policy or Policy()    # defaults to MONITOR mode

    def process(self, message: Message) -> Decision:
        self.state_store.record_flow(message)
        context = self.state_store.get_context(message.session_id)

        verdicts = [agent.check(message, context) for agent in self.agents]
        decision = resolve(message, verdicts, self.policy)

        logger.info(
            "HARIS %s -> %s | mode=%s | action=%s | enforced=%s | verdicts=%s",
            message.sender,
            message.receiver,
            self.policy.mode.value,
            decision.action.value,
            decision.enforced,
            [(v.agent_name, v.label.value) for v in verdicts],
        )

        # MONITOR mode: pass through unchanged no matter what.
        if decision.enforced and decision.action is Action.BLOCK:
            raise HarisBlocked(decision)

        return decision
