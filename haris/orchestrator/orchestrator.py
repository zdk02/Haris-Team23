"""Orchestrator: runs agents, resolves a Decision, enforces it.

process() returns a Decision, not a Message. In ENFORCE mode a BLOCK raises
HarisBlocked to the sender. In MONITOR mode nothing is ever raised.

Reliability (a deliberate non-functional requirement): a security agent that
raises must never (a) take Haris down for the whole hop, nor (b) let a message
pass *silently* just because a detector crashed. So each agent runs behind a
guard with a mode-dependent, stated failure policy:
  * MONITOR -> fail OPEN: the crash is turned into a benign FLAG (logged + surfaced
    for observability) but the message is delivered. A bug in a detector can never
    break the protected app while we are only monitoring.
  * ENFORCE -> fail CLOSED: the crash is turned into a BLOCK. When Haris is actually
    guarding the data path, a detector we can't trust to have run is treated as a
    failed check, so the message is stopped rather than waved through.
The healthy agents' verdicts are unaffected: one agent crashing never suppresses
another's result.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from haris.agents.base import SecurityAgent
from haris.policy.engine import resolve
from haris.schemas.decision import Action, Decision, HarisBlocked
from haris.schemas.message import Message
from haris.schemas.policy import Mode, Policy
from haris.schemas.verdict import Label, Verdict
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

        verdicts = [self._safe_check(agent, message, context) for agent in self.agents]
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

    def _safe_check(self, agent: SecurityAgent, message: Message,
                    context: dict[str, Any]) -> Verdict:
        """Run one agent's check() behind the reliability guard.

        A raised exception becomes a synthetic verdict following the stated failure
        policy: BLOCK in enforce (fail closed), a logged FLAG in monitor (fail open).
        Either way the crash is recorded as this agent's verdict, so it shows up in the
        audit trail / dashboard and never disappears silently.
        """
        name = getattr(agent, "name", agent.__class__.__name__)
        try:
            return agent.check(message, context)
        except Exception as exc:  # noqa: BLE001 - any detector failure is contained here
            fail_closed = self.policy.mode is Mode.ENFORCE
            logger.error(
                "HARIS agent %r crashed on %s -> %s; failing %s. %s: %s",
                name, message.sender, message.receiver,
                "CLOSED (block)" if fail_closed else "OPEN (allow, monitor)",
                type(exc).__name__, exc,
            )
            if fail_closed:
                return Verdict(
                    agent_name=name, label=Label.BLOCK, score=1.0,
                    reason=(f"agent error — failing closed in enforce mode: "
                            f"{type(exc).__name__}: {exc}"),
                )
            return Verdict(
                agent_name=name, label=Label.FLAG, score=1.0,
                reason=(f"agent error — failing open in monitor mode (delivered, "
                        f"logged): {type(exc).__name__}: {exc}"),
            )
