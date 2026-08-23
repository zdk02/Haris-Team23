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

import hashlib
import logging
import time
from typing import Any, Optional

from haris.agents.base import SecurityAgent
from haris.audit import AuditLog
from haris.notify.notifier import Notifier
from haris.policy.engine import resolve
from haris.schemas.decision import Action, Decision, HarisBlocked
from haris.schemas.message import Message
from haris.schemas.notification import NotificationEvent
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
        audit_log: Optional[AuditLog] = None,
        notifier: Optional[Notifier] = None,
    ) -> None:
        self.state_store = state_store
        self.agents = agents or []          # ZERO agents in the skeleton
        self.policy = policy or Policy()    # defaults to MONITOR mode
        # Optional durable record of every decision. When set, each processed message
        # (including blocked ones) is appended before enforcement raises — the audit
        # trail must record the block. Any app running through Haris populates it.
        self.audit_log = audit_log
        # Optional notifier. When set, the runtime triggers below push an alert to a human:
        # a detector crash / fail-closed (OPERATIONAL, CRITICAL) and a blocked leak
        # (SECURITY, WARNING). When None, Haris behaves exactly as before — notifications
        # are purely additive and never change a decision.
        self.notifier = notifier

    def process(self, message: Message) -> Decision:
        # The timer starts HERE, on the first line. Recording the flow and loading the
        # session context are work Haris does on every hop and the sender waits for, so
        # starting the clock after them understated the middleware's real overhead --
        # and the state store is exactly the component whose cost grows with session
        # length, so the omission got worse as sessions got longer.
        t0 = time.perf_counter()

        self.state_store.record_flow(message)
        context = self.state_store.get_context(message.session_id)

        verdicts = [self._safe_check(agent, message, context) for agent in self.agents]
        decision = resolve(message, verdicts, self.policy)

        # Everything the RECEIVER waits for: state store + agents + policy. This is the
        # number stored in the audit record. A record cannot contain the cost of its own
        # write, so the audit write is measured separately below.
        latency_ms = (time.perf_counter() - t0) * 1000.0

        if self.audit_log is not None:
            self.audit_log.record(message, decision, latency_ms)

        # End-to-end cost including the audit write -- operational only, never stored.
        # Reported so the excluded step is observable rather than merely disclaimed.
        total_ms = (time.perf_counter() - t0) * 1000.0

        logger.info(
            "HARIS %s -> %s | mode=%s | action=%s | enforced=%s | latency=%.2fms | "
            "total=%.2fms | verdicts=%s",
            message.sender,
            message.receiver,
            self.policy.mode.value,
            decision.action.value,
            decision.enforced,
            latency_ms,
            total_ms,
            [(v.agent_name, v.label.value) for v in verdicts],
        )
        # TRIGGER T4 — a leak was blocked at egress: a security event a human should review.
        # The engine only yields action == BLOCK in enforce mode (monitor clamps BLOCK to
        # FLAG in policy/engine._apply_mode), so this fires exactly when a message was really
        # stopped. The summary is SANITIZED — only sender/receiver/data_type, never the
        # content or the raw agent reason (that goes in metadata, which the Notifier strips
        # before any channel). The reference is the content hash, the same pointer the audit
        # log stores, so an operator can find the full record without the secret in the alert.
        if self.notifier is not None and decision.action is Action.BLOCK:
            md = message.metadata or {}
            self.notifier.notify(NotificationEvent.security(
                "orchestrator",
                f"Haris blocked a {md.get('data_type') or 'message'} flow "
                f"{message.sender} -> {message.receiver}",
                reference=hashlib.sha256((message.content or "").encode("utf-8")).hexdigest(),
                session_id=message.session_id,
                reason=decision.reason,
                enforced=decision.enforced,
                recipient=md.get("recipient"),
            ))

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
            # TRIGGERS T1/T2 — a detector crashed. This is exactly the mentor's "if something
            # goes wrong, how do we know?": the guard already contains the crash, and now it
            # also pushes a CRITICAL alert so a human is told a detector is down (and, in
            # enforce, that we're failing closed). The error type goes in metadata (kept for
            # the log, stripped before any channel); the summary carries no message content.
            if self.notifier is not None:
                self.notifier.notify(NotificationEvent.operational(
                    "orchestrator",
                    f"detector {name!r} crashed on {message.sender} -> {message.receiver}; "
                    f"failing {'CLOSED (block)' if fail_closed else 'OPEN (allow, monitor)'}",
                    session_id=message.session_id,
                    error_type=type(exc).__name__,
                    error=str(exc),
                    mode=self.policy.mode.value,
                ))
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