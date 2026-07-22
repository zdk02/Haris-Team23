"""SubjectBindingAgent — data-subject (attribute-based) authorization.

The Authorization agent (Module 8) answers "may this sender talk to this receiver about
this data_type?" — a decision about AGENT identities. This agent answers the deeper
question the mentor raised: "does this data belong to the SUBJECT this session is about?"

Real authorization is often about the data INSTANCE, not just the agents. A session
handling patient A's case may legitimately carry patient A's record — but patient B's
record must not enter it, even though the same agents and the same data_type are involved.
Per-agent guardrails cannot express this: the block depends on whose data this is versus
whose case the session is, which only the session context knows.

Binding model (coarse, demo-grade): a session is bound to the FIRST data_subject that
appears in its lineage. Any later message whose data_subject differs is cross-subject
contamination (threat-model TC4) and is BLOCKED. A message with no data_subject, or one
that matches the bound subject, passes. The binding is inferred from the state store's
history — no extra configuration or session registry is needed.

Stateful by necessity (it reads context["history"]), unlike the stateless Module 8. It
always emits its true verdict; the policy engine's mode gate downgrades BLOCK to a flag in
monitor mode, so the agent stays mode-agnostic.
"""
from __future__ import annotations

from typing import Any, Optional

from haris.agents.base import SecurityAgent
from haris.schemas.message import Message
from haris.schemas.verdict import Label, Verdict


class SubjectBindingAgent(SecurityAgent):
    name = "subject_binding"

    def __init__(self, subject_key: str = "data_subject") -> None:
        self.subject_key = subject_key

    def check(self, message: Message, context: dict[str, Any]) -> Verdict:
        current = (message.metadata or {}).get(self.subject_key)
        if not current:
            return self._pass("message carries no data_subject to bind against")

        bound = self._session_subject(context)
        if bound is None or str(bound) == str(current):
            return self._pass(
                f"data_subject '{current}' matches the session's subject")

        return Verdict(
            agent_name=self.name, label=Label.BLOCK, score=1.0,
            reason=(f"cross-subject contamination (TC4): data_subject '{current}' does "
                    f"not match the session's bound subject '{bound}'"),
        )

    def _session_subject(self, context: dict[str, Any]) -> Optional[str]:
        """The subject this session is bound to = the first data_subject seen in lineage.

        The orchestrator records the current message *before* calling agents, so on the
        first subject-bearing hop the bound subject equals the current message's subject
        (it is the only one in history) and the message is allowed. A later hop carrying a
        different subject is what trips the block.
        """
        for m in context.get("history", []):
            subject = (m.metadata or {}).get(self.subject_key)
            if subject:
                return str(subject)
        return None

    def _pass(self, reason: str) -> Verdict:
        return Verdict(agent_name=self.name, label=Label.PASS, score=0.0, reason=reason)
