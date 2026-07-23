"""IdentityAgent — per-agent authentication (threat-model Problem F).

The Authorization agent answers "what may this agent do?" — but that is meaningless if an
attacker can simply *claim* to be Agent A. This agent answers the prior question: "is this
message really FROM the agent it says it is?" Without it, every relationship rule is void,
because a spoofer just labels their message "from record_reader".

Mechanism (the MVP the mentor described — "a per-agent key Haris checks is enough"): each
agent is issued a secret token; a legitimate message carries its sender's token in metadata
(default key ``auth_token``). Haris holds a registry of the tokens and verifies the one on
the message against the claimed sender. A missing or wrong token — a spoofed or
unauthenticated sender — is BLOCKED.

This establishes the property (identity is verified, not self-declared). Hardened versions —
HMAC-signing the whole message so the token also proves integrity, plus a nonce/timestamp to
defeat replay — are the roadmap.

Stateless: the token registry is passed at construction; agents never see each other's
tokens. ``default_allow_unregistered`` controls what happens to a sender with no registry
entry (default False = strict: an unknown sender has no verifiable identity, so it's blocked).
"""
from __future__ import annotations

import hmac
from typing import Any, Mapping

from haris.agents.base import SecurityAgent
from haris.schemas.message import Message
from haris.schemas.verdict import Label, Verdict


class IdentityAgent(SecurityAgent):
    name = "identity"

    def __init__(self, tokens: Mapping[str, str], token_key: str = "auth_token",
                 default_allow_unregistered: bool = False) -> None:
        self.tokens = dict(tokens)
        self.token_key = token_key
        self.default_allow_unregistered = default_allow_unregistered

    def check(self, message: Message, context: dict[str, Any]) -> Verdict:
        expected = self.tokens.get(message.sender)
        provided = (message.metadata or {}).get(self.token_key)

        if expected is None:
            if self.default_allow_unregistered:
                return self._pass(f"sender '{message.sender}' not registered; allowed by config")
            return self._block(
                f"unregistered sender '{message.sender}' — no verifiable identity")

        # Constant-time compare so a wrong token can't be discovered by timing.
        if provided is not None and hmac.compare_digest(str(provided), str(expected)):
            return self._pass(f"sender '{message.sender}' identity verified")

        why = "no identity token" if provided is None else "identity token does not match"
        return self._block(
            f"spoofed or unauthenticated sender '{message.sender}' ({why})")

    def _pass(self, reason: str) -> Verdict:
        return Verdict(agent_name=self.name, label=Label.PASS, score=0.0, reason=reason)

    def _block(self, reason: str) -> Verdict:
        return Verdict(agent_name=self.name, label=Label.BLOCK, score=1.0, reason=reason)
