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

The registry is passed at construction, so no agent holds another agent's registry entry.

BUT AGENTS DO SEE EACH OTHER'S TOKENS IN TRANSIT. An earlier version of this docstring said
they never do, and that was false. `record_flow` stores the whole `Message` including its
metadata, and `get_context` hands the full session history to every agent on every hop — so
a downstream agent can read the reader's token straight out of the history it is given.
Verified by harvesting one, not theorised.

Stripping the token from the stored Message is the fix and it is small; it is deferred
rather than done because the accompanying half is not small. There is no nonce, timestamp or
sequence number anywhere in `Message` or in this agent, so a captured message replays
forever, and closing that needs the token bound by HMAC to session, sender, receiver, nonce
and a content hash, with the orchestrator rejecting nonce reuse — a protocol change across
the schema and every agent that builds a message. Report §8 records both halves under
"identity is a bearer token: no message integrity, no anti-replay". A docstring that
overstated the property was the more urgent problem, because it is the one a reader would
have believed.

``default_allow_unregistered`` controls what happens to a sender with no registry entry
(default False = strict: an unknown sender has no verifiable identity, so it's blocked).
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

        # Constant-time compare so a wrong token can't be discovered by timing. Compare
        # BYTES: compare_digest on str operands requires both to be ASCII-only and raises
        # TypeError otherwise, so a non-ASCII token would crash into the reliability guard
        # instead of being rejected.
        if provided is not None and hmac.compare_digest(
                str(provided).encode("utf-8"), str(expected).encode("utf-8")):
            return self._pass(f"sender '{message.sender}' identity verified")

        why = "no identity token" if provided is None else "identity token does not match"
        return self._block(
            f"spoofed or unauthenticated sender '{message.sender}' ({why})")

    def _pass(self, reason: str) -> Verdict:
        return Verdict(agent_name=self.name, label=Label.PASS, score=0.0, reason=reason)

    def _block(self, reason: str) -> Verdict:
        return Verdict(agent_name=self.name, label=Label.BLOCK, score=1.0, reason=reason)