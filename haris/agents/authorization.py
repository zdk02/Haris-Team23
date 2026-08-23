"""AuthorizationAgent — Module 8 (relationship-rule + egress authorization).

A stateless SecurityAgent. For each message it decides whether this
sender -> receiver -> data_type flow is permitted, and whether sensitive data is
being routed to an external recipient. It never consults the lineage ledger, so
it is independent of Module 6.

Two inputs, both data-not-code:
  * relationship rules — a list of the frozen PolicyRule (sender, receiver,
    data_type, action in {"allow","deny","redact"}). "*" is a wildcard for any
    field; the first matching rule wins.
  * egress config — internal_domain + sensitive_types. The frozen PolicyRule has
    no recipient field, so the "don't send PHI/summary to an external address"
    constraint (TC5) cannot be expressed as a PolicyRule; it lives here instead.

Decision order for one message:
  1. matching rule action "deny"   -> BLOCK
  2. matching rule action "redact" -> FLAG  (authz only flags; actual content
     redaction is the PII / info-flow agents' job, not authorization's)
  3. sensitive data_type to an external recipient -> BLOCK  (TC5)
  4. no matching rule and strict mode (default_allow=False) -> BLOCK (default-deny)
  5. otherwise -> PASS

The agent always emits its true verdict (e.g. BLOCK); the policy engine's mode
gate is what downgrades it to a flag in monitor mode, so the agent stays
mode-agnostic. `data_subject` (patient-A vs patient-B) is read but NOT enforced
yet — reserved by the frozen Policy contract.

Trust boundary (THREAT_MODEL.md §2.3): `recipient`, like every other metadata
field, is supplied by the SENDER — the party the threat model treats as possibly
compromised. An absent recipient is therefore ambiguous: it is both the normal
internal agent-to-agent handoff AND what a compromised sender produces by deleting
one key. `treat_missing_recipient_as_external` exposes that choice; see the note on
it in __init__ for the measured cost of enforcing it in this architecture.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from haris.agents.base import SecurityAgent
from haris.schemas.message import Message
from haris.schemas.policy import PolicyRule
from haris.schemas.verdict import Label, Verdict


# Demo-oriented defaults; override in the constructor for another deployment so
# nothing hospital-specific is hardcoded into the evaluation logic.
DEFAULT_INTERNAL_DOMAIN = "@hospital.internal"
DEFAULT_SENSITIVE_TYPES: frozenset[str] = frozenset({"PHI", "summary", "credential"})


class AuthorizationAgent(SecurityAgent):
    name = "authorization"

    def __init__(
        self,
        rules: Optional[Iterable[PolicyRule]] = None,
        internal_domain: str = DEFAULT_INTERNAL_DOMAIN,
        sensitive_types: Iterable[str] = DEFAULT_SENSITIVE_TYPES,
        default_allow: bool = True,
        treat_missing_recipient_as_external: bool = False,
    ) -> None:
        self.rules: list[PolicyRule] = list(rules or [])
        self.internal_domain = internal_domain
        self.sensitive_types = frozenset(sensitive_types)
        self.default_allow = default_allow
        # A message with no recipient names no destination, and the field comes from the
        # sender - the party the threat model treats as compromised. So deleting one key
        # switches the egress check off (THREAT_MODEL.md, trusted-metadata boundary).
        #
        # It CANNOT default to True here. In this architecture an absent recipient is also
        # the normal internal agent-to-agent handoff (record_reader -> summarizer carries
        # data_type=PHI and no recipient), so treating absence as egress blocks every
        # session at its first hop: measured leak-prevention 100%, false positives 100%,
        # utility 0%. Distinguishing the two cases needs to know which agents are inside
        # the system, which Haris does not hold.
        #
        # Set True in a deployment whose interception adapter BINDS `recipient` from the
        # transport, so absence really does mean "no destination was declared". That
        # binding is the deployment-era requirement named in THREAT_MODEL.md.
        self.treat_missing_recipient_as_external = treat_missing_recipient_as_external

    def check(self, message: Message, context: dict[str, Any]) -> Verdict:
        sender = message.sender
        receiver = message.receiver
        md = message.metadata or {}
        data_type = md.get("data_type")
        recipient = md.get("recipient")

        rule = self._match(sender, receiver, data_type)

        # 1./2. explicit relationship rule
        if rule is not None:
            if rule.action == "deny":
                return self._block(
                    f"policy denies {sender} -> {receiver} carrying '{data_type}'")
            if rule.action == "redact":
                return self._flag(
                    f"policy restricts {sender} -> {receiver} carrying "
                    f"'{data_type}' (redact)")
            # action == "allow": fall through — an explicit allow still does not
            # license leaking sensitive data to an external recipient (step 3).

        # 3. egress: sensitive data leaving the trust boundary (TC5)
        if data_type in self.sensitive_types and self._is_external(recipient):
            return self._block(
                f"sensitive '{data_type}' routed to external recipient "
                f"'{recipient}' (outside {self.internal_domain})")

        # 4. default-deny (strict mode) when nothing explicitly permits the flow
        if rule is None and not self.default_allow:
            return self._block(
                f"no rule permits {sender} -> {receiver} carrying '{data_type}' "
                f"(default-deny)")

        # 5. permitted
        why = "allowed by rule" if rule is not None else "no restriction applies"
        return self._pass(why)

    # ------------------------------------------------------------------ #
    # helpers                                                            #
    # ------------------------------------------------------------------ #

    def _match(self, sender: str, receiver: str,
               data_type: Optional[str]) -> Optional[PolicyRule]:
        """First rule matching (sender, receiver, data_type); '*' is a wildcard."""
        for r in self.rules:
            if (self._eq(r.sender, sender)
                    and self._eq(r.receiver, receiver)
                    and self._eq(r.data_type, data_type)):
                return r
        return None

    @staticmethod
    def _eq(rule_val: str, msg_val: Optional[str]) -> bool:
        return rule_val == "*" or rule_val == msg_val

    def _is_external(self, recipient: Optional[str]) -> bool:
        # An ABSENT recipient is not evidence of an internal handoff - it is absence of
        # evidence, and the field is supplied by the sender we treat as compromised.
        # Deleting one key must not be a way to turn the egress check off.
        if recipient is None:
            return self.treat_missing_recipient_as_external
        return not recipient.endswith(self.internal_domain)

    def _block(self, reason: str) -> Verdict:
        return Verdict(agent_name=self.name, label=Label.BLOCK, score=1.0, reason=reason)

    def _flag(self, reason: str) -> Verdict:
        return Verdict(agent_name=self.name, label=Label.FLAG, score=0.8, reason=reason)

    def _pass(self, reason: str) -> Verdict:
        return Verdict(agent_name=self.name, label=Label.PASS, score=0.0, reason=reason)