"""SubjectBindingAgent — data-subject (attribute-based) authorization.

The Authorization agent (Module 8) answers "may this sender talk to this receiver about
this data_type?" — a decision about AGENT identities. This agent answers the deeper
question the mentor raised: "does this data belong to the SUBJECT this session is about?"

Real authorization is often about the data INSTANCE, not just the agents. A session
handling patient A's case may legitimately carry patient A's record — but patient B's
record must not enter it, even though the same agents and the same data_type are involved.
Per-agent guardrails cannot express this: the block depends on whose data this is versus
whose case the session is, which only the session context knows.

THREE BINDINGS.

  1. SESSION BINDING (original). A session is bound to the FIRST data_subject that appears
     in its lineage. A later message DECLARING a different data_subject is cross-subject
     contamination (threat-model TC4) and is BLOCKED.

  2. CONTENT BINDING (added 2026-08-24). A record usually asserts its own subject — as a
     bracketed marker in a structured header, or simply named in the text of a narrative
     note, a JSON payload or a chat transcript. When that assertion disagrees with the
     message's declared `data_subject`, the message is BLOCKED, regardless of where it is
     addressed. Reading only the bracketed form made this a property of one record
     format; both are read since task N1.

  3. DECLARED SCOPE (added 2026-08-24, after measuring what binding 1 costs). When the
     calling application states up front which subjects a session legitimately covers,
     binding 1 uses that set instead of "whichever subject arrived first".

Binding 1 alone is defeated by an attacker who simply does not update the label. Deliver
patient B's record into patient A's session while leaving `data_subject: patient-A` in
place and every metadata check in the system agrees: the recipient is authorised, the
token is valid, exactly one subject has been declared. Nothing in the metadata is wrong.
What is wrong is that the DATA disagrees with the METADATA — and the only way to see that
is to read the record's own claim about itself and compare it to the session's claim.

This is the property no metadata heuristic can reproduce, because a metadata heuristic by
definition never opens the payload; and no per-message content scanner can reproduce it
either, because the message is addressed internally and carries nothing a DLP rule
recognises as a secret. It is the concrete answer to "what does lineage buy you?"

WHY BINDING 3 EXISTS, AND WHAT IT COST TO FIND.
Binding 1 treats every second data subject as contamination. That is right for an attack
and wrong for a ward round: a clinician reviewing two patients, an advisor comparing two
accounts, a recruiter screening two candidates are all ordinary work, and their traffic is
INDISTINGUISHABLE from the attack — two source reads, two subjects, one session, nothing
egressing. Measured on a corpus built to contain both (`multi_subject_workflow` against
`subject_mismatch`), binding 1 alone refused 24 of 24 legitimate sessions: a 17% false
positive rate, the whole of it this one case.

Nothing in the message stream separates the two, so the separation has to come from
outside it. `session_scope` is the calling application saying, before any record is read,
which subjects this piece of work is about. With it, a session covering A and B accepts
both and still refuses C. Without it, the agent falls back to first-subject binding
exactly as before, so an attack that declares nothing is caught exactly as it was.

THE HONEST LIMIT OF BINDING 3. `session_scope` is sender-supplied metadata, and
THREAT_MODEL.md §2.3 already treats that whole class as attacker-controllable: a
compromised agent can forge a scope covering both subjects and walk the contamination
attack straight through. That is not a hole this agent can close on its own — the same
argument applies to `recipient` and `data_type`, and the same fix applies too: bind the
field at the interception adapter from something the sender does not author (the
authenticated caseload, the workflow's ticket), as E1/E2 did for `receiver`. The corpus
measures the forged case rather than asserting it (`forged_session_scope`), so the cost of
this convenience is a number in the results and not a footnote.

SCOPE, HONESTLY. Content binding is only as good as the record's self-assertion. It works
on structured records that name their subject; a free-prose note that never says whose it
is asserts nothing, and this agent will not catch a forged label there. It is a real
mechanism against a real threat, not a general solution to data-provenance forgery — say
so in §8 rather than letting a reader assume the stronger claim.

Content binding is OFF unless `known_subjects` is configured. That is deliberate: the
agent only treats a bracketed marker as a subject claim when it matches a subject the
deployment declared, so ordinary bracketed text — `[REDACTED]`, `[see attached]` — can
never be mistaken for one. Configuring it is one argument, and `demo_app/eval/domains.py`
passes `domain.subjects`.

Stateful by necessity (it reads context["history"]), unlike the stateless Module 8. It
always emits its true verdict; the policy engine's mode gate downgrades BLOCK to a flag in
monitor mode, so the agent stays mode-agnostic.
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Optional

from haris.agents.base import SecurityAgent
from haris.schemas.message import Message
from haris.schemas.verdict import Label, Verdict

# Structured records carry their subject in a bracketed header: "[patient-A]".
_SUBJECT_MARKER = r"\[([^\]]+)\]"


class SubjectBindingAgent(SecurityAgent):
    name = "subject_binding"

    def __init__(self, subject_key: str = "data_subject", *,
                 known_subjects: Iterable[str] = (),
                 subject_marker: str = _SUBJECT_MARKER,
                 scope_key: str = "session_scope") -> None:
        """
        known_subjects: the data subjects this deployment knows about. A bracketed marker
            in message content is treated as a subject claim ONLY if it is one of these,
            so `[REDACTED]` and other bracketed prose are never mistaken for a subject.
            Left empty (the default), content binding is disabled entirely and this agent
            behaves exactly as it did before 2026-08-24.
        subject_marker: regex with one capture group locating a record's self-asserted
            subject. Defaults to the bracketed-header convention.
        scope_key: metadata field in which the calling application declares which data
            subjects this session legitimately covers, comma-separated. Absent, the agent
            falls back to binding the session to its first subject.
        """
        self.subject_key = subject_key
        self.known_subjects = frozenset(str(s) for s in known_subjects)
        self._marker = re.compile(subject_marker)
        self.scope_key = scope_key

    def check(self, message: Message, context: dict[str, Any]) -> Verdict:
        current = (message.metadata or {}).get(self.subject_key)
        if not current:
            return self._pass("message carries no data_subject to bind against")

        # BINDING 2 — the record's own claim vs the message's declaration.
        # Checked first because it is the more specific finding: the label is not merely
        # inconsistent with the session, it is inconsistent with the payload it labels.
        forged = self._contradicting_subjects(message.content, str(current))
        if forged:
            return Verdict(
                agent_name=self.name, label=Label.BLOCK, score=1.0,
                reason=(f"subject forgery: content asserts data subject "
                        f"{', '.join(repr(s) for s in forged)} but the message is "
                        f"declared as '{current}'; the payload contradicts its own label"),
            )

        # BINDING 3 — a scope the application declared, if it declared one. Checked
        # before binding 1 because it REPLACES it: where a session legitimately covers
        # several subjects, "the first one seen" is not the right question to ask.
        scope = self._declared_scope(message, context)
        if scope is not None:
            if str(current) in scope:
                return self._pass(
                    f"data_subject '{current}' is within the session's declared scope "
                    f"({', '.join(sorted(scope))})")
            return Verdict(
                agent_name=self.name, label=Label.BLOCK, score=1.0,
                reason=(f"out of session scope: data_subject '{current}' is not among "
                        f"the {len(scope)} subject(s) this session declared"),
            )

        # BINDING 1 — the session's bound subject vs the message's declaration. The
        # fallback when nothing was declared, and still what catches an attack that
        # declares nothing.
        bound = self._session_subject(context)
        if bound is None or str(bound) == str(current):
            return self._pass(
                f"data_subject '{current}' matches the session's subject")

        return Verdict(
            agent_name=self.name, label=Label.BLOCK, score=1.0,
            reason=(f"cross-subject contamination (TC4): data_subject '{current}' does "
                    f"not match the session's bound subject '{bound}'"),
        )

    def _contradicting_subjects(self, content: str, declared: str) -> list[str]:
        """Subjects the CONTENT claims, which are not the subject the message declares.

        Two ways a record can assert whose it is. A bracketed marker — the convention a
        structured record uses — or the subject simply NAMED in the text, which is what a
        narrative note, a JSON payload or a chat transcript does. Reading only the first
        made content binding a property of one record format: measured in the
        `record_format` family, a subject-forgery attack delivered as prose asserted
        nothing this agent could see (task N1).

        Only strings matching a configured known subject count, in either form, so an
        unconfigured agent returns nothing and ordinary prose cannot be mistaken for a
        subject claim. That is what keeps the bare-text check from firing on a word that
        merely resembles a label.
        """
        if not self.known_subjects:
            return []
        asserted = {m.strip() for m in self._marker.findall(content or "")}
        text = content or ""
        asserted |= {s for s in self.known_subjects if s in text}
        return sorted((asserted & self.known_subjects) - {declared})

    def _declared_scope(self, message: Message,
                        context: dict[str, Any]) -> Optional[frozenset]:
        """The subjects this session declared it covers, or None if it declared nothing.

        Read from the CURRENT message and from the session's history, so a scope stated
        on the opening hop still governs later ones. A session that declares a scope
        partway through is honoured from that point — the alternative, ignoring it,
        would make the field depend on hop ordering for no security benefit.

        Empty and whitespace-only declarations are treated as no declaration at all: an
        empty scope would otherwise refuse every subject including the session's own,
        which is a failure mode nobody intends by leaving a field blank.
        """
        subjects: set[str] = set()
        for m in [message, *context.get("history", [])]:
            raw = (m.metadata or {}).get(self.scope_key)
            if raw:
                subjects |= {x.strip() for x in str(raw).split(",") if x.strip()}
        return frozenset(subjects) if subjects else None

    def _session_subject(self, context: dict[str, Any]) -> Optional[str]:
        """The subject this session is bound to = the first data_subject seen in lineage.

        The orchestrator records a hop only AFTER deciding it, and only when it was not
        blocked, so history holds the session's prior DELIVERED hops and not the current
        one. On the first subject-bearing hop history is therefore empty, `bound` is None
        and the message is allowed — it is what binds the session. A later hop carrying a
        different subject is what trips the block.

        Because refused hops never reach the store, an attacker whose message is blocked
        cannot bind the session to their subject and deny service to everyone after them
        (issue #15).
        """
        for m in context.get("history", []):
            subject = (m.metadata or {}).get(self.subject_key)
            if subject:
                return str(subject)
        return None

    def _pass(self, reason: str) -> Verdict:
        return Verdict(agent_name=self.name, label=Label.PASS, score=0.0, reason=reason)