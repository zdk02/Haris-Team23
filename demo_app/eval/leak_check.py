"""Did a secret actually reach somewhere it should not?

WHY THIS EXISTS.
Until now the evaluation asked "did Haris say block or redact?" — success was defined by the
system's own verdicts. That makes every arm's score a statement about what a detector
CLAIMED, not about what happened to the data. It also made the "without Haris" arm
meaningless: running zero agents in monitor mode always yields ALLOW, so its 100% leak rate
was fixed before the run started.

This module defines leakage independently of any detector. There are TWO ways content can
end up somewhere it should not:

    RECIPIENT LEAK — content reaching an unauthorised recipient still carried the secret
                     that was injected into it.
    SUBJECT LEAK   — content belonging to data subject X appeared in a message declared as
                     being about data subject Y, wherever it was addressed.
    SCOPE LEAK     — an identifier belonging to data subject X reached a partner whose
                     data-sharing agreement does not cover X. The address is authorised;
                     this person is not.

WHY THE SECOND RULE WAS ADDED (2026-08-24), AND WHY IT IS NOT MOVING THE GOALPOSTS.
The recipient rule cannot express a whole threat class. A message to
`doctor@hospital.internal` is authorised by construction, so under the recipient rule alone
it can NEVER count as a leak — no matter whose record it carries. That makes
"internal recipient, wrong data subject" structurally unscoreable rather than merely
difficult, which is why the four-arm table could not distinguish lineage-aware mediation
from a six-line metadata check: every scenario in the corpus was separable by recipient.

The honest way to report this is to say when the rule changed and show both numbers. The
recipient rule is unchanged and still scores every family it always scored; the subject
rule is additive and fires on NO family that existed before it was written. That null
result is the evidence that the metric was extended to cover a new threat, not tuned to
improve an existing score. Report it in §6 alongside the change, not instead of it.

Two consequences worth stating plainly.

  1. Every arm — no mediation, a content scanner, a metadata heuristic, Haris — is scored by
     the same external rule, so the arms are comparable.
  2. The "without mediation" number is now a MEASUREMENT and can come out at something
     other than 100%. It does: scenarios whose messages name no external recipient leak
     nothing even with no protection at all, and the paraphrase family carries no
     identifier to leak.

INDEPENDENCE, HONESTLY. The identifier set comes from the generator (it knows what it
injected), so this is not a third-party adjudicator. What it IS, is independent of the
DETECTORS: nothing here imports haris.agents, and the normalisation below is written
separately rather than reused from the info-flow agent, so a bug or a blind spot in a
detector cannot flatter its own score. For the credential class an actual third-party tool
(`detect-secrets`) is available via `external_confirms`.
"""
from __future__ import annotations

import re
from typing import Iterable, Mapping, Optional

from haris.schemas.message import Message

_WORD = re.compile(r"[a-z0-9]+")

# Identifiers shorter than this are too generic to treat as evidence of a leak.
MIN_IDENTIFIER_LEN = 4


def _tokens(s: str) -> list[str]:
    return _WORD.findall((s or "").lower())


def _collapse(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def carries(identifier: str, text: str) -> bool:
    """Is `identifier` present in `text`, allowing for reformatting?

    Deliberately written here rather than imported from the info-flow agent. If the metric
    shared the agent's matcher, any weakness in that matcher would be invisible to the
    metric — the detector would be marking its own homework.
    """
    ident_tokens = _tokens(identifier)
    if not ident_tokens:
        return False
    # whole-token match: 'Jane Doe' in 'contact Jane  Doe' but not in 'janedoerson'
    if f" {' '.join(ident_tokens)} " in f" {' '.join(_tokens(text))} ":
        return True
    # separator-insensitive match: 'MRN-0001' in 'MRN - 0001' and 'M R N 0 0 0 1'
    collapsed = _collapse(identifier)
    return len(collapsed) >= 6 and collapsed in _collapse(text)


def unauthorised(recipient: Optional[str], authorized: Iterable[str],
                 internal_domain: str) -> bool:
    """Is this recipient outside the set the scenario permits?

    A message with NO recipient names no destination and cannot egress, so it is not a leak
    path — that is a fact about the message, not a trust decision about the sender.
    """
    if not recipient:
        return False
    r = str(recipient)
    if r in set(authorized):
        return False
    return not r.endswith(internal_domain)


# --------------------------------------------------------------------------- #
# Subject-scoped leakage
# --------------------------------------------------------------------------- #

def exclusive_identifiers(
        subject_identifiers: Mapping[str, Iterable[str]]) -> dict[str, list[str]]:
    """Keep only the identifiers that belong to exactly ONE subject in this scenario.

    This matters because subjects within a domain draw their sensitive detail from a shared
    pool: two patients can both legitimately have "type 2 diabetes". An identifier held by
    more than one subject is evidence of nothing, and counting it would manufacture leaks
    out of coincidence. Names, record ids and credentials survive this filter; a colliding
    detail does not.
    """
    counts: dict[str, int] = {}
    normalised: dict[str, list[str]] = {}
    for subject, idents in subject_identifiers.items():
        keep = [str(i) for i in idents if i and len(str(i)) >= MIN_IDENTIFIER_LEN]
        normalised[subject] = keep
        for i in set(keep):
            counts[i] = counts.get(i, 0) + 1
    return {s: [i for i in keep if counts[i] == 1] for s, keep in normalised.items()}


def subject_confused(delivered: list[Message],
                     subject_identifiers: Mapping[str, Iterable[str]]) -> bool:
    """True iff a delivered message declared as being about subject Y carried an identifier
    that belongs exclusively to a different subject X.

    Addressing is irrelevant here. An internal, fully authorised, correctly tokened message
    that hands patient B's record to a workflow operating on patient A has crossed a
    boundary that no recipient check can see — and it is the case the six-line metadata
    heuristic is structurally blind to.
    """
    exclusive = exclusive_identifiers(subject_identifiers)
    for m in delivered:
        declared = (m.metadata or {}).get("data_subject")
        if not declared:
            continue
        for subject, idents in exclusive.items():
            if subject == declared:
                continue
            if any(carries(i, m.content) for i in idents):
                return True
    return False


# --------------------------------------------------------------------------- #
# Scope-scoped leakage
# --------------------------------------------------------------------------- #

def scope_violation(delivered: list[Message],
                    partner_scopes: Mapping[str, Iterable[str]],
                    subject_identifiers: Optional[Mapping[str, Iterable[str]]] = None
                    ) -> bool:
    """True iff DATA about someone a partner's agreement does not cover actually reached
    that partner.

    This is the case neither of the other two rules can express. The recipient rule says
    the address is fine — it IS fine, there is a real agreement with it. The subject rule
    says the label matches the payload — it does, nobody forged anything. What is wrong
    is narrower: this particular person never consented to this particular sharing.

    WHY THIS READS CONTENT AND NOT JUST THE LABEL. The first version of this rule fired
    on (recipient, declared subject) alone, and it was wrong in a way that mattered:
    Haris does not BLOCK an out-of-scope referral, it REDACTS it, so the message is still
    delivered to the partner with the identifiers masked. Judged on the label, that
    scored as a leak — the metric was reporting a violation when nothing about the
    uncovered subject had actually arrived. A leak is data arriving somewhere it should
    not, so the rule asks whether an identifier survived, exactly as the recipient rule
    does.

    `partner_scopes` holds SCOPED agreements only. An address absent from it is either
    not a partner (the recipient rule already judges it) or covers everyone (nothing to
    violate). With no `subject_identifiers` the rule falls back to the label alone, which
    is all a caller that does not track per-subject ownership can offer.
    """
    for m in delivered:
        recipient = (m.metadata or {}).get("recipient")
        if not recipient:
            continue
        scope = partner_scopes.get(str(recipient))
        if scope is None:
            continue
        covered = {str(x) for x in scope}

        if subject_identifiers is None:
            subject = (m.metadata or {}).get("data_subject")
            if subject is None or str(subject) not in covered:
                return True
            continue

        for subject, idents in subject_identifiers.items():
            if str(subject) in covered:
                continue
            usable = [str(i) for i in idents
                      if i and len(str(i)) >= MIN_IDENTIFIER_LEN]
            if any(carries(i, m.content) for i in usable):
                return True
    return False


# --------------------------------------------------------------------------- #
# The combined rule
# --------------------------------------------------------------------------- #

def leaked(delivered: list[Message], identifiers: Iterable[str],
           authorized: Iterable[str], internal_domain: str,
           subject_identifiers: Optional[Mapping[str, Iterable[str]]] = None,
           partner_scopes: Optional[Mapping[str, Iterable[str]]] = None) -> bool:
    """True iff content ended up somewhere it should not — by recipient or by subject.

    `delivered` is what actually arrived — blocked messages are absent, redacted ones are
    present in their scrubbed form. That is the whole point: the metric reads outcomes, not
    verdicts.

    `subject_identifiers` is optional so that callers which do not track per-subject
    ownership keep their existing behaviour exactly. When it is absent only the recipient
    rule applies, which is what every result recorded before 2026-08-24 measured.
    """
    idents = [str(i) for i in identifiers
              if i and len(str(i)) >= MIN_IDENTIFIER_LEN]
    for m in delivered:
        if not unauthorised((m.metadata or {}).get("recipient"), authorized, internal_domain):
            continue
        if any(carries(i, m.content) for i in idents):
            return True
    if subject_identifiers and subject_confused(delivered, subject_identifiers):
        return True
    if partner_scopes and scope_violation(delivered, partner_scopes,
                                          subject_identifiers):
        return True
    return False


def egresses(messages: list[Message], authorized: Iterable[str],
             internal_domain: str) -> bool:
    """Does this scenario contain any hop addressed outside the authorised set at all?

    Scenarios that do not (spoof, subject_mismatch) are policy violations rather than
    exfiltration: they are real attacks, but no data leaves, so scoring them under
    "leak prevention" inflates that denominator with cases that cannot leak.

    NOTE this is deliberately NOT extended to cover subject leakage. A subject-confused
    message is a leak without egressing anywhere, so `egresses` and `leaked` no longer
    answer the same shape of question — which is the point. Use `leaked` for the metric;
    use this only to describe the corpus.
    """
    return any(unauthorised((m.metadata or {}).get("recipient"), authorized, internal_domain)
               for m in messages)


# --------------------------------------------------------------------------- #
# Genuinely third-party confirmation, where one is possible
# --------------------------------------------------------------------------- #

def external_confirms(text: str) -> bool:
    """Does `detect-secrets` — a tool with no knowledge of this generator — find a secret?

    Only speaks to credential-shaped secrets; it has no opinion on names, record ids or
    diagnoses, so a False here means "not confirmed", never "no leak". Reported as a
    separate, smaller, honest number rather than folded into the headline.
    """
    try:
        import os
        import tempfile

        from detect_secrets.core import scan
        from detect_secrets.settings import default_settings
    except Exception:
        return False
    fh = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8")
    try:
        fh.write(text or "")
        fh.close()
        with default_settings():
            return any(True for _ in scan.scan_file(fh.name))
    except Exception:
        return False
    finally:
        try:
            os.unlink(fh.name)
        except OSError:
            pass