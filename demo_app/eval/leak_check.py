"""Did a secret actually reach somewhere it should not?

WHY THIS EXISTS.
Until now the evaluation asked "did Haris say block or redact?" — success was defined by the
system's own verdicts. That makes every arm's score a statement about what a detector
CLAIMED, not about what happened to the data. It also made the "without Haris" arm
meaningless: running zero agents in monitor mode always yields ALLOW, so its 100% leak rate
was fixed before the run started.

This module defines leakage independently of any detector:

    a scenario LEAKED if content that reached an unauthorised recipient
    still carried the secret that was injected into it.

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
from typing import Iterable, Optional

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


def leaked(delivered: list[Message], identifiers: Iterable[str],
           authorized: Iterable[str], internal_domain: str) -> bool:
    """True iff any DELIVERED message reached an unauthorised recipient still carrying an
    injected identifier.

    `delivered` is what actually arrived — blocked messages are absent, redacted ones are
    present in their scrubbed form. That is the whole point: the metric reads outcomes, not
    verdicts.
    """
    idents = [str(i) for i in identifiers
              if i and len(str(i)) >= MIN_IDENTIFIER_LEN]
    for m in delivered:
        if not unauthorised((m.metadata or {}).get("recipient"), authorized, internal_domain):
            continue
        if any(carries(i, m.content) for i in idents):
            return True
    return False


def egresses(messages: list[Message], authorized: Iterable[str],
             internal_domain: str) -> bool:
    """Does this scenario contain any hop addressed outside the authorised set at all?

    Scenarios that do not (spoof, subject_mismatch) are policy violations rather than
    exfiltration: they are real attacks, but no data leaves, so scoring them under
    "leak prevention" inflates that denominator with cases that cannot leak.
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
