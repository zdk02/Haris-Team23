"""Partner agreements — an external address, and WHOSE data it may receive.

An earlier version of this concept was a flat allowlist of addresses (task I2): a
recipient was either permitted or not, for everybody. That is not how a data-sharing
agreement works. A hospital's referral arrangement with a clinic covers the patients who
consented to it, not every patient on the system; a payments processor may receive the
accounts it settles and no others. "May we send to this address" and "may we send THIS
PERSON'S data to this address" are different questions, and only the second one is the
one a data-protection officer actually asks.

Shared by AuthorizationAgent and InformationFlowAgent so the two cannot drift: a partner
permitted by one and refused by the other would be a silent policy split.

Two shapes are accepted, so an existing deployment does not have to change:
    "partner@clinic.org"                       -> permitted for ANY data subject
    ("partner@clinic.org", ("patient-A",))     -> permitted for patient-A only
"""
from __future__ import annotations

from typing import Iterable, Mapping, Optional

_MISSING = object()

# address -> frozenset of permitted subjects, or None meaning "any subject"
PartnerMap = Mapping[str, Optional[frozenset]]


def normalise_partners(spec: Iterable) -> dict[str, Optional[frozenset]]:
    """Accept bare addresses or (address, subjects) pairs; key by lowercased address."""
    out: dict[str, Optional[frozenset]] = {}
    for entry in spec or ():
        if isinstance(entry, str):
            out[entry.lower()] = None                      # unscoped agreement
            continue
        address, subjects = entry
        scope = frozenset(str(s) for s in subjects)
        out[str(address).lower()] = scope or None          # empty tuple == unscoped
    return out


def partner_allows(partners: PartnerMap, recipient: Optional[str],
                   subject: Optional[str]) -> bool:
    """Does an agreement permit sending THIS subject's data to THIS recipient?

    A scoped agreement refuses a message with no declared subject. That is deliberate and
    it fails closed: if we cannot tell whose data this is, we cannot tell whether the
    agreement covers it, and the safe reading of an unlabelled message is not "everyone
    consented".
    """
    if not recipient:
        return False
    scope = partners.get(str(recipient).lower(), _MISSING)
    if scope is _MISSING:
        return False                                        # not a partner at all
    if scope is None:
        return True                                         # unscoped agreement
    return subject is not None and str(subject) in scope
