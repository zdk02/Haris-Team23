"""Task I3 — an address that merely RESEMBLES the trust boundary.

`doctor@hospital.internal.evil.com` is a domain an attacker can register today. It ends
with the string `hospital.internal`, so any boundary check written as a bare
`recipient.endswith(internal_domain)` treats it as inside the trust boundary and permits
everything: tainted content, sensitive data types, unredacted PII.

Four independent places decide "is this internal", in three agents and in the metric.
They have to agree, and they have to agree on the SAFE answer. This file probes all four
with the same set of lookalikes, because a boundary that holds in three places and leaks
in the fourth is not a boundary.

If any of these fail, it is a live vulnerability rather than a false positive, and it
outranks everything else on the board.
"""
from __future__ import annotations

import pytest

from haris.agents.authorization import AuthorizationAgent
from haris.agents.infoflow import InformationFlowAgent
from haris.schemas.message import Message
from haris.schemas.verdict import Label

from demo_app.eval.leak_check import unauthorised

INTERNAL = "hospital.internal"
RECORD = "[patient-A]\nName: Robert Roberts\nMRN: MRN-4821\nDetail: type 2 diabetes"

# Every one of these is registrable by an attacker and none is inside the boundary.
LOOKALIKES = [
    "doctor@hospital.internal.evil.com",   # the boundary as a prefix of a longer domain
    "doctor@evil-hospital.internal",       # the boundary as a suffix of a longer label
    "doctor@hospital.internal.co",         # a different TLD entirely
    "doctor@nothospital.internal",         # a longer label ending in the boundary
    "hospital.internal@evil.com",          # the boundary in the LOCAL part
    "doctor@HOSPITAL.INTERNAL.EVIL.COM",   # and the same trick in another case
]

GENUINELY_INTERNAL = [
    "doctor@hospital.internal",
]

# A DELEGATED SUBDOMAIN is not inside the boundary, and this is a decision rather than an
# accident. Whoever runs `ward3` is a different party from whoever runs the parent domain,
# so inheriting the organisation's trust for free is exactly how a compromised
# departmental server becomes a data exfiltration route. A deployment that wants one
# lists it explicitly - `internal_domains` accepts several.
#
# Found on 2026-08-25 by this file: InformationFlowAgent accepted subdomains while
# AuthorizationAgent and the metric refused them, so one address was simultaneously inside
# the boundary and outside it depending on which agent you asked. No scenario exercised
# it; a reviewer typing one address would have.
DELEGATED = [
    "nurse@ward3.hospital.internal",
    "svc@backup.hospital.internal",
]


def _msg(recipient, content=RECORD, data_type="note"):
    return Message(session_id="s", sender="summarizer", receiver="emailer",
                   content=content,
                   metadata={"data_type": data_type, "data_subject": "patient-A",
                             "recipient": recipient, "auth_token": "t"})


def _history():
    return [Message(session_id="s", sender="record_reader", receiver="summarizer",
                    content=RECORD,
                    metadata={"data_type": "PHI", "data_subject": "patient-A"})]


# --------------------------------------------------------------------------- #
# 1. InformationFlowAgent — tainted content must not reach a lookalike
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("recipient", LOOKALIKES)
def test_infoflow_refuses_a_lookalike(recipient):
    agent = InformationFlowAgent(source_data_type="PHI", detector=None,
                                 internal_domains=(INTERNAL,))
    v = agent.check(_msg(recipient, content="Following up on MRN-4821 for Robert Roberts."),
                    {"history": _history()})
    assert v.label is Label.FLAG, f"{recipient} was treated as inside the boundary"


@pytest.mark.parametrize("recipient", GENUINELY_INTERNAL)
def test_infoflow_still_allows_the_real_boundary(recipient):
    """The check must not be so strict that legitimate internal traffic breaks."""
    agent = InformationFlowAgent(source_data_type="PHI", detector=None,
                                 internal_domains=(INTERNAL,))
    v = agent.check(_msg(recipient, content="Following up on MRN-4821 for Robert Roberts."),
                    {"history": _history()})
    assert v.label is Label.PASS, f"{recipient} is inside the boundary and was refused"


# --------------------------------------------------------------------------- #
# 2. AuthorizationAgent — sensitive types must not reach a lookalike
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("recipient", LOOKALIKES)
def test_authorization_refuses_a_lookalike(recipient):
    agent = AuthorizationAgent(internal_domain="@" + INTERNAL,
                               sensitive_types=("PHI", "summary", "credential"))
    v = agent.check(_msg(recipient, data_type="summary"), {})
    assert v.label is Label.BLOCK, f"{recipient} received a sensitive data type"


@pytest.mark.parametrize("recipient", GENUINELY_INTERNAL)
def test_authorization_still_allows_the_real_boundary(recipient):
    agent = AuthorizationAgent(internal_domain="@" + INTERNAL,
                               sensitive_types=("PHI", "summary", "credential"))
    assert agent.check(_msg(recipient, data_type="summary"), {}).label is Label.PASS


# --------------------------------------------------------------------------- #
# 3. SecretsPIIAgent — PII must be redacted on the way to a lookalike
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("recipient", LOOKALIKES)
def test_secrets_pii_treats_a_lookalike_as_egress(recipient):
    """Checked at the boundary helper rather than through Presidio, so the test runs
    without the spaCy model and pins the POLICY rather than the detector."""
    from haris.agents.secrets_pii import SecretsPIIAgent
    agent = SecretsPIIAgent.__new__(SecretsPIIAgent)     # no detectors needed
    agent.internal_domains = (INTERNAL,)
    agent.authorized_partners = {}
    agent.treat_missing_recipient_as_internal = True
    assert agent._is_egress(_msg(recipient)), f"{recipient} was treated as a safe hop"


# --------------------------------------------------------------------------- #
# 4. The metric — a lookalike must count as an unauthorised recipient
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("recipient", LOOKALIKES)
def test_the_metric_counts_a_lookalike_as_unauthorised(recipient):
    """If the METRIC thought a lookalike was internal, a leak to it would not be scored
    as a leak — the evaluation would report success on a genuine exfiltration."""
    assert unauthorised(recipient, ["doctor@hospital.internal"], "@" + INTERNAL), \
        f"{recipient} would not be scored as a leak"


@pytest.mark.parametrize("recipient", GENUINELY_INTERNAL)
def test_the_metric_does_not_count_the_real_boundary(recipient):
    assert not unauthorised(recipient, [], "@" + INTERNAL)


# --------------------------------------------------------------------------- #
# 5. All three boundary checks must give the SAME answer
# --------------------------------------------------------------------------- #

def _all_three_say_internal(recipient: str) -> tuple[bool, bool, bool]:
    from haris.agents.secrets_pii import SecretsPIIAgent

    infoflow = InformationFlowAgent(source_data_type="PHI", detector=None,
                                    internal_domains=(INTERNAL,))
    pii = SecretsPIIAgent.__new__(SecretsPIIAgent)
    pii.internal_domains = (INTERNAL,)
    authz = AuthorizationAgent(internal_domain="@" + INTERNAL)

    return (
        infoflow._is_internal(recipient),
        pii._is_internal(recipient),
        not authz._is_unauthorized_external(recipient),
    )


@pytest.mark.parametrize("recipient", LOOKALIKES + GENUINELY_INTERNAL + DELEGATED)
def test_the_three_boundary_checks_agree(recipient):
    """A boundary that holds in two agents and not the third is not a boundary. This is
    the test that caught the subdomain disagreement; keep it parametrised over every
    address the others use, so a new case is checked for consistency automatically."""
    answers = _all_three_say_internal(recipient)
    assert len(set(answers)) == 1, (
        f"{recipient}: infoflow={answers[0]}, secrets_pii={answers[1]}, "
        f"authorization={answers[2]} — the agents disagree about the trust boundary")


@pytest.mark.parametrize("recipient", DELEGATED)
def test_a_delegated_subdomain_is_outside_the_boundary(recipient):
    """Strict by choice: a subdomain is a delegation to a party that is not us. The
    fail-closed reading matches the posture taken for undeclared destinations and for
    partner agreements, both of which require an explicit listing."""
    assert all(not a for a in _all_three_say_internal(recipient)), recipient


@pytest.mark.parametrize("recipient", DELEGATED)
def test_a_subdomain_can_be_admitted_by_configuration(recipient):
    """Strict is not a dead end: a deployment that really does run ward3 lists it, and
    the same address is then inside the boundary in every agent."""
    domain = recipient.split("@", 1)[1]
    agent = InformationFlowAgent(source_data_type="PHI", detector=None,
                                 internal_domains=(INTERNAL, domain))
    assert agent._is_internal(recipient)