"""Task I2 — an authorized partner is external AND permitted.

Before this, `partner@trusted-<domain>.org` was written into scenario metadata and never
passed to any agent, so a legitimate referral to a partner clinic was indistinguishable
from an exfiltration attempt. Those 24 scenarios were the ENTIRE false-positive rate of
the system: 20% overall, and 100% of the one benign family that tests it.

These tests pin both halves of the fix — the partner is allowed, and nothing else became
allowed with it. The second half matters more: an allowlist that is too generous turns a
false-positive fix into a false-negative one, which is a far worse trade.
"""
from __future__ import annotations

import pytest

from haris.agents.authorization import AuthorizationAgent
from haris.agents.infoflow import InformationFlowAgent
from haris.schemas.message import Message
from haris.schemas.verdict import Label

from demo_app.eval.baselines import haris
from demo_app.eval.domains import DOMAINS, HOSPITAL
from demo_app.eval.generate import generate

PARTNER = "partner@trusted-hospital.org"
OUTSIDER = "outside@example.com"
RECORD = "[patient-A]\nName: Robert Roberts\nMRN: MRN-4821\nDetail: type 2 diabetes"


@pytest.fixture(scope="module")
def scenarios():
    return generate()


def _msg(recipient, content="Following up on MRN-4821 for Robert Roberts.",
         data_type="note"):
    md = {"data_type": data_type, "data_subject": "patient-A", "auth_token": "t"}
    if recipient is not None:
        md["recipient"] = recipient
    return Message(session_id="s", sender="summarizer", receiver="emailer",
                   content=content, metadata=md)


def _history():
    return [Message(session_id="s", sender="record_reader", receiver="summarizer",
                    content=RECORD,
                    metadata={"data_type": "PHI", "data_subject": "patient-A"})]


# --------------------------------------------------------------------------- #
# Info-flow: tainted content may reach a partner
# --------------------------------------------------------------------------- #

def _infoflow(partners=()):
    return InformationFlowAgent(source_data_type="PHI", detector=None,
                                internal_domains=("hospital.internal",),
                                authorized_partners=partners)


def test_partner_destination_is_permitted():
    v = _infoflow((PARTNER,)).check(_msg(PARTNER), {"history": _history()})
    assert v.label is Label.PASS
    assert "partner" in v.reason


def test_unconfigured_agent_still_flags_the_partner():
    """Backwards compatibility, and the proof that the config is what changed —
    not the detection logic."""
    v = _infoflow().check(_msg(PARTNER), {"history": _history()})
    assert v.label is Label.FLAG


def test_a_partner_allowlist_does_not_permit_anyone_else():
    """The important half: allowing one address must not weaken the boundary."""
    v = _infoflow((PARTNER,)).check(_msg(OUTSIDER), {"history": _history()})
    assert v.label is Label.FLAG


def test_partner_match_is_exact_not_by_domain():
    """`partner@trusted-hospital.org` being allowed must not allow
    `anyone-else@trusted-hospital.org` — the agreement is with an address."""
    v = _infoflow((PARTNER,)).check(_msg("anyone-else@trusted-hospital.org"),
                                    {"history": _history()})
    assert v.label is Label.FLAG


def test_a_forged_source_label_still_cannot_egress_to_an_outsider():
    """The data_type=PHI origin exemption is still gated on the destination."""
    v = _infoflow((PARTNER,)).check(_msg(OUTSIDER, content=RECORD, data_type="PHI"),
                                    {"history": _history()})
    assert v.label is Label.FLAG


# --------------------------------------------------------------------------- #
# Authorization: sensitive types may reach a partner, nobody else
# --------------------------------------------------------------------------- #

def _authz(partners=()):
    return AuthorizationAgent(internal_domain="@hospital.internal",
                              sensitive_types=("PHI", "summary", "credential"),
                              authorized_partners=partners)


def test_sensitive_type_to_a_partner_is_allowed():
    v = _authz((PARTNER,)).check(_msg(PARTNER, data_type="summary"), {})
    assert v.label is Label.PASS


def test_sensitive_type_to_an_outsider_is_still_blocked():
    v = _authz((PARTNER,)).check(_msg(OUTSIDER, data_type="summary"), {})
    assert v.label is Label.BLOCK


def test_unconfigured_authz_blocks_the_partner():
    v = _authz().check(_msg(PARTNER, data_type="summary"), {})
    assert v.label is Label.BLOCK


# --------------------------------------------------------------------------- #
# The corpus
# --------------------------------------------------------------------------- #

def test_every_domain_declares_its_partner():
    for d in DOMAINS.values():
        assert d.authorized_partners, d.name
        assert d.authorized_partners == (f"partner@trusted-{d.name}.org",), d.name


def test_the_partner_matches_what_the_generator_addresses(scenarios):
    """If these ever drift apart the false positives come straight back."""
    for scn in [s for s in scenarios if s.family == "authorized_external"]:
        declared = set(DOMAINS[scn.domain].authorized_partners)
        addressed = {m.metadata.get("recipient") for m in scn.messages
                     if m.metadata.get("recipient")}
        assert declared & addressed, scn.id


def test_authorized_external_is_no_longer_a_false_positive(scenarios):
    for scn in [s for s in scenarios if s.family == "authorized_external"]:
        assert not haris(scn).stopped, f"{scn.id}: still a false positive"


def test_the_other_benign_families_are_unaffected(scenarios):
    for family in ("internal_clean", "internal_derived", "near_miss_benign",
                   "same_subject"):
        for scn in [s for s in scenarios if s.family == family]:
            assert not haris(scn).stopped, scn.id


def test_no_attack_family_became_permitted(scenarios):
    """The false-positive fix must not have bought anything on the attack side."""
    expected_missed = {"external_paraphrase"}   # the documented semantic gap
    for scn in [s for s in scenarios if s.is_attack]:
        if scn.family in expected_missed:
            continue
        assert haris(scn).stopped, f"{scn.id}: attack became permitted"
