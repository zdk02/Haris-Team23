"""Issue #14 — weak signals corroborate, and a strong identifier cannot leave quietly.

Three defects, all measured before they were fixed:

  1. `max()` across findings meant the strongest one decided alone. The module docstring
     said weak entities "matter in the company of strong ones"; no quantity of weak
     evidence ever changed an answer.
  2. A detected US_SSN addressed to an external recipient returned PASS at severity 0.4
     while naming US_SSN in its own explanation — a verdict contradicting its own reason,
     and recorded that way in the audit log, which is worse than a silent miss.
  3. `DEFAULT_PII_MIN_SCORE = 0.4` discarded US_DRIVER_LICENSE, which Presidio's own
     recogniser scores at 0.3, before weighting ever ran.

These tests use synthetic findings and the boundary helper rather than live Presidio, so
they run without the spaCy model and pin the POLICY rather than the detector's recall.
"""
from __future__ import annotations

import pytest

from haris.agents.secrets_pii import (
    DEFAULT_FLOOR_ENTITIES, Finding, SecretsPIIAgent, _combine,
)
from haris.schemas.message import Message
from haris.schemas.verdict import Label


# --------------------------------------------------------------------------- #
# 1. Weak signals corroborate
# --------------------------------------------------------------------------- #

def test_one_finding_is_unchanged():
    """Nothing that flagged before may stop flagging: a single finding keeps its score."""
    assert _combine([0.85]) == pytest.approx(0.85)
    assert _combine([]) == 0.0


def test_two_weak_findings_exceed_either_alone():
    """THE DEFECT. Under max() these stayed at 0.3 however many arrived."""
    assert _combine([0.3, 0.3]) == pytest.approx(0.51)
    assert _combine([0.3, 0.3, 0.3]) == pytest.approx(0.657, abs=1e-3)


def test_combination_is_monotone_and_bounded():
    """Adding evidence must never lower the score, and must never exceed 1.0 — the two
    properties a security control needs and a mean does not have."""
    growing = [_combine([0.4] * n) for n in range(1, 6)]
    assert growing == sorted(growing)
    assert all(v <= 1.0 for v in growing)
    assert _combine([0.99, 0.99, 0.99]) <= 1.0


def test_three_weak_signals_now_clear_the_default_threshold():
    """The behaviour the docstring always described: weak entities matter together."""
    assert _combine([0.3, 0.3, 0.3]) > 0.5


# --------------------------------------------------------------------------- #
# 2. The egress hard floor
# --------------------------------------------------------------------------- #

def _agent(**kw):
    """An agent with stub detectors, so this tests the policy and not Presidio."""
    class _NoPII:
        def analyze(self, text):
            return []

        def redact(self, text, results=None):
            return "[REDACTED]"

    class _NoSecrets:
        def scan(self, text):
            return []

    return SecretsPIIAgent(pii_detector=_NoPII(), secrets_detector=_NoSecrets(),
                           internal_domains=("hospital.internal",), **kw)


def _msg(recipient):
    md = {"data_type": "note", "data_subject": "patient-A", "auth_token": "t"}
    if recipient:
        md["recipient"] = recipient
    return Message(session_id="s", sender="summarizer", receiver="emailer",
                   content="Patient SSN 221974444 attached.", metadata=md)


def test_the_floor_entities_are_the_ones_that_matter():
    """Government identifiers and payment instruments. If this list shrinks, say why."""
    assert {"US_SSN", "CREDIT_CARD", "IBAN_CODE"} <= set(DEFAULT_FLOOR_ENTITIES)


def test_a_detected_ssn_cannot_pass_to_an_external_recipient(monkeypatch):
    """THE REPRODUCTION from the issue. Severity 0.4 is below the 0.5 threshold, so under
    the old logic this returned PASS while its own reason named US_SSN."""
    agent = _agent()
    monkeypatch.setattr(agent, "_to_findings",
                        lambda p, s: [Finding(kind="pii", entity_type="US_SSN",
                                              severity=0.4)])
    v = agent.check(_msg("attacker@evil.com"), {})
    assert v.label is Label.FLAG
    assert "US_SSN" in v.reason


def test_the_same_ssn_is_allowed_inside_the_boundary(monkeypatch):
    """Egress only. A record contains these values by definition, and flagging every
    internal hop would refuse the system's ordinary work."""
    agent = _agent()
    monkeypatch.setattr(agent, "_to_findings",
                        lambda p, s: [Finding(kind="pii", entity_type="US_SSN",
                                              severity=0.4)])
    v = agent.check(_msg("doctor@hospital.internal"), {})
    assert v.label is Label.PASS


def test_a_weak_non_floor_entity_still_passes_at_egress(monkeypatch):
    """The floor is narrow on purpose. A lone DATE_TIME leaving the boundary is not an
    incident, and a floor that caught everything would be an egress block wearing a
    detector's clothes."""
    agent = _agent()
    monkeypatch.setattr(agent, "_to_findings",
                        lambda p, s: [Finding(kind="pii", entity_type="DATE_TIME",
                                              severity=0.3)])
    v = agent.check(_msg("attacker@evil.com"), {})
    assert v.label is Label.PASS


def test_the_floored_verdict_carries_redacted_content(monkeypatch):
    """A flag without redacted content resolves to a bare FLAG in the policy engine, so
    the message would still be delivered intact. The floor has to redact to mean
    anything."""
    agent = _agent()
    monkeypatch.setattr(agent, "_to_findings",
                        lambda p, s: [Finding(kind="pii", entity_type="CREDIT_CARD",
                                              severity=0.2)])
    v = agent.check(_msg("attacker@evil.com"), {})
    assert v.label is Label.FLAG
    assert v.redacted_content is not None
