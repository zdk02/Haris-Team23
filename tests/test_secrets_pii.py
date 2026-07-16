"""Unit tests for SecretsPIIAgent (Module 7).

Covers the two helpers in isolation (PIIDetector span+mask, SecretsDetector
scan+mask), the agent's verdicts on the threat-model cases (TC1 clean summary
passes, TC2 verbatim PHI flags with redacted content, planted credential
flags), the severity weighting that keeps weak DATE_TIME hits from
false-positiving clean traffic, and integration with the REAL policy engine
(resolve()) to prove an above-threshold FLAG + redacted_content becomes a
REDACT in ENFORCE mode and is clamped to FLAG in MONITOR mode.

Requires the spaCy model (en_core_web_sm by default); tests are skipped, not
failed, when Presidio can't load it.
"""

import pytest

from haris.agents.secrets_pii import PIIDetector, SecretsDetector, SecretsPIIAgent
from haris.schemas.message import Message
from haris.schemas.policy import Policy, Mode
from haris.schemas.verdict import Label
from haris.schemas.decision import Action
from haris.policy.engine import resolve
from demo_app.hospital.records import load_record, format_record

CTX: dict = {"history": []}

CLEAN_SUMMARY = ("The patient is recovering well and should follow up "
                 "in two weeks to review medication.")
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def _msg(content, sender="summarizer", receiver="emailer", **md):
    return Message(session_id="s1", sender=sender, receiver=receiver,
                   content=content, metadata=md)


# One detector/agent for the whole module: Presidio's spaCy load is slow.
@pytest.fixture(scope="module")
def agent():
    a = SecretsPIIAgent()
    try:
        a.pii.analyze("warm up")
    except Exception as exc:  # pragma: no cover - environment-dependent
        pytest.skip(f"Presidio/spaCy unavailable: {exc}")
    return a


# ---- helpers in isolation ----------------------------------------------------

def test_pii_detector_finds_and_masks_person(agent):
    det = agent.pii
    text = "Patient Jane Doe was admitted yesterday."
    results = det.analyze(text)
    assert any(r.entity_type == "PERSON" for r in results)
    masked = det.redact(text, results)
    assert "Jane Doe" not in masked
    assert "<PERSON>" in masked


def test_secrets_detector_scan_and_mask():
    det = SecretsDetector()
    text = f'config line: aws_key = "{AWS_KEY}"'
    hits = det.scan(text)
    assert any(AWS_KEY == value for _t, value in hits)
    masked = SecretsDetector.redact(text, hits)
    assert AWS_KEY not in masked and "<SECRET>" in masked


# ---- TC1: clean traffic must pass (no false positives) -----------------------

def test_tc1_clean_summary_passes(agent):
    v = agent.check(_msg(CLEAN_SUMMARY), CTX)
    assert v.label is Label.PASS
    assert v.redacted_content is None
    assert v.score < agent.flag_threshold  # weak DATE_TIME stays sub-threshold


# ---- TC2: verbatim PHI in an outbound message ---------------------------------

def test_tc2_verbatim_phi_flags_with_redaction(agent):
    record = format_record(load_record("patient-A"))  # contains "Jane Doe", DOB
    v = agent.check(_msg(record, recipient="outside@example.com"), CTX)
    assert v.label is Label.FLAG
    assert v.score >= agent.flag_threshold
    assert "PERSON" in v.reason
    assert v.redacted_content is not None
    assert "Jane Doe" not in v.redacted_content
    assert "<PERSON>" in v.redacted_content


def test_tc2_dob_also_masked_once_flagged(agent):
    record = format_record(load_record("patient-A"))
    v = agent.check(_msg(record), CTX)
    # DATE_TIME is a weak signal on its own, but once the message is flagged
    # (the PERSON hit), every detected span is masked — including the DOB.
    assert "1980-02-14" not in v.redacted_content


# ---- planted credential --------------------------------------------------------

def test_planted_credential_flags(agent):
    v = agent.check(_msg(f'forwarding creds: aws_key = "{AWS_KEY}"'), CTX)
    assert v.label is Label.FLAG
    assert "secrets:" in v.reason
    assert AWS_KEY not in v.redacted_content
    assert "<SECRET>" in v.redacted_content


def test_mixed_pii_and_credential(agent):
    text = f'Jane Doe uploaded her key: aws_key = "{AWS_KEY}"'
    v = agent.check(_msg(text), CTX)
    assert v.label is Label.FLAG
    assert "PII:" in v.reason and "secrets:" in v.reason
    assert "Jane Doe" not in v.redacted_content
    assert AWS_KEY not in v.redacted_content


# ---- verdict shape --------------------------------------------------------------

def test_verdict_shape(agent):
    v = agent.check(_msg(CLEAN_SUMMARY), CTX)
    assert v.agent_name == "secrets_pii"
    assert 0.0 <= v.score <= 1.0
    assert isinstance(v.reason, str) and v.reason


def test_empty_content_passes(agent):
    v = agent.check(_msg(""), CTX)
    assert v.label is Label.PASS


# ---- integration with the real policy engine ------------------------------------

def test_flag_with_redaction_resolves_redact_enforce_flag_monitor(agent):
    m = _msg(format_record(load_record("patient-A")))
    v = agent.check(m, CTX)
    assert v.label is Label.FLAG and v.redacted_content is not None

    # ENFORCE: above-threshold FLAG + redacted_content => REDACT, enforced
    d_enf = resolve(m, [v], Policy(mode=Mode.ENFORCE))
    assert d_enf.action is Action.REDACT
    assert d_enf.enforced is True
    assert "Jane Doe" not in (d_enf.final_content or "")

    # MONITOR: same verdict, clamped to FLAG, not enforced
    d_mon = resolve(m, [v], Policy(mode=Mode.MONITOR))
    assert d_mon.action is Action.FLAG
    assert d_mon.enforced is False
