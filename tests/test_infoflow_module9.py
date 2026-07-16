"""Module 9 promotion tests: the destination rule and the injectable M7 detector seam.

These run WITHOUT Presidio installed: the destination tests use the structured
fallback, and the detector-seam test injects a fake Presidio-shaped detector.
"""
from __future__ import annotations

from dataclasses import dataclass

from demo_app.hospital.app import EXTERNAL_EXAMPLE, INTERNAL_DOCTOR, format_record
from demo_app.hospital.records import load_record
from haris.agents.infoflow import InformationFlowAgent
from haris.policy.engine import resolve
from haris.schemas.decision import Action
from haris.schemas.message import Message
from haris.schemas.policy import Mode, Policy
from haris.schemas.verdict import Label

RECORD_A = format_record(load_record("patient-A"))
IDENTIFIED = ("Visit summary for Jane Doe: Type 2 diabetes; hypertension. "
              "Follow-up advised.")


def _phi_source(subject="patient-A") -> Message:
    return Message(session_id="s", sender="record_reader", receiver="summarizer",
                   content=format_record(load_record(subject)),
                   metadata={"data_type": "PHI", "data_subject": subject})


def _derived(text: str, recipient: str) -> Message:
    return Message(session_id="s", sender="summarizer", receiver="emailer",
                   content=text, metadata={"data_type": "summary", "recipient": recipient})


def _ctx(*msgs) -> dict:
    return {"history": list(msgs)}


AGENT = InformationFlowAgent()


# --- the destination rule (TC5-style: SAME summary, recipient decides) ---------

def test_external_recipient_flags_identified_summary():
    msg = _derived(IDENTIFIED, EXTERNAL_EXAMPLE)
    v = AGENT.check(msg, _ctx(_phi_source(), msg))
    assert v.label is Label.FLAG
    assert "Jane Doe" not in (v.redacted_content or "")


def test_internal_recipient_allows_identical_summary():
    """The info-flow judgment: identifiers derived from PHI MAY reach the treating
    doctor inside the trust boundary. Same content that is flagged externally passes."""
    msg = _derived(IDENTIFIED, INTERNAL_DOCTOR)
    v = AGENT.check(msg, _ctx(_phi_source(), msg))
    assert v.label is Label.PASS
    assert "trust boundary" in v.reason


def test_missing_recipient_flags_by_default():
    msg = Message(session_id="s", sender="summarizer", receiver="emailer",
                  content=IDENTIFIED, metadata={"data_type": "summary"})
    v = AGENT.check(msg, _ctx(_phi_source(), msg))
    assert v.label is Label.FLAG


def test_missing_recipient_allowed_when_configured():
    agent = InformationFlowAgent(flag_unknown_destination=False)
    msg = Message(session_id="s", sender="summarizer", receiver="emailer",
                  content=IDENTIFIED, metadata={"data_type": "summary"})
    v = agent.check(msg, _ctx(_phi_source(), msg))
    assert v.label is Label.PASS


def test_subdomain_of_internal_domain_is_internal():
    msg = _derived(IDENTIFIED, "nurse@clinic.hospital.internal")
    v = AGENT.check(msg, _ctx(_phi_source(), msg))
    assert v.label is Label.PASS


# --- the injectable Module 7 detector seam -------------------------------------

@dataclass
class _FakeResult:
    start: int
    end: int
    entity_type: str
    score: float


class _FakeDetector:
    """Presidio-shaped: .analyze(text) -> results with start/end/entity_type/score.
    Flags a token the structured extractor would NOT catch, proving the seam is used."""
    def __init__(self, needle: str):
        self.needle = needle
        self.calls = 0

    def analyze(self, text: str):
        self.calls += 1
        i = text.find(self.needle)
        return [_FakeResult(i, i + len(self.needle), "PERSON", 0.99)] if i >= 0 else []


def test_injected_detector_drives_taint_tags():
    needle = "Zylophar Quibbleton"   # not a 'Key: value' field, only the detector sees it
    source = Message(session_id="s", sender="record_reader", receiver="summarizer",
                     content=f"free narrative mentioning {needle} in passing",
                     metadata={"data_type": "PHI", "data_subject": "patient-A"})
    det = _FakeDetector(needle)
    agent = InformationFlowAgent(detector=det, use_structured_fallback=False)
    msg = _derived(f"Summary: the individual {needle} is doing fine.", EXTERNAL_EXAMPLE)
    v = agent.check(msg, _ctx(source, msg))
    assert det.calls >= 1                       # the injected detector was consulted
    assert v.label is Label.FLAG
    assert needle not in (v.redacted_content or "")
    assert "[REDACTED]" in (v.redacted_content or "")


def test_detector_disabled_uses_structured_only():
    agent = InformationFlowAgent(detector=None)   # no detector at all
    msg = _derived(IDENTIFIED, EXTERNAL_EXAMPLE)
    v = agent.check(msg, _ctx(_phi_source(), msg))
    assert v.label is Label.FLAG                   # structured extractor still catches it


# --- end-to-end through the real policy engine ---------------------------------

def test_verdict_resolves_to_redact_in_enforce_and_flag_in_monitor():
    msg = _derived(IDENTIFIED, EXTERNAL_EXAMPLE)
    v = AGENT.check(msg, _ctx(_phi_source(), msg))

    d_enf = resolve(msg, [v], Policy(mode=Mode.ENFORCE))
    assert d_enf.action is Action.REDACT and d_enf.enforced is True
    assert "Jane Doe" not in (d_enf.final_content or "")
    assert "[REDACTED]" in (d_enf.final_content or "")

    d_mon = resolve(msg, [v], Policy(mode=Mode.MONITOR))
    assert d_mon.action is Action.FLAG and d_mon.enforced is False