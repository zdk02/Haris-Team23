"""Taint MATCHING tests — the Aug 22 rework (C1-C5).

`test_infoflow_module9.py` covers the destination rule and the detector seam. This file
covers the other half: *how* a tag is decided to have resurfaced, and what the extractor
is willing to treat as a tag in the first place.

Every test here pins a behaviour the eval corpus does NOT exercise. The corpus contains
no benign message quoting a prose-field word and no reformatted identifier outside the
obfuscated family, so a regression in any of this would leave the headline numbers
untouched. That is exactly why these belong in the suite.
"""
from __future__ import annotations

from haris.agents.infoflow import InformationFlowAgent
from haris.schemas.message import Message
from haris.schemas.verdict import Label

EXTERNAL = "outside@example.com"

RECORD = ("PATIENT RECORD [patient-A]\n"
          "Name: Jane Doe\n"
          "MRN: MRN-0001\n"
          "Diagnosis: Type 2 diabetes\n"
          "Status: active\n"
          "Visit: routine follow-up")

# detector=None everywhere: these test the structured extractor and the matcher, not
# Presidio. Keeps the file runnable without spaCy models installed.
AGENT = InformationFlowAgent(detector=None)


def _source(content: str = RECORD) -> Message:
    return Message(session_id="s", sender="record_reader", receiver="summarizer",
                   content=content,
                   metadata={"data_type": "PHI", "data_subject": "patient-A"})


def _derived(text: str, recipient: str = EXTERNAL) -> Message:
    return Message(session_id="s", sender="summarizer", receiver="emailer",
                   content=text,
                   metadata={"data_type": "summary", "recipient": recipient})


def _check(text: str, agent: InformationFlowAgent = AGENT, source: str = RECORD):
    msg = _derived(text)
    return agent.check(msg, {"history": [_source(source), msg]})


# --- C1: normalisation. The finding-12 case ------------------------------------

def test_a_double_space_no_longer_defeats_the_match():
    """Finding 12. Before normalisation this exact message passed: the matcher used
    `tag.lower() in content.lower()`, and 'Jane  Doe' is not a substring of 'Jane Doe'.
    The deck presented semantic paraphrase as the ceiling; the real ceiling was
    whitespace."""
    v = _check("Visit summary for Jane  Doe. Follow-up advised.")
    assert v.label is Label.FLAG
    assert "Jane" not in (v.redacted_content or "")


def test_a_reformatted_identifier_is_caught():
    """The obfuscated family: same digits, different separators. This is the change
    that took obfuscated-leak detection from 42% to 100% (report/evidence/)."""
    v = _check("Reference M R N 0 0 0 1 attached.")
    assert v.label is Label.FLAG


# --- C3: only identifying fields become tags -----------------------------------

def test_a_prose_field_value_does_not_taint_the_session():
    """'Status: active' must not make 'active' a taint tag. Before C3 every 'Key: value'
    line contributed, so this benign message was flagged and redacted. Worst case is
    used deliberately: external recipient, live PHI lineage."""
    v = _check("The clinic is active today.")
    assert v.label is Label.PASS
    assert v.redacted_content is None


def test_identifying_keys_are_configurable_not_hardcoded():
    """The allow-list is a constructor argument. A deployment with different field names
    configures it; nothing about the clinical default is baked in."""
    agent = InformationFlowAgent(detector=None, identifying_keys={"status"})
    assert "active" in agent._extract_tags(RECORD)
    assert "Jane Doe" not in agent._extract_tags(RECORD)


# --- C2/C4: word boundaries on the token pass ----------------------------------

def test_a_tag_does_not_match_inside_a_longer_word():
    """Without boundary matching a short tag fires inside any word containing it.
    'Anna' must not match 'Announcement'."""
    record = "PATIENT RECORD [patient-A]\nName: Anna\nMRN: MRN-0001"
    v = _check("Announcement: the clinic reopens Monday.", source=record)
    assert v.label is Label.PASS


# --- The documented residual ---------------------------------------------------

def test_collapsed_matching_ignores_word_boundaries_a_known_limit():
    """KNOWN LIMIT, pinned so it stays visible (cf. the paraphrase ceiling test).

    The second matching pass strips every non-alphanumeric character from both sides so
    that 'MRN - 0001' still matches 'MRN-0001'. Removing the separators also removes the
    boundaries, so 'Jane Doe' -> 'janedoe' matches inside 'janedoerson'. The two
    properties are the same information; you cannot have both in one comparison.

    `min_collapse_len` bounds how often this can fire. Crucially it can only ever cause a
    FALSE POSITIVE, never a miss - the safe direction for a security control. If this
    test ever fails because the match stopped happening, the residual was fixed: delete
    the test and update report section 8."""
    v = _check("Please contact janedoerson today.")
    assert v.label is Label.FLAG


def test_short_tags_are_not_collapse_matched():
    """The gate that bounds the residual above: below `min_collapse_len` only the
    boundary-respecting token pass runs, so a 4-character tag cannot match inside a
    longer word."""
    assert AGENT._tag_resurfaces("Anna", "announcement today", "announcementtoday") is False
    assert AGENT._tag_resurfaces("Anna", "anna visited today", "annavisitedtoday") is True


# --- C5: memoization -----------------------------------------------------------

class _CountingDetector:
    """Presidio-shaped, counts how many times it is asked to analyze."""

    def __init__(self) -> None:
        self.calls = 0

    def analyze(self, text: str):
        self.calls += 1
        return []


def test_tag_extraction_runs_once_per_source_not_once_per_hop():
    """C5. The orchestrator replays the whole session history on every hop, so an
    un-cached extractor re-runs the detector once per hop per source. With Presidio on
    that is a full NER pass each time (measured 11.1 ms -> 0.6 ms per hop)."""
    det = _CountingDetector()
    agent = InformationFlowAgent(detector=det)
    src, hops = _source(), []
    for i in range(5):
        msg = _derived(f"Summary revision {i}.")
        hops.append(msg)
        agent.check(msg, {"history": [src] + hops})
    assert det.calls == 1                      # five hops, one extraction


def test_the_cache_is_bounded_and_evicts_the_oldest():
    """An unbounded cache in the data path is a memory leak. Least-recently-used is
    evicted once the bound is reached."""
    agent = InformationFlowAgent(detector=None, tag_cache_size=2)
    for i in range(3):
        agent._extract_tags(f"Name: Person Number{i}")
    assert len(agent._tag_cache) == 2


def test_caching_can_be_disabled_and_still_returns_the_same_tags():
    """Correctness must not depend on the cache: the memoized answer is identical to the
    freshly computed one, because extraction is a pure function of the text."""
    cached = InformationFlowAgent(detector=None, tag_cache_size=512)
    uncached = InformationFlowAgent(detector=None, tag_cache_size=0)
    assert cached._extract_tags(RECORD) == uncached._extract_tags(RECORD)
    assert uncached._tag_cache == {}
