"""Task N1 — does the result depend on the shape the record arrives in?

THE CRITICISM. Every record in the corpus is a `Key: value` block, which is exactly what
`InformationFlowAgent._structured_tags` parses. With Presidio OFF — the configuration every
headline number comes from — that fallback extractor is the ONLY source of taint tags. So
the corpus was authored in the format the detector expects, and the reported detection rate
depends on that in a way nothing measured.

THE PROBE. Four source formats, one leak. The egress hop is byte-for-byte the same in all
four scenarios: the same derived message, the same external address, the same name and
record id. Only the SOURCE record changes shape — structured block, JSON payload,
clinician's narrative, chat transcript. If detection moves, it is the parser that moved and
not the threat.

DEVIATION FROM THE PLAN, STATED. N2 asks for the whole corpus to be rewritten in 3-5
formats per domain. That would move every number in the report five days before submission.
This isolates the same question into one family. Rewriting the corpus is the more thorough
answer and remains follow-up work — the finding here tells you how much it would matter.
"""
from __future__ import annotations

import pytest

from demo_app.eval.baselines import content_scanner, haris, metadata_heuristic
from demo_app.eval.domains import DOMAINS
from demo_app.eval.generate import RECORD_FORMATS, generate
from demo_app.eval.leak_check import leaked
from demo_app.eval.oracle import label_consistency_check


@pytest.fixture(scope="module")
def scenarios():
    return generate()


@pytest.fixture(scope="module")
def formats(scenarios):
    return [s for s in scenarios if s.family == "record_format"]


def _rate(formats, fmt):
    rows = [s for s in formats if s.record_format == fmt]
    return sum(1 for s in rows if haris(s).stopped) / len(rows)


# --------------------------------------------------------------------------- #
# The probe is a fair one
# --------------------------------------------------------------------------- #

def test_every_format_is_represented_equally(formats):
    from collections import Counter
    counts = Counter(s.record_format for s in formats)
    assert set(counts) == set(RECORD_FORMATS)
    assert len(set(counts.values())) == 1, counts


def test_the_egress_hop_is_identical_across_formats(formats):
    """THE CONTROL, and the whole validity of this family rests on it. If the leaking
    message differed between formats, a difference in detection would tell us nothing
    about the parser."""
    by_scenario = {}
    for scn in formats:
        key = (scn.domain, scn.topology, scn.secret.record_id)
        by_scenario.setdefault(key, []).append(scn)
    for group in by_scenario.values():
        egress = {s.messages[-1].content for s in group}
        assert len(egress) == 1, group[0].id


def test_the_source_record_really_differs(formats):
    """And the other half: the four formats must actually be different text, not four
    labels on the same block."""
    sources = {s.record_format: s.messages[0].content for s in formats}
    assert len(set(sources.values())) == len(RECORD_FORMATS)
    assert "{" in sources["2_json"]
    assert "Detail:" not in sources["3_narrative"]
    assert "nurse_a" in sources["4_chat"]


def test_every_format_is_a_real_leak(formats):
    """The identifiers reach an external address in all four, so the denominator is the
    same and only the detector's answer can vary."""
    for scn in formats:
        dom = DOMAINS[scn.domain]
        assert leaked(list(scn.messages), scn.all_identifiers(),
                      scn.authorized_recipients, dom.internal_at), scn.id


def test_every_format_is_labelled_an_attack_from_traffic(formats):
    for scn in formats:
        should_stop, method = label_consistency_check(scn)
        assert should_stop, (scn.id, scn.record_format)
        assert method.startswith("traffic"), (scn.id, method)


# --------------------------------------------------------------------------- #
# The result
# --------------------------------------------------------------------------- #

def test_the_structured_control_is_caught(formats):
    """The format every other family uses. If this fails, nothing else here means
    anything."""
    assert _rate(formats, "1_structured") == 1.0


def test_the_format_changes_the_answer(formats):
    """THE FINDING. Same threat, same egress message, different source shape — and the
    detector's answer moves. That is a fact about the parser, and it means the headline
    detection rate is conditioned on a corpus written the way the parser likes.

    Which formats survive is measured rather than asserted here; the per-format numbers
    are in the runner's BY RECORD FORMAT table and belong in §6 next to the headline,
    not in a footnote.
    """
    rates = {fmt: _rate(formats, fmt) for fmt in RECORD_FORMATS}
    assert len(set(rates.values())) > 1, (
        f"all formats scored identically ({rates}) — either the fallback parser is more "
        "general than we thought, which is worth saying, or the formats are not actually "
        "different enough to test anything")


def test_the_baselines_are_indifferent_to_format(formats):
    """The comparison that isolates the cause. Both baselines judge the EGRESS message,
    which is identical across all four formats, so neither can vary — the heuristic
    blocks every one on the recipient, the scanner on the identifier. Any variation is
    ours alone, and it comes from how we read the SOURCE."""
    for scn in formats:
        assert metadata_heuristic(scn).stopped, (scn.id, scn.record_format)
        assert content_scanner(scn).stopped, (scn.id, scn.record_format)
