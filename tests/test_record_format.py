"""Task N1 — does the result depend on the shape the record arrives in?

THE CRITICISM. Every record in the corpus is a `Key: value` block, which is exactly what
`InformationFlowAgent._structured_tags` parses. With Presidio OFF — the configuration every
headline number comes from — that fallback extractor is the ONLY source of taint tags. So
the corpus was authored in the format the detector expects, and the reported detection rate
depends on that in a way nothing measured.

THE PROBE. Four source formats, one leak. The egress hop is byte-for-byte the same in all
four scenarios: the same derived message, the same external address, the same name and
record id. Only the SOURCE record changes shape — structured block, JSON payload,
clinician's narrative, chat transcript, forwarded email thread. If detection moves, it is the parser that moved and
not the threat.

WHAT IT FOUND, AND WHAT WAS DONE. First measurement: 100 / 100 / 0 / 0. Half of the
realistic record formats were unparseable, so the reported rate was a property of how we
had written the corpus. The parser was then widened — a prose extractor for
identifier-shaped tokens, credentials and capitalised name runs, and content binding that
reads a subject named in text as well as bracketed — and the whole corpus was rotated
through all four formats in every family (task N2). All four are now caught.

This family stays as the CONTROL and the regression guard. Every other family meets the
four formats too, but only here is the egress hop held byte-identical across them, which
is what isolates the parser from the threat.
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

def test_every_format_is_represented(formats):
    """Assigned by position, so the counts are within one of each other. They cannot be
    exactly equal: five formats do not divide twenty-four scenarios, and forcing them to
    would mean either dropping a format or padding the family for arithmetic's sake."""
    from collections import Counter
    counts = Counter(s.record_format for s in formats)
    assert set(counts) == set(RECORD_FORMATS)
    assert max(counts.values()) - min(counts.values()) <= 1, counts


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
    assert sources["5_email"].startswith("From:")
    assert "\n>" in sources["5_email"], "the quoted reply is what makes this shape distinct"


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


def test_every_format_is_now_caught(formats):
    """THE RESULT, and it is the reverse of what this family first measured.

    On 2026-08-26 the four formats scored 100 / 100 / 0 / 0. A structured block and a JSON
    payload were caught; a clinician's narrative and a chat transcript were not, because
    `InformationFlowAgent._structured_tags` only reads `Key: value` lines and with Presidio
    off that is the only source of taint tags. The corpus had been authored in the one
    shape the parser understood, so the headline rate was conditioned on it.

    The parser was widened rather than the finding documented: a prose extractor for
    identifier-shaped tokens, credential-shaped runs and capitalised name runs, unioned
    with the structured one; and content binding now reads a subject NAMED in text as well
    as bracketed. All four formats are caught, and the corpus rotates through all four in
    every family (task N2) rather than testing one shape and hoping.

    This test is now the regression guard for that fix. If a format drops back to zero,
    the extractor lost a pattern and the headline rate has quietly become a property of
    record shape again.
    """
    rates = {fmt: _rate(formats, fmt) for fmt in RECORD_FORMATS}
    assert set(rates.values()) == {1.0}, (
        f"a record format is no longer parsed: {rates} — the prose extractor has lost a "
        "pattern, and the reported detection rate is conditioned on record shape again")


def test_the_baselines_are_indifferent_to_format(formats):
    """The comparison that isolates the cause. Both baselines judge the EGRESS message,
    which is identical across all four formats, so neither can vary — the heuristic
    blocks every one on the recipient, the scanner on the identifier. Any variation is
    ours alone, and it comes from how we read the SOURCE."""
    for scn in formats:
        assert metadata_heuristic(scn).stopped, (scn.id, scn.record_format)
        assert content_scanner(scn).stopped, (scn.id, scn.record_format)