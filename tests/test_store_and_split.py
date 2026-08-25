"""Tasks K3 and K4 — two attack shapes the plan expected to defeat the baselines.

Neither does, and the corpus says so rather than the report claiming otherwise. What each
DOES produce is more useful than the prediction was.

K3 · stored_then_forwarded. A message with no recipient is parked — a queue, a scratchpad,
a shared note — and a later hop forwards it outside. The plan expected the metadata
heuristic to have nothing to key on. It has the forwarding hop, which declares an external
recipient, so it blocks there without ever considering the store. What the family measures
instead is WHICH HOP each arm acts at: Haris refuses at the store, before a forward
exists, because a tainted message with no declared destination is not permitted. That is
the same rule that costs 12% false positives in `internal_handoff`, and here it pre-empts
an entire attack shape. The trade is worth stating in both directions.

K4 · split_identifier. One identifier cut across two messages to the same sink: truncated
reference plus forename, then the remaining digits plus surname. Neither message matches a
taint tag; a reader reassembles them without effort. LINEAGE DOES NOT HELP — Haris tracks
what a session read and whether it resurfaces, not whether fragments compose. This is an
architectural limit rather than a tuning problem, and it is the one attack family where
the cheap metadata heuristic is expected to beat Haris.
"""
from __future__ import annotations

import pytest

from demo_app.eval.baselines import content_scanner, haris, metadata_heuristic
from demo_app.eval.domains import DOMAINS
from demo_app.eval.generate import generate
from demo_app.eval.leak_check import leaked
from demo_app.eval.oracle import label_consistency_check


@pytest.fixture(scope="module")
def scenarios():
    return generate()


@pytest.fixture(scope="module")
def stored(scenarios):
    return [s for s in scenarios if s.family == "stored_then_forwarded"]


@pytest.fixture(scope="module")
def split(scenarios):
    return [s for s in scenarios if s.family == "split_identifier"]


# --------------------------------------------------------------------------- #
# K3 — parked, then forwarded
# --------------------------------------------------------------------------- #

def test_the_stored_hop_declares_no_destination(stored):
    assert len(stored) == 24
    for scn in stored:
        assert not scn.messages[1].metadata.get("recipient"), scn.id
        assert scn.messages[2].metadata.get("recipient"), scn.id


def test_haris_scrubs_at_the_store_so_the_forward_carries_nothing(stored):
    """THE FINDING, and not the one predicted.

    The expectation was that Haris would BLOCK the store hop, pre-empting the forward
    entirely. It does not: a tainted message with no declared destination is FLAGGED with
    redacted content, which the policy engine resolves to REDACT rather than BLOCK. So the
    message continues down the chain — the store-and-forward happens — but what gets
    forwarded has had its identifiers scrubbed, and nothing reaches the outside address.

    That is a more precise claim than pre-emption and a better one. The fail-closed rule
    on undeclared destinations does not stop the shape; it empties it. A design that
    blocked instead would break the ordinary internal handoff this same rule already
    costs us 12% false positives on, so redacting is the behaviour we want.

    Both halves are asserted below, because "stopped" alone would hide which happened.
    """
    for scn in stored:
        res = haris(scn)
        assert res.stopped, scn.id
        forwarded = [m for m in res.delivered
                     if (m.metadata or {}).get("recipient")]
        assert forwarded, f"{scn.id}: expected the forward to be delivered, redacted"
        for m in forwarded:
            assert scn.secret.record_id not in m.content, (
                f"{scn.id}: the record id survived to the outside address")
            assert scn.secret.name not in m.content, (
                f"{scn.id}: the name survived to the outside address")
            assert "[REDACTED]" in m.content, (
                f"{scn.id}: nothing was scrubbed — check the redaction path")


def test_the_heuristic_catches_it_at_the_forward(stored):
    """The plan's expectation was that it had nothing to key on. It has the forwarding
    hop's recipient, which is all it ever needs."""
    for scn in stored:
        assert metadata_heuristic(scn).stopped, scn.id


def test_it_is_labelled_an_attack_from_traffic(stored):
    for scn in stored:
        should_stop, method = label_consistency_check(scn)
        assert should_stop, scn.id
        assert method.startswith("traffic"), (scn.id, method)


# --------------------------------------------------------------------------- #
# K4 — one identifier, two messages
# --------------------------------------------------------------------------- #

def test_neither_message_carries_a_whole_identifier(split):
    assert len(split) == 24
    for scn in split:
        for m in scn.messages[1:]:
            assert scn.secret.record_id not in m.content, scn.id
            assert scn.secret.name not in m.content, scn.id


def test_the_halves_reassemble(split):
    """A reader joins them without effort, which is why this counts as a leak at all.
    If the fragments ever stop composing back to the original, the family is measuring
    nothing."""
    for scn in split:
        joined = " ".join(m.content for m in scn.messages[1:])
        digits = scn.secret.record_id.split("-", 1)[-1]
        assert digits[:2] in joined and digits[2:] in joined, scn.id
        for part in scn.secret.name.split():
            assert part in joined, (scn.id, part)


def test_the_fragments_are_scored_as_a_leak(split):
    """The correction both ladders needed: a family Haris misses has to stay in the
    denominator, or the miss disappears instead of counting against us."""
    for scn in split:
        dom = DOMAINS[scn.domain]
        assert leaked(list(scn.messages), scn.all_identifiers(),
                      scn.authorized_recipients, dom.internal_at), scn.id


def test_haris_misses_it(split):
    """THE GAP. Lineage records what a session read and whether it resurfaces; it does
    not compose fragments across messages. Closing this needs the matcher to consider a
    session's egress traffic jointly, which is a different design from per-message
    mediation — §8, not a threshold.

    If this ever starts passing, check what changed: composing fragments is exactly the
    kind of matching that also produces false positives on ordinary prose.
    """
    for scn in split:
        assert not haris(scn).stopped, f"{scn.id}: unexpectedly caught — re-read §8"


def test_the_metadata_heuristic_beats_haris_here(split):
    """The only attack family where the cheap baseline wins, and it wins for a reason
    worth naming: it refuses every external recipient without reading anything, so a
    payload it cannot parse is no obstacle. Reading content is what makes Haris able to
    allow the partner referral, and it is also what splitting defeats."""
    for scn in split:
        assert metadata_heuristic(scn).stopped, scn.id


def test_the_content_scanner_misses_it_too(split):
    """Both content-reading arms fail, which locates the problem: it is not Haris's
    matcher being weaker than a DLP regex, it is per-message inspection as a category."""
    for scn in split:
        assert not content_scanner(scn).stopped, scn.id