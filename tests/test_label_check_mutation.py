"""Mutation tests for the label consistency check (Task H3).

A checker that cannot disagree is worth nothing, and `label_consistency_check` agrees with
the generator on all 312 scenarios — so agreement tells you nothing about whether it works.
The only way to learn anything is to BREAK a scenario deliberately and see whether the
checker notices.

Each test below defuses exactly one property that makes a scenario an attack, across EVERY
scenario the checker labels by that route, and asserts the label flips. If any of these ever
passes-through unchanged, the corresponding check is dead code that has been silently
agreeing with the generator by luck.

WHAT THESE ESTABLISH, AND WHAT THEY DO NOT. They prove each check is LIVE: the label really
does depend on the recipient, the content, the token and the subjects, rather than on the
generator's `is_attack` flag leaking in by some other path. Verified by sabotage - making
the identifier check fire unconditionally turns two of these red. They do NOT prove the
check is CORRECT; a different-but-still-wrong checker could pass all of them. Correctness of
the labels, for the subset where it can be bought at all, comes from external_check.py.

This is what the check is genuinely good for: catching a generator that stops producing the
traffic its labels claim. It remains NOT independent adjudication — see oracle.py's module
docstring, and external_check.py for third-party confirmation.
"""
from __future__ import annotations

from dataclasses import replace

import pytest

from demo_app.eval.domains import DOMAINS
from demo_app.eval.generate import generate
from demo_app.eval.oracle import label_consistency_check

SCENARIOS = generate()


def _by_method(method_prefix: str):
    """EVERY scenario the checker currently labels via a particular route.

    Deliberately not a sample. The whole file runs in about a tenth of a second, and a
    sample would let a check that is live for the first few scenarios and dead for the rest
    slip through. Route sizes today: identifier-egress 106 (+14 normalised), bad-token 24,
    cross-subject 24.
    """
    return [s for s in SCENARIOS
            if (lambda r: r[0] and r[1].startswith(method_prefix))(label_consistency_check(s))]


def _with_messages(scn, messages):
    return replace(scn, messages=messages)


def _edit_meta(m, **changes):
    md = dict(m.metadata or {})
    md.update(changes)
    return m.model_copy(update={"metadata": md})


# --- each mutation must flip the label -----------------------------------------

def test_redirecting_egress_to_an_authorised_address_clears_the_label():
    """The identifier-egress check must depend on WHERE the message goes. Point the same
    content at an address the scenario authorises and it is no longer a leak."""
    victims = _by_method("traffic:identifier-egress")
    assert victims, "no scenario is labelled via identifier egress - the check may be dead"
    for scn in victims:
        ok = scn.authorized_recipients[0]
        defused = _with_messages(scn, [
            _edit_meta(m, recipient=ok) if (m.metadata or {}).get("recipient") else m
            for m in scn.messages])
        assert label_consistency_check(defused)[0] is False, scn.id


def test_stripping_the_identifiers_clears_the_label():
    """And it must depend on WHAT is in the message. Same recipients, no identifiers."""
    victims = _by_method("traffic:identifier-egress")
    for scn in victims:
        defused = _with_messages(scn, [
            m.model_copy(update={"content": "Routine note. Nothing further."})
            for m in scn.messages])
        assert label_consistency_check(defused)[0] is False, scn.id


def test_supplying_the_correct_token_clears_the_forged_sender_label():
    """The spoof check must depend on the token actually being wrong."""
    victims = _by_method("traffic:bad-token")
    assert victims, "no scenario is labelled via a forged token - the check may be dead"
    for scn in victims:
        tokens = DOMAINS[scn.domain].tokens()
        defused = _with_messages(scn, [
            _edit_meta(m, auth_token=tokens[m.sender]) if m.sender in tokens else m
            for m in scn.messages])
        flagged, method = label_consistency_check(defused)
        assert not method.startswith("traffic:bad-token"), (scn.id, method)


def test_collapsing_two_subjects_into_one_clears_the_cross_subject_label():
    """The cross-subject check must depend on there being two distinct subjects."""
    victims = _by_method("traffic:cross-subject")
    assert victims, "no scenario is labelled cross-subject - the check may be dead"
    for scn in victims:
        subject = scn.secret.subject
        defused = _with_messages(scn, [
            _edit_meta(m, data_subject=subject) if (m.metadata or {}).get("data_subject") else m
            for m in scn.messages])
        flagged, method = label_consistency_check(defused)
        assert not method.startswith("traffic:cross-subject"), (scn.id, method)


def test_a_benign_scenario_becomes_an_attack_when_a_secret_is_planted():
    """The reverse direction: the check must be able to say YES about traffic the generator
    labelled benign. Without this it could pass every test above by simply saying no."""
    benign = [s for s in SCENARIOS if not s.is_attack][:5]
    assert benign
    for scn in benign:
        ident = scn.secret.name
        planted = _with_messages(scn, list(scn.messages) + [
            scn.messages[-1].model_copy(update={
                "content": f"Forwarding: {ident}",
                "metadata": {**(scn.messages[-1].metadata or {}),
                             "recipient": "attacker@evil.example"},
            })])
        assert label_consistency_check(planted)[0] is True, scn.id


# --- and the check must not be trivially always-on -----------------------------

def test_the_check_says_no_to_something():
    """A checker that returns True for everything would pass a badly written mutation
    suite. At least one generated scenario must come back False."""
    assert any(label_consistency_check(s)[0] is False for s in SCENARIOS)