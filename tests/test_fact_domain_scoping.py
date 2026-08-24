"""Task I1 — record content belongs to the domain that owns it.

Before this fix, `_FACTS` and `_ID_LABEL` were module-level lookup tables in generate.py,
keyed by source_type and shared across every domain. Finance customers carried "type 2
diabetes" and hospital patients carried "a restructured mortgage". The bug was invisible
to the eval (no rate moved) and obvious to anyone who opened a single record.

`facts` and `id_label` are now fields on `Domain`, so a system's records can only say
what that system would hold. These tests keep it that way.
"""
from __future__ import annotations

import dataclasses

import pytest

from demo_app.eval.domains import DOMAINS, HOSPITAL, Domain
from demo_app.eval.generate import generate


@pytest.fixture(scope="module")
def scenarios():
    return generate()


# --------------------------------------------------------------------------- #
# The domain specs themselves
# --------------------------------------------------------------------------- #

def test_every_domain_carries_its_own_content_fields():
    """No domain may rely on a shared table for its record content."""
    for domain in DOMAINS.values():
        assert domain.facts, domain.name
        assert domain.id_label, domain.name


def test_fact_pools_are_disjoint():
    """Overlapping pools would make the cross-domain assertions below vacuous."""
    seen: dict[str, str] = {}
    for domain in DOMAINS.values():
        for fact in domain.facts:
            assert fact not in seen, (
                f"{fact!r} appears in both {seen[fact]!r} and {domain.name!r}"
            )
            seen[fact] = domain.name


def test_id_labels_are_distinct():
    """A shared prefix would make records from different systems indistinguishable."""
    labels = [d.id_label for d in DOMAINS.values()]
    assert len(set(labels)) == len(labels), labels


def test_fact_pools_are_equal_length():
    """`fake.random_element` draws through _randbelow(len(seq)), so unequal or changed
    pool sizes shift the seeded RNG stream and silently rewrite every downstream name,
    record ID and credential. Keep all pools the same size."""
    sizes = {n: len(d.facts) for n, d in DOMAINS.items()}
    assert len(set(sizes.values())) == 1, sizes


# --------------------------------------------------------------------------- #
# A half-specified domain must fail at construction, not at generation
# --------------------------------------------------------------------------- #

def test_domain_with_no_facts_is_rejected():
    with pytest.raises(ValueError, match="empty fact pool"):
        dataclasses.replace(HOSPITAL, facts=())


def test_domain_with_no_id_label_is_rejected():
    with pytest.raises(ValueError, match="no id_label"):
        dataclasses.replace(HOSPITAL, id_label="")


def test_domain_is_immutable():
    """Frozen: nothing can swap a pool at runtime after the checks have run."""
    with pytest.raises(dataclasses.FrozenInstanceError):
        HOSPITAL.facts = ()  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# The generated corpus
# --------------------------------------------------------------------------- #

def test_each_secret_draws_from_its_own_domain(scenarios):
    assert scenarios, "generator produced nothing"
    for scn in scenarios:
        own = DOMAINS[scn.domain].facts
        assert scn.secret.fact in own, (scn.id, scn.domain, scn.secret.fact)


def test_each_record_id_uses_its_own_domains_label(scenarios):
    for scn in scenarios:
        label = DOMAINS[scn.domain].id_label
        assert scn.secret.record_id.startswith(f"{label}-"), (scn.id, scn.secret.record_id)


def test_no_message_carries_another_domains_fact(scenarios):
    """Covers families that build a second secret (e.g. subject_mismatch) and every
    content style that embeds the raw record."""
    for scn in scenarios:
        domain: Domain = DOMAINS[scn.domain]
        own = set(domain.facts)
        foreign = {f for d in DOMAINS.values() for f in d.facts} - own
        blob = "\n".join(m.content for m in scn.messages)
        offenders = sorted(f for f in foreign if f in blob)
        assert not offenders, (scn.id, scn.domain, offenders)