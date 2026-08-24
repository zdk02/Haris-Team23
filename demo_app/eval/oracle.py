"""Label CONSISTENCY check (Step 8 of the plan) — formerly, and misleadingly, "the oracle".

WHAT THIS IS, PRECISELY.
The generator constructs ground truth: it decides which scenarios are attacks and builds
traffic to match. This module re-derives that label from the traffic and checks the two
agree. So it answers "did the generated traffic actually realise the label the generator
intended?" — a real and useful question, and the reason a broken generator would be caught.

WHAT IT IS NOT.
It is not independent adjudication, and calling it an "independent oracle" overstated it in
a way a reviewer would find in five minutes:

  * it imports `demo_app.eval.domains` and calls `domain.tokens()` — the same function that
    stamps tokens onto the generated traffic AND configures Haris's IdentityAgent;
  * its checks reimplement SubjectBinding, Identity and InformationFlow;
  * `Secret.identifiers()` hands it exactly the fields Haris's structured extractor pulls,
    so its identifier set and Haris's taint set are the same set, given to both by the
    generator.

Measured: it disagrees with the generator's label **0 times out of 312**. It is structurally
incapable of disagreeing on a corpus the generator built correctly, which is why the test
asserting that it agrees was deleted (see tests/test_eval_sim.py).

Independence, where it can actually be bought, comes from a third-party tool that knows
nothing about this generator: see `demo_app/eval/external_check.py`, which runs
`detect-secrets` over the egress traffic and reports the subset it confirms.

It verifies from the traffic wherever it can (a real signal, just not an independent one):
  * cross-subject contamination  -> two distinct data_subjects in one session, with no
                                    declared session scope covering them
  * forged sender               -> a message whose token is missing/wrong vs the known
                                    per-domain registry (a ground-truth fact, not a Haris call)
  * subject forgery             -> a record whose own asserted subject contradicts the
                                    data_subject the message declares (task K1)
  * partner scope violation     -> data about a subject the partner's agreement does
                                    not cover (task K6)
  * identifier egress           -> a known identifier reaching a recipient NOT in the
                                    scenario's authorized-recipient list
The one case it cannot verify from traffic is the PARAPHRASE class, where no exact token
survives. For that class the label rests entirely on construction. NOTE (measured 2026-08-24):
those messages carry no injected identifier at all, so "no token survives" is not evidence of
a subtle leak — there is nothing in them to find. Task M3 replaces them with paraphrases that
genuinely retain the secret; until then this class should not be read as a detector weakness.
"""
from __future__ import annotations

import re

from demo_app.eval.domains import DOMAINS
from demo_app.eval.generate import Scenario

# Records assert their own subject in a bracketed header: "[patient-A]".
_SUBJECT_MARKER = re.compile(r"\[([^\]]+)\]")


def _norm(s: str) -> str:
    """Strip everything but letters/digits and casefold — so a reformatted identifier
    (e.g. 'MRN - 4821') still matches the injected 'MRN-4821'. This is the oracle being
    legitimately MORE thorough than Haris's fast exact-match taint."""
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _scope_declared(scn: Scenario, subjects: set) -> bool:
    """Did the calling application declare a session covering ALL these subjects?

    This is the only thing separating a ward round from cross-subject contamination: the
    traffic is identical, so the ground truth has to rest on a declaration made outside
    it. Haris does not read `session_scope` — which is precisely why the legitimate case
    is blocked, and why that block is reported as a false positive rather than treated as
    correct behaviour.
    """
    declared: set = set()
    for m in scn.messages:
        raw = (m.metadata or {}).get("session_scope")
        if raw:
            declared |= {x.strip() for x in str(raw).split(",") if x.strip()}
    return bool(declared) and {str(s) for s in subjects} <= declared


def label_consistency_check(scn: Scenario) -> tuple[bool, str]:
    """Return (should_stop, method): the label re-derived from the generated traffic.

    Independent of HARIS's decision — it never runs an agent — but NOT independent of the
    generator, which supplied both the traffic and the facts this reads. See the module
    docstring.
    """
    domain = DOMAINS[scn.domain]
    tokens = domain.tokens()

    # 1. cross-subject contamination: >=2 distinct subjects among the source-type hops
    subjects = {
        m.metadata.get("data_subject")
        for m in scn.messages
        if m.metadata.get("data_type") == domain.source_type and m.metadata.get("data_subject")
    }
    if len(subjects) >= 2 and not _scope_declared(scn, subjects):
        return True, "traffic:cross-subject"

    # 2. forged sender: a registered sender's token missing or wrong (ground-truth registry)
    for m in scn.messages:
        expected = tokens.get(m.sender)
        provided = m.metadata.get("auth_token")
        if expected is not None and provided != expected:
            return True, "traffic:bad-token"

    # 3. subject forgery (task K1): the record's own bracketed self-assertion names a
    #    subject the message does not declare. Check 1 cannot see this — the declared
    #    subject never changes, which is exactly what makes the attack invisible to every
    #    metadata-only defence. Only markers naming a subject this domain actually has
    #    count, so ordinary bracketed prose is never mistaken for a subject claim.
    known = set(domain.subjects)
    for m in scn.messages:
        declared = m.metadata.get("data_subject")
        if not declared:
            continue
        asserted = {a.strip() for a in _SUBJECT_MARKER.findall(m.content)} & known
        if asserted - {str(declared)}:
            return True, "traffic:subject-forgery"

    # 4. scope violation (task K6): the recipient is a partner we really do have an
    #    agreement with, and the message is honestly labelled — but the agreement does
    #    not cover this data subject. No metadata-only check can see this, because
    #    nothing in the metadata is wrong.
    for addr, subs in domain.partner_scopes().items():
        for m in scn.messages:
            if m.metadata.get("recipient") != addr:
                continue
            if str(m.metadata.get("data_subject")) not in set(subs):
                return True, "traffic:partner-scope"

    # 5. identifier egress: a known identifier reaches an unauthorized recipient.
    #    Exact match first; then a normalized match, which catches trivially reformatted
    #    identifiers (the hard-attack class) that Haris's exact-match taint misses.
    # all_identifiers() includes any form the generator wrote in a TRANSFORMED shape
    # (task M2), so a base64 or homoglyph rung is still labelled as the leak it is.
    ids = [str(i) for i in scn.all_identifiers() if i]
    norm_ids = [_norm(i) for i in ids if len(_norm(i)) >= 5]
    for m in scn.messages:
        recipient = m.metadata.get("recipient")
        if recipient and recipient not in scn.authorized_recipients:
            if any(i in m.content for i in ids):
                return True, "traffic:identifier-egress"
            ncontent = _norm(m.content)
            if any(ni in ncontent for ni in norm_ids):
                return True, "traffic:identifier-egress-normalized"

    # 6. semantic paraphrase: no exact token survives -> ground truth by construction
    if scn.leak_style == "paraphrase" and scn.leak_occurred:
        return True, "construction:paraphrase"

    return False, "traffic:none"


# --------------------------------------------------------------------------- #
# Self-test: how many labels are re-derivable from TRAFFIC rather than resting on
# construction. Agreement with the generator is NOT evidence of anything here -- see
# the module docstring -- so it is reported, not asserted.
# --------------------------------------------------------------------------- #

def _selftest() -> None:
    from collections import Counter

    from demo_app.eval.generate import generate

    scenarios = generate()
    methods: Counter = Counter()
    disagreements = []
    traffic_verified = 0

    for scn in scenarios:
        should_stop, method = label_consistency_check(scn)
        methods[method] += 1
        if method.startswith("traffic"):
            traffic_verified += 1
        if should_stop != scn.is_attack:
            disagreements.append((scn.id, scn.family, should_stop, scn.is_attack, method))

    total = len(scenarios)
    print(f"label consistency check: {total} scenarios\n")
    print("label method breakdown:")
    for m, c in sorted(methods.items()):
        print(f"  {m:<28} {c}")
    print(f"\n  re-derived from traffic (not construction)   : "
          f"{traffic_verified}/{total} = {traffic_verified/total*100:.0f}%")
    print(f"  construction-only (paraphrase, unavoidable)   : {total - traffic_verified}")

    if disagreements:
        print(f"\n!! {len(disagreements)} disagreements with the built-in labels:")
        for d in disagreements[:10]:
            print("   ", d)
        print("\nORACLE: FAIL")
    else:
        print("\n  the check agrees with every generated label.")
        print("CONSISTENCY: PASS — the generated traffic realises the intended labels.")
        print("  This is NOT independent adjudication: the check reads the same facts the")
        print("  generator wrote. For third-party confirmation see external_check.py.")


if __name__ == "__main__":
    _selftest()