"""Independent ground-truth oracle (Step 8 of the plan).

Decides, for each scenario, whether it is a real attack/leak that SHOULD be stopped —
using ONLY the injected facts and the observed traffic, never Haris's decision. This is
what makes the evaluation credible: the labels are not produced by the thing under test.

It verifies from the traffic wherever it can (that is the strong, independent signal):
  * cross-subject contamination  -> two distinct data_subjects in one session
  * forged sender               -> a message whose token is missing/wrong vs the known
                                    per-domain registry (a ground-truth fact, not a Haris call)
  * identifier egress           -> a known identifier reaching a recipient NOT in the
                                    scenario's authorized-recipient list
The one case it cannot verify by string-matching is the SEMANTIC PARAPHRASE leak (no exact
token survives — that is precisely why it is hard). For that class only, ground truth is
"by construction": we authored a reworded secret, so we know it is a leak. This is the
documented, deterministic exception (see EVAL_DESIGN.md, decision 6).
"""
from __future__ import annotations

from demo_app.eval.domains import DOMAINS
from demo_app.eval.generate import Scenario


def oracle_should_stop(scn: Scenario) -> tuple[bool, str]:
    """Return (should_stop, method). Independent of Haris."""
    domain = DOMAINS[scn.domain]
    tokens = domain.tokens()

    # 1. cross-subject contamination: >=2 distinct subjects among the source-type hops
    subjects = {
        m.metadata.get("data_subject")
        for m in scn.messages
        if m.metadata.get("data_type") == domain.source_type and m.metadata.get("data_subject")
    }
    if len(subjects) >= 2:
        return True, "traffic:cross-subject"

    # 2. forged sender: a registered sender's token missing or wrong (ground-truth registry)
    for m in scn.messages:
        expected = tokens.get(m.sender)
        provided = m.metadata.get("auth_token")
        if expected is not None and provided != expected:
            return True, "traffic:bad-token"

    # 3. identifier egress: a known identifier reaches an unauthorized recipient
    ids = [str(i) for i in scn.secret.identifiers() if i]
    for m in scn.messages:
        recipient = m.metadata.get("recipient")
        if recipient and recipient not in scn.authorized_recipients:
            if any(i in m.content for i in ids):
                return True, "traffic:identifier-egress"

    # 4. semantic paraphrase: no exact token survives -> ground truth by construction
    if scn.leak_style == "paraphrase" and scn.leak_occurred:
        return True, "construction:paraphrase"

    return False, "traffic:none"


# --------------------------------------------------------------------------- #
# Self-test: the oracle must independently reproduce the by-construction labels,
# and it must decide (almost) everything from TRAFFIC, not construction.
# --------------------------------------------------------------------------- #

def _selftest() -> None:
    from collections import Counter

    from demo_app.eval.generate import generate

    scenarios = generate()
    methods: Counter = Counter()
    disagreements = []
    traffic_verified = 0

    for scn in scenarios:
        should_stop, method = oracle_should_stop(scn)
        methods[method] += 1
        if method.startswith("traffic"):
            traffic_verified += 1
        if should_stop != scn.is_attack:
            disagreements.append((scn.id, scn.family, should_stop, scn.is_attack, method))

    total = len(scenarios)
    print(f"oracle checked {total} scenarios\n")
    print("label method breakdown:")
    for m, c in sorted(methods.items()):
        print(f"  {m:<28} {c}")
    print(f"\n  traffic-verified (independent of construction): "
          f"{traffic_verified}/{total} = {traffic_verified/total*100:.0f}%")
    print(f"  construction-only (paraphrase, unavoidable)   : {total - traffic_verified}")

    if disagreements:
        print(f"\n!! {len(disagreements)} disagreements with the built-in labels:")
        for d in disagreements[:10]:
            print("   ", d)
        print("\nORACLE: FAIL")
    else:
        print("\n  oracle agrees with every scenario's built-in label.")
        print("ORACLE: PASS — labels are independently reproduced, "
              "only paraphrase relies on construction (as designed).")


if __name__ == "__main__":
    _selftest()
