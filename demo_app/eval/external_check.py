"""Third-party confirmation of the generated labels (Task H2).

WHY THIS EXISTS.
`oracle.py` re-derives each label from the traffic, which catches a broken generator but is
not independent adjudication: it reads the same facts the generator wrote, using checks that
mirror Haris's own agents. See its module docstring.

Independence has to be BOUGHT from something that knows nothing about this project. This
module runs `detect-secrets` — a pinned third-party dependency, not part of Haris, not used
by any agent in the evaluated configuration — over the messages that reach an unauthorised
recipient, and reports how many scenarios it independently confirms carry a secret.

WHAT THE NUMBER MEANS, AND WHAT IT DOES NOT.
A confirmation is strong: an outside tool agrees a secret is present at an unauthorised
destination. A non-confirmation is NOT a refutation - `detect-secrets` looks for
credential-shaped strings (API keys, tokens, high-entropy blobs). It has no opinion at all
about a patient name, a record id or a diagnosis, so the PHI families are simply outside
what it can judge.

That makes this a small honest number rather than a large dishonest one, which is the whole
point. Report it as "N of 312 labels confirmed by an external tool", never as a validation
rate for the corpus as a whole.

WHY 24 AND NOT 48. The plan expected the `external_verbatim` family to confirm as well, on
the assumption that "the whole record" includes the credential. It does not: verified
2026-08-24, a verbatim egress message carries name / record id / detail, while
`Secret.credential` is interpolated only into the `external_credential` family. So
detect-secrets finds nothing there because nothing credential-shaped is present — a fact
about the corpus, not a limit of the tool. Do not "fix" this by planting a key into the
verbatim messages to inflate the confirmed count; that is teaching to the test.

Presidio is deliberately NOT used here. Presidio is Haris's own PII detector; grading the
corpus with it would reintroduce exactly the circularity this module exists to escape.

Run:  python -m demo_app.eval.external_check
"""
from __future__ import annotations

import collections

from demo_app.eval.generate import generate
from demo_app.eval.leak_check import external_confirms, unauthorised
from demo_app.eval.domains import DOMAINS


def confirm_scenario(scn) -> bool:
    """Does an external tool find a secret in this scenario's egress traffic?"""
    internal = DOMAINS[scn.domain].internal_at
    return any(
        external_confirms(m.content)
        for m in scn.messages
        if unauthorised((m.metadata or {}).get("recipient"),
                        scn.authorized_recipients, internal)
    )


def main() -> None:
    scenarios = generate()
    per_family: dict[str, list[int]] = collections.defaultdict(lambda: [0, 0])
    confirmed = 0

    for scn in scenarios:
        row = per_family[scn.family]
        row[0] += 1
        if scn.is_attack and confirm_scenario(scn):
            row[1] += 1
            confirmed += 1

    print("External confirmation of generated labels — detect-secrets (third-party)\n")
    print(f"{'family':<24}{'n':>5}{'confirmed':>12}")
    for fam in sorted(per_family):
        n, k = per_family[fam]
        print(f"{fam:<24}{n:>5}{k:>12}")
    print(f"\n  {confirmed}/{len(scenarios)} labels confirmed by an external tool.")
    print( "  A confirmation means an outside tool agrees a secret reaches an unauthorised")
    print( "  recipient. A non-confirmation is NOT a refutation: detect-secrets recognises")
    print( "  credential-shaped strings only and has no opinion on names, record ids or")
    print( "  diagnoses, so the PHI families lie outside what it can judge.")


if __name__ == "__main__":
    main()