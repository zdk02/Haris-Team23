"""The strict-recipient measurement behind THREAT_MODEL.md §2.3 (Task E1/E2).

WHY THIS EXISTS.
A message with no `recipient` is ambiguous: it is both the ordinary internal agent-to-agent
handoff AND what a compromised sender produces by deleting the key. Nothing in the message
separates them. The audit findings asked for the strict reading — treat an absent recipient
as external — as the fix for the trusted-metadata problem.

We did not take it, and the reason is a measurement rather than an opinion: the strict
reading stops everything, including every legitimate first hop, because that hop is a
genuine internal PHI handoff with no recipient. This module runs both configurations over
the same corpus and prints the three rates, so the claim in THREAT_MODEL.md §2.3 can be
checked by running it instead of believed by reading it.

WHAT IS HELD CONSTANT.
Everything except the two flags. The agents are built by the SAME `build_agents()` the main
evaluation uses; this module then flips `AuthorizationAgent.treat_missing_recipient_as_external`
and `SecretsPIIAgent.treat_missing_recipient_as_internal` on the constructed objects. Same
corpus, same seed, same orchestrator, same policy engine, same scoring rule — so the
difference between the two rows is attributable to the recipient policy alone.

HOW TO READ THE RESULT.
Leak prevention is scored by outcome (`leak_check.py`): a scenario is prevented when content
reaching an unauthorised recipient no longer carries an injected identifier. Strict mode
scores 100% there — and 100% false positives with 0% utility, because it blocks the benign
traffic too. A configuration that stops everything prevents every leak trivially; that is
why prevention must never be read without the other two columns.

The strict reading becomes correct only once the interception adapter binds `recipient` from
the transport, at which point an absent recipient really does mean "no destination was
declared" rather than "the sender did not say".

Run:  python -m demo_app.eval.strict_recipient
"""
from __future__ import annotations

from haris.agents.authorization import AuthorizationAgent
from haris.agents.secrets_pii import SecretsPIIAgent

import demo_app.eval.runner as runner
from demo_app.eval.domains import build_agents


def _strict(agents: list) -> list:
    """Flip the missing-recipient policy on an already-built agent list."""
    for agent in agents:
        if isinstance(agent, AuthorizationAgent):
            agent.treat_missing_recipient_as_external = True
        elif isinstance(agent, SecretsPIIAgent):
            agent.treat_missing_recipient_as_internal = False
    return agents


def measure(strict: bool, include_secrets: bool = False) -> dict:
    """Run the whole corpus in one configuration and return its three headline rates."""
    original = runner.build_agents
    if strict:
        runner.build_agents = lambda d, s=include_secrets: _strict(build_agents(d, s))
    try:
        rows = runner.run_all(include_secrets=include_secrets)
    finally:
        runner.build_agents = original

    attacks = [r for r in rows if r["label_attack"]]
    benign = [r for r in rows if not r["label_attack"]]
    leaking = [r for r in attacks if r["leak_unmediated"]]
    prevented = sum(1 for r in leaking if not r["leak_haris"])
    stopped_benign = sum(1 for r in benign if r["stopped"])
    return {
        "prevented": prevented, "leaking": len(leaking),
        "false_pos": stopped_benign, "benign": len(benign),
        "utility": len(benign) - stopped_benign,
    }


def _row(label: str, m: dict) -> str:
    pct = lambda k, n: f"{(k / n * 100):.0f}%" if n else "—"
    return (f"{label:<34}"
            f"{pct(m['prevented'], m['leaking']):>12}"
            f"{pct(m['false_pos'], m['benign']):>16}"
            f"{pct(m['utility'], m['benign']):>10}")


def main() -> None:
    print("Missing-recipient policy — both configurations over the same corpus\n")
    print(f"{'configuration':<34}{'prevention':>12}{'false positives':>16}{'utility':>10}")
    permissive = measure(strict=False)
    strict = measure(strict=True)
    print(_row("absent = internal (shipped default)", permissive))
    print(_row("absent = external (strict)", strict))
    print(f"\n  Prevention is scored over the {permissive['leaking']} scenarios that actually leak "
          f"unmediated;\n  false positives and utility over the {permissive['benign']} benign scenarios.")
    print( "\n  Strict mode prevents every leak by blocking every session at its first hop —")
    print( "  that hop is a legitimate internal handoff carrying no recipient. Prevention")
    print( "  without the other two columns is not a result. See THREAT_MODEL.md §2.3.")


if __name__ == "__main__":
    main()
