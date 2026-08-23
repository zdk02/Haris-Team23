"""Regression tests for two defects the Presidio-OFF suite could not see (2026-08-24).

Both bugs shared a shape: the evaluation's default configuration hid them. The suite ran
with Presidio off, so the agent that was misconfigured was never even constructed; and the
metric that was wrong only became wrong once that agent started producing verdicts. Neither
test below needs Presidio, which is the point -- a guard that only fires in the expensive
configuration is a guard nobody runs.

1. EVERY agent is configured for the domain it is evaluating.
   `SecretsPIIAgent` was constructed bare in `build_agents`, and its default
   `internal_domains` is `("hospital.internal",)`. So education / finance / HR ran their PII
   scanner against HOSPITAL's trust boundary: every internal hop in those domains looked
   like egress and was redacted. Measured cost with Presidio on -- false positives 48% vs
   20%, utility 52% vs 80%, and per-domain FP of 20/57/57/57 where the report claims
   "consistency across domains = generalization". This contradicted the project's central
   app-agnostic claim (plan decision 3, Step 10: "no hardcoded hospital values") in exactly
   the configuration we ship.

2. DETECTION is scoped to the hop the claim is about.
   `detected` was "any non-PASS verdict on any message in the scenario". With Presidio on
   the internal SOURCE hop always flags PERSON, so every scenario counted as detected and
   the rate pinned at 100% -- including the paraphrase family, whose messages carry no
   injected identifier at all. See `_run_arm`'s docstring.
"""
from __future__ import annotations

from haris.schemas.message import Message
from haris.schemas.policy import Mode

from demo_app.eval.domains import DOMAINS, build_agents
from demo_app.eval.generate import generate
from demo_app.eval.runner import _run_arm


# --------------------------------------------------------------------------- #
# 1. No agent may carry another domain's trust boundary
# --------------------------------------------------------------------------- #

def _boundaries(agent) -> set[str]:
    """Every trust-boundary value this agent holds, normalised to the bare domain."""
    found: set[str] = set()
    for attr in ("internal_domains", "internal_domain"):
        value = getattr(agent, attr, None)
        if value is None:
            continue
        values = [value] if isinstance(value, str) else list(value)
        found |= {str(v).lstrip("@").lower() for v in values}
    return found


def test_every_agent_is_built_for_its_own_domain():
    """Deliberately not a check that one specific agent got one specific kwarg.

    Written as an invariant over WHATEVER `build_agents` returns, so it also catches the
    next agent someone adds without wiring the domain through -- which is how this bug got
    in. Runs with include_secrets=True: constructing `SecretsPIIAgent` does not require
    Presidio (the detector is built lazily), so the guard runs everywhere.
    """
    others = {d.internal_domain.lower() for d in DOMAINS.values()}
    for domain in DOMAINS.values():
        foreign = others - {domain.internal_domain.lower()}
        for agent in build_agents(domain, include_secrets=True):
            leaked_in = _boundaries(agent) & foreign
            assert not leaked_in, (
                f"{agent.name} in domain '{domain.name}' holds the trust boundary of "
                f"another domain: {sorted(leaked_in)}. Every agent must be configured "
                f"from the Domain spec -- see this module's docstring.")


def test_the_pii_agents_default_is_still_hospital_specific():
    """Pins WHY the test above matters, so a reader doesn't dismiss it as paranoia.

    If this ever fails because the default became domain-neutral, that is good news: delete
    this test and keep the one above.
    """
    from haris.agents.secrets_pii import SecretsPIIAgent
    assert SecretsPIIAgent().internal_domains == ("hospital.internal",)


# --------------------------------------------------------------------------- #
# 2. Detection is the decisive hop, not any hop
# --------------------------------------------------------------------------- #

def _one(family: str):
    return next(s for s in generate() if s.family == family)


def test_a_verdict_on_the_source_hop_alone_is_not_a_detection():
    """The bug, reproduced without Presidio by injecting a stub agent that flags the source
    hop and nothing else -- which is exactly what the PII scanner does to a record.
    """
    class FlagsTheSourceHop:
        name = "stub"

        def check(self, message, context):
            from haris.schemas.verdict import Label, Verdict
            is_source = message.metadata.get("data_type") == "PHI"
            return Verdict(agent_name=self.name,
                           label=Label.FLAG if is_source else Label.PASS,
                           score=1.0 if is_source else 0.0, reason="stub")

    scn = _one("external_paraphrase")
    _, detected, _, _ = _run_arm(scn, [FlagsTheSourceHop()], Mode.MONITOR)
    assert detected is False, (
        "a flag raised only on the internal source hop was counted as detecting the leak")


def test_a_verdict_on_the_decisive_hop_is_a_detection():
    class FlagsEverything:
        name = "stub"

        def check(self, message, context):
            from haris.schemas.verdict import Label, Verdict
            return Verdict(agent_name=self.name, label=Label.FLAG, score=1.0, reason="stub")

    scn = _one("external_derived")
    _, detected, _, _ = _run_arm(scn, [FlagsEverything()], Mode.MONITOR)
    assert detected is True


def test_threats_that_never_egress_are_still_detectable():
    """Guards against the fix I nearly shipped instead.

    Scoping detection to the EGRESSING hop looks equivalent and is not: spoof and
    subject_mismatch never address an outside recipient (0 of 24 each), so that version
    reported detect=0% for two threat classes Haris stops 100% of the time.
    """
    from demo_app.eval.runner import run_scenario
    for family in ("spoof", "subject_mismatch"):
        scn = _one(family)
        assert not any((m.metadata or {}).get("recipient") for m in scn.messages), family
        assert run_scenario(scn)["detected"] is True, family
