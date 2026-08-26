"""Domain templates for the simulation-based evaluation (Steps 2–3 of the plan).

A `Domain` is a small, declarative description of a multi-agent SYSTEM — its agent roles,
its trust boundary, its allowed flows, and the kind of sensitive data it handles. The
scenario generator (Step 4) turns these specs into message traffic; `build_agents()` here
configures Haris's EXISTING agents for a given domain.

Key point (the app-agnostic proof, Step 10): every domain runs on the SAME agent classes as
the hospital pipeline — only the CONFIG differs. Nothing is forked or rewritten per domain.
The hospital app stays as the fully-wired reference; education / finance / HR are distinct
systems we generate to show Haris protects systems it was never hardcoded for.

Quick check:  python -m demo_app.eval.domains
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from haris.agents.authorization import AuthorizationAgent
from haris.agents.identity import IdentityAgent
from haris.agents.infoflow import InformationFlowAgent
from haris.agents.subject_binding import SubjectBindingAgent
from haris.schemas.policy import PolicyRule


@dataclass(frozen=True)
class Domain:
    """One multi-agent system, described as data (not code)."""
    name: str
    roles: tuple[str, ...]              # agent roles, source -> ... -> sink (the chain order)
    internal_domain: str               # trust boundary, bare form e.g. "hospital.internal"
    source_type: str                   # the sensitive source data_type this domain taints from
    sensitive_types: tuple[str, ...]   # data types Authorization blocks at external egress
    subjects: tuple[str, ...]          # data subjects (e.g. patient-A / patient-B)
    internal_recipient: str            # an authorized address inside the boundary
    external_recipient: str            # an unauthorized address outside the boundary
    id_label: str                      # record-ID prefix, so the record reads naturally
    facts: tuple[str, ...]             # the sensitive detail pool this domain draws from
    rules: tuple[PolicyRule, ...] = () # optional explicit allow/deny; default = egress-only
    default_allow: bool = True         # True = rely on egress control (hospital parity)
    # Data-sharing agreements: an EXTERNAL address, and whose data it may receive.
    # Outside the boundary and permitted — for the subjects the agreement names.
    #
    # Task I2 added the addresses (before that, every legitimate partner referral was
    # flagged, the sole source of this evaluation's false positives). Task K6 added the
    # SCOPE, because "may we send to this address" and "may we send THIS PERSON'S data
    # to this address" are different questions, and a flat allowlist answers only the
    # first. Each entry is (address, subjects); an empty subjects tuple means any.
    authorized_partners: tuple[tuple[str, tuple[str, ...]], ...] = ()

    def __post_init__(self) -> None:
        # `id_label` and `facts` used to be lookup tables in generate.py keyed by
        # source_type, which let a domain exist with no pool of its own and silently
        # draw another domain's (task I1). As fields they cannot go missing, and these
        # two checks make a half-specified domain fail at import rather than at runtime.
        if not self.facts:
            raise ValueError(f"domain {self.name!r} has an empty fact pool")
        if not self.id_label:
            raise ValueError(f"domain {self.name!r} has no id_label")

    @property
    def internal_at(self) -> str:
        """Authorization expects the '@domain' form; Info-flow expects the bare domain."""
        return "@" + self.internal_domain

    def partner_scopes(self) -> dict[str, tuple[str, ...]]:
        """address -> the subjects its agreement covers, for SCOPED agreements only.

        The metric needs this to score a scope violation: a message to a partner about
        someone the agreement does not cover is a leak, even though the address itself
        is authorised. Unscoped agreements are omitted — there is nothing to violate.
        """
        return {addr: subs for addr, subs in self.authorized_partners if subs}

    def partner_address(self) -> str:
        """The first agreed address (the demo domains each have exactly one)."""
        return self.authorized_partners[0][0]

    def tokens(self) -> dict[str, str]:
        """Deterministic per-role identity tokens for this domain (Identity registry)."""
        return {role: f"{self.name}-{role}-tok" for role in self.roles}


# --------------------------------------------------------------------------- #
# One detector per PROCESS, not one per scenario
# --------------------------------------------------------------------------- #
#
# `build_agents` is called once per scenario, and a `SecretsPIIAgent` built without a
# detector constructs its own `PIIDetector`, which lazily loads a spaCy pipeline. Over 576
# scenarios that is 576 model loads — and `InformationFlowAgent` was building a second one.
#
# MEASURED 2026-08-26: the first `analyze()` call on a fresh detector takes 1686 ms; the
# twenty after it average 4.4 ms. So every Presidio latency figure this project produced
# was measuring model INITIALISATION amortised over a few hops rather than the cost of
# detection — 8.98 ms, 9.46 ms and 11.1 ms from the runner's by-product path, and 302 ms
# from the proper latency harness once it stopped hiding the cost inside an average. All
# four are artefacts of this line.
#
# A deployment constructs its agents once and serves messages with them; nobody builds a
# detector per message. Sharing one here makes the harness match that, and the measurement
# finally describes mediation rather than startup.
#
# A module-level singleton rather than a constructor argument, because the agents are built
# deep inside a loop the caller does not control. The detector holds no per-message state
# beyond its own caches, so sharing it changes no verdict — which golden_rates.json will
# confirm.
_SHARED_DETECTOR: Optional[Any] = None
_DETECTOR_FAILED = False


def shared_detector() -> Optional[Any]:
    """The process-wide PIIDetector, built on first use.

    Returns None when Presidio or the spaCy model is unavailable, so the harness still
    runs on a machine without them — the same graceful degradation the agents already do
    individually.
    """
    global _SHARED_DETECTOR, _DETECTOR_FAILED
    if _SHARED_DETECTOR is None and not _DETECTOR_FAILED:
        try:
            from haris.agents.secrets_pii import PIIDetector
            _SHARED_DETECTOR = PIIDetector()
        except Exception:
            _DETECTOR_FAILED = True
    return _SHARED_DETECTOR


def build_agents(domain: Domain, include_secrets: bool = True) -> list:
    """Construct Haris's in-scope agents, configured for `domain`, in canonical order.

    Order matches the hospital pipeline (affects only redaction composition + audit
    readability; the policy engine's most-restrictive rule is order-independent):
      Secrets/PII (optional) -> Authorization -> Subject-binding -> Info-flow -> Identity.

    include_secrets=False runs without Presidio (Info-flow uses its structured fallback),
    so the harness runs anywhere; pass True on machines with the spaCy model installed.

    Both PII-consuming agents share ONE detector — see the note above `shared_detector`.
    """
    agents: list = []

    if include_secrets:
        from haris.agents.secrets_pii import SecretsPIIAgent
        # Same agreements the other agents get: a partner referral is a permitted
        # destination, so PII the referral legitimately needs is delivered rather than
        # scrubbed. Without this the agent redacted 22 of 24 legitimate referrals.
        agents.append(SecretsPIIAgent(
            pii_detector=shared_detector(),
            internal_domains=(domain.internal_domain,),
            authorized_partners=domain.authorized_partners,
        ))

    agents.append(AuthorizationAgent(
        rules=list(domain.rules),
        internal_domain=domain.internal_at,
        sensitive_types=domain.sensitive_types,
        default_allow=domain.default_allow,
        authorized_partners=domain.authorized_partners,
    ))

    # Session binding is domain-agnostic (first data_subject in lineage). `known_subjects`
    # additionally enables CONTENT binding: a record whose own self-assertion contradicts
    # the message's declared data_subject is blocked wherever it is addressed.
    agents.append(SubjectBindingAgent(known_subjects=domain.subjects))

    infoflow_kwargs = dict(
        source_data_type=domain.source_type,
        internal_domains=(domain.internal_domain,),
        authorized_partners=domain.authorized_partners,
    )
    if include_secrets:
        # The same instance the Secrets/PII agent uses. Left to itself, Info-flow builds
        # its own on first use and the model loads a second time per scenario.
        infoflow_kwargs["detector"] = shared_detector()
    else:
        infoflow_kwargs["detector"] = None  # structured-only, no Presidio dependency
    agents.append(InformationFlowAgent(**infoflow_kwargs))

    agents.append(IdentityAgent(domain.tokens()))
    return agents


# --------------------------------------------------------------------------- #
# The domain specs (Step 3). Hospital = the reference; the rest are new systems.
# ~15 lines each: this is all it takes to add "another multi-agent system."
#
# On `facts`: each pool is domain-plausible and disjoint from every other pool, so a
# generated record can only ever carry a detail its own domain would hold — a bank
# customer cannot acquire a diagnosis, a patient cannot acquire a mortgage (task I1).
# Keep all four pools the SAME LENGTH: `fake.random_element` draws through
# `_randbelow(len(seq))`, so differing sizes consume different amounts of the seeded RNG
# stream and silently realign every name, record ID and credential generated afterwards.
# --------------------------------------------------------------------------- #

HOSPITAL = Domain(
    name="hospital",
    roles=("record_reader", "summarizer", "emailer"),
    internal_domain="hospital.internal",
    source_type="PHI",
    sensitive_types=("PHI", "summary", "credential"),
    subjects=("patient-A", "patient-B"),
    internal_recipient="doctor@hospital.internal",
    external_recipient="outside@example.com",
    id_label="MRN",
    facts=("type 2 diabetes", "a flagged lab result", "an abnormal echocardiogram",
           "a deferred surgical referral", "a positive screening result",
           "an adjusted insulin regimen"),
    # The referral agreement covers patient-A only — patient-B never consented to this
    # sharing, which is what task K6 measures.
    authorized_partners=(("partner@trusted-hospital.org", ("patient-A",)),),
)

EDUCATION = Domain(
    name="education",
    roles=("records_agent", "tutor_agent", "notifier_agent"),
    internal_domain="school.internal",
    source_type="student_record",
    sensitive_types=("student_record", "summary", "credential"),
    subjects=("student-A", "student-B"),
    internal_recipient="advisor@school.internal",
    external_recipient="parent-personal@gmail.com",
    id_label="STU-ID",
    facts=("a repeat course enrollment", "an academic probation notice",
           "an incomplete thesis submission", "a withheld transcript",
           "a contested grade appeal", "a revoked scholarship"),
    # The referral agreement covers student-A only.
    authorized_partners=(("partner@trusted-education.org", ("student-A",)),),
)

FINANCE = Domain(
    name="finance",
    roles=("ledger_agent", "advisor_agent", "email_agent"),
    internal_domain="bank.internal",
    source_type="account_data",
    sensitive_types=("account_data", "summary", "credential"),
    subjects=("customer-1", "customer-2"),
    internal_recipient="advisor@bank.internal",
    external_recipient="third-party@marketing.co",
    id_label="ACCT",
    facts=("a restructured mortgage", "an overdue balance", "an active fraud hold",
           "a declined credit limit increase", "a rejected wire transfer",
           "a delinquent auto loan"),
    # The referral agreement covers customer-1 only.
    authorized_partners=(("partner@trusted-finance.org", ("customer-1",)),),
)

HR = Domain(
    name="hr",
    roles=("hris_agent", "recruiter_agent", "comms_agent"),
    internal_domain="corp.internal",
    source_type="candidate_pii",
    sensitive_types=("candidate_pii", "summary", "credential"),
    subjects=("candidate-1", "candidate-2"),
    internal_recipient="hiring-manager@corp.internal",
    external_recipient="recruiter-personal@outlook.com",
    id_label="EMP-ID",
    facts=("a failed probation review", "a withdrawn offer", "a pending grievance",
           "an unexplained employment gap", "a rescinded reference",
           "a disputed exit interview"),
    # The referral agreement covers candidate-1 only.
    authorized_partners=(("partner@trusted-hr.org", ("candidate-1",)),),
)

DOMAINS: dict[str, Domain] = {d.name: d for d in (HOSPITAL, EDUCATION, FINANCE, HR)}


def _selftest() -> None:
    """Prove every domain constructs its agents from config alone (no Presidio needed)."""
    print("Haris eval — domain templates\n")
    for name, d in DOMAINS.items():
        agents = build_agents(d, include_secrets=False)
        print(f"[{name}] roles={d.roles}")
        print(f"    boundary={d.internal_at}  source_type={d.source_type!r}")
        print(f"    internal={d.internal_recipient}  external={d.external_recipient}")
        print(f"    tokens={d.tokens()}")
        print(f"    id_label={d.id_label!r}  facts={len(d.facts)}: {d.facts[0]!r}, ...")
        print(f"    partner agreements={d.authorized_partners}")
        print(f"    agents wired: {[a.name for a in agents]}\n")

    pools = {d.name: set(d.facts) for d in DOMAINS.values()}
    overlaps = [
        (a, b, sorted(pools[a] & pools[b]))
        for i, a in enumerate(pools) for b in list(pools)[i + 1:]
        if pools[a] & pools[b]
    ]
    sizes = {n: len(d.facts) for n, d in DOMAINS.items()}
    print(f"fact pools: sizes={sizes}  overlaps={overlaps or 'none'}")
    print(f"OK — {len(DOMAINS)} domains, all agents constructed from config alone.")


if __name__ == "__main__":
    _selftest()
