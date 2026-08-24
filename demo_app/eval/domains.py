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

    def tokens(self) -> dict[str, str]:
        """Deterministic per-role identity tokens for this domain (Identity registry)."""
        return {role: f"{self.name}-{role}-tok" for role in self.roles}


def build_agents(domain: Domain, include_secrets: bool = True) -> list:
    """Construct Haris's in-scope agents, configured for `domain`, in canonical order.

    Order matches the hospital pipeline (affects only redaction composition + audit
    readability; the policy engine's most-restrictive rule is order-independent):
      Secrets/PII (optional) -> Authorization -> Subject-binding -> Info-flow -> Identity.

    include_secrets=False runs without Presidio (Info-flow uses its structured fallback),
    so the harness runs anywhere; pass True on machines with the spaCy model installed.
    """
    agents: list = []

    if include_secrets:
        from haris.agents.secrets_pii import SecretsPIIAgent
        agents.append(SecretsPIIAgent(internal_domains=(domain.internal_domain,)))

    agents.append(AuthorizationAgent(
        rules=list(domain.rules),
        internal_domain=domain.internal_at,
        sensitive_types=domain.sensitive_types,
        default_allow=domain.default_allow,
    ))

    agents.append(SubjectBindingAgent())  # domain-agnostic: binds session to first subject

    infoflow_kwargs = dict(
        source_data_type=domain.source_type,
        internal_domains=(domain.internal_domain,),
    )
    if not include_secrets:
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