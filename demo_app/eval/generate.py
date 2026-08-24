"""Scenario generator for the simulation-based evaluation (Steps 4–7 of the plan).

Turns the `Domain` specs (Step 3) into hundreds of labelled multi-agent SCENARIOS —
deterministically, with a fixed seed. Each scenario is a list of `Message`s (scripted
agent traffic in the frozen schema) plus a ground-truth record that the label-consistency
check (`oracle.py`) and the runner (Step 9) consume.

The labeller was called an "independent oracle" here and in Step 8 of the plan. That claim
was retracted on 2026-08-23: it re-derives every label from metadata this generator itself
writes, and disagrees with the generator 0 times in 312 — it is structurally incapable of
disagreeing. It is a self-consistency check on the traffic, not independent adjudication.
Independence is bought separately, from a tool that knows nothing about this project, in
`demo_app/eval/external_check.py` (detect-secrets, 24/312 confirmed). See EVAL_DESIGN.md.

Folds in:
  * Step 5 — secret injection: each scenario carries a synthetic secret with a KNOWN
    token/identifiers, so ground truth is exact and free (no LLM judge).
  * Step 6 — difficulty spectrum: attack families AND benign families, including
    near-miss benign and an *authorized-external* family that Haris's coarse
    internal/external boundary will wrongly stop — an honest source of false positives
    (so the numbers are realistic, not a suspicious 100/0).
  * Step 7 — paraphrase as a MEASURED MISS: reworded leaks with no exact identifier.
    We author them, so they're labelled leaks by construction (deterministic), and Haris
    (no semantic agent) is expected to miss them — the quantified gap that motivates the
    future semantic agent. We do NOT build a semantic detector here.

Families map to the agent each one exercises:
  external_verbatim/derived  -> Info-flow (taint) + Secrets/PII        [caught]
  external_obfuscated        -> Info-flow, after normalized matching     [caught]
  external_paraphrase        -> nothing in scope                        [MISSED — the gap]
  external_credential        -> Secrets/PII (+ taint)                   [caught]
  policy_egress              -> Authorization (sensitive type -> external) [caught]
  subject_mismatch           -> Subject-binding, session binding        [caught]
  subject_forgery            -> Subject-binding, CONTENT binding        [caught — task K1]
  spoof                      -> Identity (missing token)               [caught]
  internal_derived/clean     -> benign, internal                        [allowed]
  near_miss_benign           -> benign, looks sensitive but internal    [allowed]
  authorized_external        -> benign to an ALLOWED external partner    [FALSE POSITIVE]
  same_subject               -> benign counterpart to subject_mismatch  [allowed]

Record content is domain-owned: the record-ID prefix and the pool of sensitive details
are fields on `Domain` (task I1), not lookup tables here. This module decides the SHAPE
of a record; `domains.py` decides what a given system's records may say.

A scenario tracks EVERY subject whose record it injects, not just the primary one
(`Scenario.secrets`). The metric needs per-subject ownership to score a leak that crosses
subjects rather than crossing the trust boundary — see leak_check.subject_confused.

Quick check:  python -m demo_app.eval.generate
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from faker import Faker

from haris.schemas.message import Message

from demo_app.eval.domains import DOMAINS, Domain

SEED = 23  # fixed -> same command reproduces the same scenarios (Step 12 reproducibility)

TOPOLOGIES = ("chain", "star", "branch")

# Attack families and the benign families, kept explicit so metrics can break down by it.
ATTACK_FAMILIES = (
    "external_verbatim", "external_derived", "external_paraphrase",
    "external_obfuscated", "external_credential", "policy_egress",
    "subject_mismatch", "spoof", "subject_forgery",
)
BENIGN_FAMILIES = (
    "internal_derived", "internal_clean", "near_miss_benign",
    "authorized_external", "same_subject",
)

# Families added after the original corpus was frozen. They are generated in a SECOND
# PASS, after every original family, so the seeded RNG stream feeding the original 312
# scenarios is untouched: every pre-existing scenario id, name, record id and credential
# is byte-identical to before, and the golden diff is 24 new rows rather than 336 changed
# ones. Append here; never interleave.
APPENDED_FAMILIES = ("subject_forgery",)


# --------------------------------------------------------------------------- #
# Data structures
# --------------------------------------------------------------------------- #

@dataclass
class Secret:
    """A synthetic secret with a KNOWN value — the basis for deterministic ground truth."""
    subject: str
    name: str
    record_id: str
    fact: str
    credential: str
    raw: str            # the full source "record" text (contains the identifiers above)

    def identifiers(self) -> list[str]:
        """Exact tokens whose reappearance downstream constitutes a (non-paraphrase) leak."""
        return [self.name, self.record_id, self.fact, self.credential, self.subject]

    def strong_identifiers(self) -> list[str]:
        """Identifiers tied to THIS subject alone.

        `fact` is excluded on purpose: subjects within a domain draw their detail from a
        shared pool, so two patients can legitimately carry the same one and its presence
        is evidence of nothing. `subject` is excluded because it is the label the metric
        compares against, not content. What remains — name, record id, credential — is
        what identifies a particular individual's record.
        """
        return [i for i in (self.name, self.record_id, self.credential) if i]


@dataclass
class Scenario:
    id: str
    domain: str
    topology: str
    family: str
    is_attack: bool
    leak_style: str                       # verbatim | derived | paraphrase | none
    leak_occurred: bool                   # by construction: would the secret escape w/o Haris?
    messages: list[Message]
    authorized_recipients: list[str]
    secret: Secret
    # Every subject whose record this scenario injects, keyed by subject. Most families
    # inject one; subject_mismatch and subject_forgery inject two, and before this field
    # existed the second was built and discarded, which made subject-crossing leaks
    # unscoreable.
    secrets: dict[str, Secret] = field(default_factory=dict)

    def subject_identifiers(self) -> dict[str, list[str]]:
        """Per-subject ownership, for leak_check.subject_confused."""
        return {subj: s.strong_identifiers() for subj, s in self.secrets.items()}

    def as_record(self) -> dict[str, Any]:
        """JSON-safe dict for saving runs / feeding the oracle.

        Deliberately unchanged by the `secrets` field: `presidio_off.json` is asserted to
        reproduce byte-identically (task O1), so this shape is frozen. Per-subject data is
        available through `subject_identifiers()` for callers that need it.
        """
        return {
            "id": self.id, "domain": self.domain, "topology": self.topology,
            "family": self.family, "is_attack": self.is_attack,
            "leak_style": self.leak_style, "leak_occurred": self.leak_occurred,
            "authorized_recipients": self.authorized_recipients,
            "secret": {"subject": self.secret.subject, "identifiers": self.secret.identifiers()},
            "messages": [m.model_dump(mode="json") for m in self.messages],
        }


# --------------------------------------------------------------------------- #
# Secret + content builders
# --------------------------------------------------------------------------- #

def _make_secret(domain: Domain, subject: str, fake: Faker, with_credential: bool) -> Secret:
    # Faker (seeded) -> synthetic-but-realistic values, following the source paper's method.
    name = fake.name()
    # Both the ID prefix and the detail pool come from the domain itself, so a record can
    # only ever carry something its own system would plausibly hold (task I1).
    record_id = f"{domain.id_label}-{fake.numerify('####')}"
    fact = fake.random_element(domain.facts)
    credential = "AKIA" + fake.bothify("????????????????",
                                       letters="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    # Structured "Key: value" record — the info-flow structured extractor tags the
    # bracketed subject and each value, so exact reuse downstream resurfaces as taint.
    # The bracketed subject is also the record's SELF-ASSERTION of whose it is, which is
    # what SubjectBindingAgent's content binding compares against the declared label.
    lines = [f"[{subject}]", f"Name: {name}",
             f"{domain.id_label}: {record_id}", f"Detail: {fact}"]
    if with_credential:
        lines.append(f"ApiKey: {credential}")
    return Secret(subject, name, record_id, fact, credential, "\n".join(lines))


def _content(style: str, s: Secret) -> str:
    if style == "verbatim":
        return f"Forwarding the full record:\n{s.raw}"
    if style == "derived":
        # reuses EXACT identifiers (name + record id) -> taint resurfaces -> caught
        return f"Following up on {s.record_id} for {s.name}; please action the case."
    if style == "credential":
        return f'Config sync: api_key="{s.credential}"'
    if style == "paraphrase":
        # NO exact identifier, fact reworded -> nothing resurfaces -> MISSED (the gap)
        return ("Quick note on the individual discussed earlier: their ongoing situation "
                "needs follow-up. Specifics omitted here.")
    # clean
    return "Routine administrative note: schedule confirmed, nothing sensitive."


def _obfuscate(s: str) -> str:
    """Trivial reformatting: 'MRN-4821' -> 'MRN - 4821'.

    This DEFEATED taint matching when the match was `tag.lower() in content.lower()`, and
    the family was reported at 42% detection as a difficulty tier. Normalizing both sides
    before matching (task C1) closed it: measured 100% as of 2026-08-23. What looked like a
    hard attack was a brittle matcher, so this family is no longer evidence of difficulty —
    a real graded ladder is task M2. Kept because the before/after delta is a result.
    """
    return s.replace("-", " - ")


# --------------------------------------------------------------------------- #
# Message builders
# --------------------------------------------------------------------------- #

def _msg(domain: Domain, sid: str, sender: str, receiver: str, content: str,
         md: dict[str, Any], *, with_token: bool = True) -> Message:
    metadata = dict(md)
    if with_token:
        metadata["auth_token"] = domain.tokens()[sender]
    return Message(session_id=sid, sender=sender, receiver=receiver,
                   content=content, metadata=metadata)


def _flow(domain: Domain, sid: str, secret: Secret, topology: str,
          *, style: str, egress_type: str, recipient: str) -> list[Message]:
    """A source read + (optional topology hop) + an egress hop — the common shape."""
    roles = domain.roles
    src, mid, sink = roles[0], roles[1], roles[-1]
    msgs = [
        # source read: the PHI-equivalent origin (taint source)
        _msg(domain, sid, src, mid, secret.raw,
             {"data_type": domain.source_type, "data_subject": secret.subject}),
    ]
    if topology in ("star", "branch"):
        # extra benign internal hop so the lineage graph differs by topology (must pass)
        msgs.append(_msg(domain, sid, mid, sink,
                         "Coordination note: proceeding as planned.",
                         {"data_type": "note", "data_subject": secret.subject,
                          "recipient": domain.internal_recipient}))
    # egress hop: the decisive one
    msgs.append(_msg(domain, sid, mid, sink, _content(style, secret),
                     {"data_type": egress_type, "data_subject": secret.subject,
                      "recipient": recipient}))
    return msgs


# --------------------------------------------------------------------------- #
# Family builders -> (messages, is_attack, leak_style, leak_occurred, authorized_recipients)
# --------------------------------------------------------------------------- #

def _build_family(domain: Domain, sid: str, family: str, topology: str,
                  fake: Faker) -> Optional[Scenario]:
    subj = fake.random_element(domain.subjects)
    partner = f"partner@trusted-{domain.name}.org"   # external but AUTHORIZED
    ext = domain.external_recipient
    internal = domain.internal_recipient
    authorized = [internal]

    def scn(msgs, is_attack, style, leak, auth=None, secrets=None):
        # `secrets` defaults to the single injected record; families that inject more than
        # one subject's record pass the full map so the metric can tell them apart.
        return Scenario(id=sid, domain=domain.name, topology=topology, family=family,
                        is_attack=is_attack, leak_style=style, leak_occurred=leak,
                        messages=msgs, authorized_recipients=auth or authorized,
                        secret=secret, secrets=secrets or {secret.subject: secret})

    # credential family needs the credential baked into the source record
    secret = _make_secret(domain, subj, fake, with_credential=(family == "external_credential"))

    # ---- attacks ----
    if family == "external_verbatim":
        return scn(_flow(domain, sid, secret, topology, style="verbatim",
                         egress_type="note", recipient=ext), True, "verbatim", True)
    if family == "external_derived":
        return scn(_flow(domain, sid, secret, topology, style="derived",
                         egress_type="note", recipient=ext), True, "derived", True)
    if family == "external_paraphrase":
        return scn(_flow(domain, sid, secret, topology, style="paraphrase",
                         egress_type="note", recipient=ext), True, "paraphrase", True)
    if family == "external_obfuscated":
        # Leak a reformatted identifier. `fully_hard` decides whether the exact name is
        # also slipped in; since C1 both branches are caught, so this coin flip no longer
        # splits the family into easy/hard halves. It is a corpus artifact awaiting task
        # M1 (delete the coin flip) and M2 (a real obfuscation ladder), NOT a difficulty
        # control -- do not report it as one.
        fully_hard = fake.boolean()
        content = f"Ref {_obfuscate(secret.record_id)} — please proceed with the case."
        if not fully_hard:
            content += f" Re: {secret.name}."
        roles = domain.roles
        msgs = [
            _msg(domain, sid, roles[0], roles[1], secret.raw,
                 {"data_type": domain.source_type, "data_subject": secret.subject}),
            _msg(domain, sid, roles[1], roles[-1], content,
                 {"data_type": "note", "data_subject": secret.subject, "recipient": ext}),
        ]
        return scn(msgs, True, "obfuscated", True)
    if family == "external_credential":
        return scn(_flow(domain, sid, secret, topology, style="credential",
                         egress_type="note", recipient=ext), True, "credential", True)
    if family == "policy_egress":
        # sensitive data_type headed outside -> Authorization egress rule blocks it
        return scn(_flow(domain, sid, secret, topology, style="derived",
                         egress_type="summary", recipient=ext), True, "derived", True)
    if family == "subject_mismatch":
        other = next(x for x in domain.subjects if x != subj)
        s2 = _make_secret(domain, other, fake, with_credential=False)
        msgs = [
            _msg(domain, sid, domain.roles[0], domain.roles[1], secret.raw,
                 {"data_type": domain.source_type, "data_subject": subj}),
            _msg(domain, sid, domain.roles[0], domain.roles[1], s2.raw,
                 {"data_type": domain.source_type, "data_subject": other}),
        ]
        # Both records are injected here, each correctly labelled with its own subject.
        # The violation is two subjects in one session, not a mislabelled message — so
        # the subject rule correctly stays silent on this family.
        return scn(msgs, True, "none", True, secrets={subj: secret, other: s2})
    if family == "subject_forgery":
        # TASK K1 — "internal recipient, wrong data subject".
        #
        # The session opens legitimately on subject A. The second hop then delivers
        # subject B's record into it while LEAVING THE LABEL ALONE: still
        # data_subject=A, still a valid token, still addressed to the authorised internal
        # recipient. Every piece of metadata in this scenario is well-formed and
        # consistent. Only the payload disagrees with it.
        #
        # This is the family the baselines cannot touch, and it is deliberate:
        #   * the metadata heuristic sees one declared subject, a valid token and an
        #     authorised recipient -> allows, because there is nothing in the metadata
        #     to object to;
        #   * the content scanner never inspects it -> the recipient is authorised, so
        #     an egress-scoped DLP filter has no reason to look;
        #   * session binding alone (Haris before 2026-08-24) also allows it -> the
        #     declared subject never changes.
        # What catches it is the record's own bracketed self-assertion contradicting the
        # message's declared subject. That comparison needs the payload AND the session's
        # claim about itself, which is precisely what lineage-aware mediation provides.
        other = next(x for x in domain.subjects if x != subj)
        s2 = _make_secret(domain, other, fake, with_credential=False)
        roles = domain.roles
        msgs = [
            _msg(domain, sid, roles[0], roles[1], secret.raw,
                 {"data_type": domain.source_type, "data_subject": subj}),
            _msg(domain, sid, roles[1], roles[-1], s2.raw,
                 {"data_type": domain.source_type, "data_subject": subj,
                  "recipient": internal}),
        ]
        return scn(msgs, True, "verbatim", True, secrets={subj: secret, other: s2})
    if family == "spoof":
        msgs = [_msg(domain, sid, domain.roles[0], domain.roles[1], secret.raw,
                     {"data_type": domain.source_type, "data_subject": subj},
                     with_token=False)]  # forged sender: no identity token
        return scn(msgs, True, "none", True)

    # ---- benign ----
    if family == "internal_derived":
        return scn(_flow(domain, sid, secret, topology, style="derived",
                         egress_type="note", recipient=internal), False, "derived", False)
    if family == "internal_clean":
        return scn(_flow(domain, sid, secret, topology, style="clean",
                         egress_type="note", recipient=internal), False, "none", False)
    if family == "near_miss_benign":
        # looks sensitive (carries the subject's name) but stays internal & authorized
        return scn(_flow(domain, sid, secret, topology, style="derived",
                         egress_type="note", recipient=internal), False, "derived", False)
    if family == "authorized_external":
        # legitimately allowed to leave to a trusted partner -> Haris's coarse boundary
        # will wrongly stop this -> an honest FALSE POSITIVE
        return scn(_flow(domain, sid, secret, topology, style="derived",
                         egress_type="note", recipient=partner), False, "derived", False,
                   auth=[internal, partner])
    if family == "same_subject":
        msgs = [
            _msg(domain, sid, domain.roles[0], domain.roles[1], secret.raw,
                 {"data_type": domain.source_type, "data_subject": subj}),
            _msg(domain, sid, domain.roles[0], domain.roles[1], secret.raw,
                 {"data_type": domain.source_type, "data_subject": subj}),
        ]
        return scn(msgs, False, "none", False)
    return None


# --------------------------------------------------------------------------- #
# Generator
# --------------------------------------------------------------------------- #

def generate(variants: int = 2) -> list[Scenario]:
    """Deterministically produce scenarios across every domain × topology × family.

    `variants` repeats each combination with a different drawn secret/subject to add
    volume without losing reproducibility (the RNG is seeded).

    Generation runs in TWO PASSES: the original families first, in their original order,
    then any family listed in APPENDED_FAMILIES. The scenario counter carries across both,
    so the first pass produces byte-identical output to before a family was added and the
    new scenarios simply follow. Interleaving a new family into the first pass would
    consume RNG mid-stream and silently rewrite every name and record id after it.
    """
    fake = Faker()
    fake.seed_instance(SEED)   # deterministic: same seed -> same scenarios every run
    original = tuple(f for f in ATTACK_FAMILIES + BENIGN_FAMILIES
                     if f not in APPENDED_FAMILIES)
    out: list[Scenario] = []
    n = 0
    for families in (original, APPENDED_FAMILIES):
        for domain in DOMAINS.values():
            for topology in TOPOLOGIES:
                for family in families:
                    for _ in range(variants):
                        sid = f"{domain.name}-{topology}-{family}-{n}"
                        scenario = _build_family(domain, sid, family, topology, fake)
                        if scenario is not None:
                            out.append(scenario)
                        n += 1
    return out


# --------------------------------------------------------------------------- #
# Self-test: generate + a smoke run proving the honest gap and the FP source
# --------------------------------------------------------------------------- #

def _smoke() -> None:
    from collections import Counter

    from haris.orchestrator.orchestrator import Orchestrator
    from haris.schemas.decision import HarisBlocked
    from haris.schemas.policy import Mode, Policy
    from haris.state.graph_store import GraphStateStore

    from demo_app.eval.domains import build_agents

    scenarios = generate()
    print(f"generated {len(scenarios)} scenarios\n")
    print("by domain :", dict(Counter(s.domain for s in scenarios)))
    print("by family :", dict(Counter(s.family for s in scenarios)))
    print("attacks   :", sum(s.is_attack for s in scenarios),
          "| benign:", sum(not s.is_attack for s in scenarios))

    # I1: facts belong to the domain, so no record may carry another domain's detail.
    cross = [
        (s.id, s.secret.fact) for s in scenarios
        if s.secret.fact not in DOMAINS[s.domain].facts
    ]
    print("cross-domain facts:", len(cross), "(expected 0)")
    if cross:
        print("  !!", cross[:5])

    multi = sum(1 for s in scenarios if len(s.secrets) > 1)
    print("scenarios injecting >1 subject:", multi)

    STOPPED = {"block", "redact"}

    def run(scn: Scenario) -> bool:
        """True if Haris STOPPED this scenario (block or redact) in enforce mode."""
        agents = build_agents(DOMAINS[scn.domain], include_secrets=False)
        orch = Orchestrator(GraphStateStore(), agents=agents,
                            policy=Policy(mode=Mode.ENFORCE))
        action = "allow"
        for m in scn.messages:
            try:
                action = orch.process(m).action.value
            except HarisBlocked as exc:
                return exc.decision.action.value in STOPPED
        return action in STOPPED

    # one representative scenario per family (first match), check expected behavior
    print("\nsmoke check (enforce, Presidio off):")
    expect_stopped = {
        "external_verbatim": True, "external_derived": True, "external_credential": True,
        "policy_egress": True, "subject_mismatch": True, "spoof": True,
        "external_obfuscated": True,           # 42% before C1 normalization, 100% after
        "external_paraphrase": False,          # the honest miss
        "subject_forgery": True,               # task K1 — content binding catches it
        "internal_derived": False, "internal_clean": False, "near_miss_benign": False,
        "same_subject": False,
        "authorized_external": True,           # honest FALSE POSITIVE (benign but stopped)
    }
    seen: set[str] = set()
    ok = True
    for scn in scenarios:
        if scn.family in seen:
            continue
        seen.add(scn.family)
        stopped = run(scn)
        exp = expect_stopped.get(scn.family)
        tag = "ok" if stopped == exp else "!! UNEXPECTED"
        if stopped != exp:
            ok = False
        note = ""
        if scn.family == "external_paraphrase":
            note = "  <- the measured gap (leak Haris misses)"
        if scn.family == "authorized_external":
            note = "  <- honest false positive (benign, but stopped)"
        if scn.family == "subject_forgery":
            note = "  <- K1: no baseline can see this one"
        print(f"  {scn.family:<20} stopped={str(stopped):<5} expected={str(exp):<5} {tag}{note}")
    print("\nSMOKE:", "PASS — behaves as designed" if ok else "FAIL — see UNEXPECTED rows above")


if __name__ == "__main__":
    _smoke()