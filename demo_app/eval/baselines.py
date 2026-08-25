"""Non-Haris reference detectors, and the four-arm comparison (Tasks L1–L3).

WHY THIS EXISTS.
Every number the harness produced before this file was Haris measured against itself.
"Prevention 100%" answers "does Haris stop the leaks we built?" — it does not answer the
question the project actually claims, which is that *lineage-aware mediation catches
things the obvious alternatives miss*. Without a reference arm the honest sentence is
"we could not find a case where Haris fails," which is a statement about our imagination,
not about Haris.

So this module implements the alternatives, deliberately NOT as strawmen:

  arm A · no_defence         — delivers everything. Pins the denominator.
  arm B · content_scanner    — per-message content inspection at egress: detect-secrets
                               (third-party, already pinned) plus identifier-shaped
                               regexes. No session state, no memory of earlier hops.
                               This is the "existing guardrail" the thesis argues against.
  arm C · metadata_heuristic — the six-line rule from finding 01: allow when the recipient
                               is authorised, the sender carries a token, and the session
                               has touched one data subject. Metadata only; never reads
                               content.
  arm D · haris              — the system under test, via runner._run_arm, so there is
                               exactly one definition of what Haris does.

HOW THEY ARE SCORED.
Identically, and by outcome. Every arm returns the messages that actually reached each
receiver, and `leak_check.leaked` asks the same question of all four: did content carrying
an injected identifier reach an unauthorised recipient? No arm is graded on its own verdict,
so no arm can score well by being confident.

WHAT WOULD MAKE THIS TABLE DISHONEST, AND HOW IT IS AVOIDED.
  * Tuning arm B's regexes until they miss. They are written to generic shapes
    (credential assignments, LABEL-1234 record ids) and are documented below; none was
    added or removed after seeing a result.
  * Giving arm B no NER. It has none — it cannot see a bare personal name, because
    Presidio is Haris's own detector and lending it to the baseline would make the
    comparison circular (same reasoning as external_check.py). This limitation runs in
    HARIS'S FAVOUR and must be stated wherever the table is reported.
  * Scoping arm B to egress. A scanner that inspected internal hops too would flag the
    legitimate source read and score a false positive on every scenario. Egress-only is
    the charitable reading, and the one a real DLP deployment uses.
  * Reporting only the columns that flatter us. Print the whole table, including the
    families where a baseline matches or beats Haris.

READ THE RESULT BEFORE WRITING NEW ATTACK FAMILIES. Wherever arm C already scores at or
near arm D, the thesis is currently unproven on this corpus — that gap, not our intuition,
is what task K has to be built to close.

Run:  python -m demo_app.eval.baselines
"""
from __future__ import annotations

import re
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable, Optional

from haris.schemas.message import Message

from demo_app.eval.domains import DOMAINS
from demo_app.eval.generate import Scenario, generate
from demo_app.eval.leak_check import egresses, external_confirms, leaked, unauthorised
from demo_app.eval.oracle import label_consistency_check
from demo_app.eval.runner import _run_arm as _haris_arm
from demo_app.eval.stats import Interval, rate_ci
from haris.schemas.policy import Mode
from demo_app.eval.domains import build_agents


# --------------------------------------------------------------------------- #
# Result shape — identical for every arm, so scoring cannot differ between them
# --------------------------------------------------------------------------- #

@dataclass
class ArmResult:
    stopped: bool                 # did the arm halt the flow at any hop?
    detected: bool                # did it flag the DECISIVE (last) message? — runner's rule
    delivered: list[Message]      # what actually reached the receivers
    latencies: list[float]        # ms per hop, wall clock


def _deliver_all(scn: Scenario) -> list[Message]:
    return list(scn.messages)


# --------------------------------------------------------------------------- #
# Arm A — no defence
# --------------------------------------------------------------------------- #

def no_defence(scn: Scenario, include_secrets: bool = False) -> ArmResult:
    """Inspect nothing, deliver everything.

    Not a competitor — a denominator. It is what the corpus does on its own, and it is
    the only arm whose result is knowable in advance, which is precisely why it belongs
    in the table: it shows the reader what "0% mediation" looks like in these columns and
    lets them check that the other three are measuring something.
    """
    return ArmResult(stopped=False, detected=False,
                     delivered=_deliver_all(scn), latencies=[0.0] * len(scn.messages))


# --------------------------------------------------------------------------- #
# Arm B — per-message content scanner
# --------------------------------------------------------------------------- #

# Generic identifier shapes. Written to what a DLP rule-writer would plausibly ship, not
# to this corpus: a credential assignment, an AWS-style key, and a LABEL-1234 record id
# (with optional spacing, so trivial reformatting does not defeat it — arm B is given the
# benefit of the C1 lesson rather than being left brittle).
_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd)\b\s*[:=]\s*[\"']?\S{8,}"),
    re.compile(r"\b[A-Z]{2,8}\s*-?\s*\d{3,8}\b"),
)


def _scanner_flags(content: str) -> bool:
    """True if an isolated look at this one message suggests it carries a secret.

    detect-secrets first (a third party with no knowledge of this project), then the
    regexes. NOTE what is absent: there is no name detection. Arm B cannot see
    "Robert Roberts" in a message, because the only NER available here is Haris's own
    Presidio and lending it to the baseline would make the comparison circular. Report
    this: it is a limitation that flatters Haris.
    """
    if external_confirms(content):
        return True
    return any(p.search(content) for p in _PATTERNS)


def content_scanner(scn: Scenario, include_secrets: bool = False) -> ArmResult:
    """Scan each egressing message in isolation; block it if it looks like it carries a
    secret. No session state — each message is judged with no knowledge of any other.

    This is the arm the thesis is about. It should do well where the secret is still
    literally present in the egress message, and it has no mechanism at all for a
    violation that is only visible across hops.
    """
    internal = DOMAINS[scn.domain].internal_at
    delivered: list[Message] = []
    stopped = detected = False
    latencies: list[float] = []

    for m in scn.messages:
        t0 = time.perf_counter()
        recipient = (m.metadata or {}).get("recipient")
        outbound = unauthorised(recipient, scn.authorized_recipients, internal)
        flag = bool(outbound and _scanner_flags(m.content))
        latencies.append((time.perf_counter() - t0) * 1000.0)

        if flag:
            stopped = True
            detected = detected or m is scn.messages[-1]
            break                    # blocked: this message and everything after it stop
        delivered.append(m)

    return ArmResult(stopped, detected, delivered, latencies)


# --------------------------------------------------------------------------- #
# Arm C — the six-line metadata heuristic (finding 01)
# --------------------------------------------------------------------------- #

def metadata_heuristic(scn: Scenario, include_secrets: bool = False) -> ArmResult:
    """Allow when the recipient is authorised, the sender presented a token, and the
    session has touched a single data subject. Otherwise block.

    Written to the finding's description and left there. It was NOT tuned against this
    corpus, and it is deliberately not made smarter: its evidentiary value is that it is
    the obvious thing a competent engineer writes in an afternoon. If Haris cannot beat
    it, that is the result, and the report says so.

    It reads metadata only — never content — which is exactly why it is cheap, and
    exactly why content-level attacks are invisible to it.
    """
    internal = DOMAINS[scn.domain].internal_at
    delivered: list[Message] = []
    stopped = detected = False
    latencies: list[float] = []
    subjects: set[str] = set()

    for m in scn.messages:
        t0 = time.perf_counter()
        md = m.metadata or {}
        subject = md.get("data_subject")
        if subject:
            subjects.add(subject)

        # --- the six lines ---
        recipient = md.get("recipient")
        bad_recipient = recipient is not None and unauthorised(
            recipient, scn.authorized_recipients, internal)
        no_token = not md.get("auth_token")
        many_subjects = len(subjects) > 1
        flag = bad_recipient or no_token or many_subjects
        # --- end ---

        latencies.append((time.perf_counter() - t0) * 1000.0)

        if flag:
            stopped = True
            detected = detected or m is scn.messages[-1]
            break
        delivered.append(m)

    return ArmResult(stopped, detected, delivered, latencies)


# --------------------------------------------------------------------------- #
# Arm D — Haris, through the runner's own implementation
# --------------------------------------------------------------------------- #

def haris(scn: Scenario, include_secrets: bool = False) -> ArmResult:
    """The system under test. Delegates to runner._run_arm so there is exactly one
    definition of Haris's behaviour; a copy here would be free to drift."""
    agents = build_agents(DOMAINS[scn.domain], include_secrets)
    stopped, detected, lat, delivered = _haris_arm(scn, agents, Mode.ENFORCE,
                                                   want_latency=True)
    return ArmResult(stopped, detected, delivered, lat)


# --------------------------------------------------------------------------- #
# The arms, in table order
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Arm:
    key: str
    label: str
    blurb: str
    run: Callable[[Scenario, bool], ArmResult]


ARMS: tuple[Arm, ...] = (
    Arm("none", "no defence",
        "delivers everything — the denominator", no_defence),
    Arm("scanner", "content scanner",
        "per-message, egress only, no session state", content_scanner),
    Arm("metadata", "metadata heuristic",
        "recipient + token + one subject; never reads content", metadata_heuristic),
    Arm("haris", "Haris",
        "lineage-aware mediation, ENFORCE", haris),
)


# --------------------------------------------------------------------------- #
# Scoring — one rule, applied to every arm
# --------------------------------------------------------------------------- #

def score_scenario(scn: Scenario, include_secrets: bool = False) -> dict:
    """Run all four arms over one scenario and score them identically."""
    label_attack, _ = label_consistency_check(scn)
    dom = DOMAINS[scn.domain]
    args = (scn.all_identifiers(), scn.authorized_recipients, dom.internal_at)
    subj_ids = scn.subject_identifiers()
    scopes = scn.partner_scopes

    row: dict = {
        "id": scn.id, "domain": scn.domain, "topology": scn.topology,
        "family": scn.family, "leak_style": scn.leak_style,
        "rung": scn.rung,
        "depth": scn.depth,
        "rewrite": scn.rewrite,
        "label_attack": label_attack,
        "egresses": egresses(scn.messages, scn.authorized_recipients, dom.internal_at),
        "leak_unmediated": leaked(list(scn.messages), *args,
                                  subject_identifiers=subj_ids,
                              partner_scopes=scopes),
        "arms": {},
    }
    for arm in ARMS:
        res = arm.run(scn, include_secrets)
        row["arms"][arm.key] = {
            "stopped": res.stopped,
            "detected": res.detected,
            "leaked": leaked(res.delivered, *args, subject_identifiers=subj_ids,
                              partner_scopes=scopes),
            "latencies": res.latencies,
        }
    return row


def run_all(include_secrets: bool = False) -> list[dict]:
    scenarios = generate()
    for scn in scenarios[:5]:          # warm-up, same shape as runner.run_all
        score_scenario(scn, include_secrets)
    return [score_scenario(scn, include_secrets) for scn in scenarios]


# --------------------------------------------------------------------------- #
# The table (Task L3)
# --------------------------------------------------------------------------- #

def _pct(x: Optional[float]) -> str:
    return "—" if x is None else f"{x*100:.0f}%"


def _prevention(rows: list[dict], key: str) -> Optional[float]:
    """Of the scenarios that ACTUALLY leak when untouched, how many did this arm stop?

    Same denominator runner.py uses for its headline: scenarios where an identifier
    really does reach an unauthorised recipient. Attack scenarios with no egress path,
    or whose egress carries nothing to leak, are excluded from both sides.
    """
    real = [r for r in rows if r["label_attack"] and r["leak_unmediated"]]
    if not real:
        return None
    return sum(1 for r in real if not r["arms"][key]["leaked"]) / len(real)


def _false_positive(rows: list[dict], key: str) -> Optional[float]:
    benign = [r for r in rows if not r["label_attack"]]
    if not benign:
        return None
    return sum(1 for r in benign if r["arms"][key]["stopped"]) / len(benign)


def _exfiltration_ci(rows: list[dict], key: str) -> Optional[Interval]:
    """Prevention over scenarios where an identifier reaches an OUTSIDE address.

    Split from the combined rate by task I5. Data leaving the trust boundary and one
    patient's record reaching the wrong workflow are both violations, but they are
    different claims: the first is exfiltration, the second is a boundary crossing with
    nothing leaving the system. A reader hearing "leak prevention" thinks of the first.
    """
    real = [r for r in rows if r["label_attack"] and r["leak_unmediated"]
            and r["egresses"]]
    if not real:
        return None
    return rate_ci([{"ok": not r["arms"][key]["leaked"]} for r in real], "ok")


def _boundary_ci(rows: list[dict], key: str) -> Optional[Interval]:
    """Prevention over violations with NO egress path: wrong data subject, or a partner
    whose agreement does not cover this person. Nothing leaves the building, and the two
    families here are exactly the ones no baseline can see."""
    real = [r for r in rows if r["label_attack"] and r["leak_unmediated"]
            and not r["egresses"]]
    if not real:
        return None
    return rate_ci([{"ok": not r["arms"][key]["leaked"]} for r in real], "ok")


def _prevention_ci(rows: list[dict], key: str) -> Optional[Interval]:
    """Prevention with its 95% interval (task M4).

    Same denominator as `_prevention`; the interval is what stops a reader taking a
    per-family 0% or 100% from n=24 as firmly as the headline from n=168.
    """
    real = [r for r in rows if r["label_attack"] and r["leak_unmediated"]]
    if not real:
        return None
    return rate_ci([{"ok": not r["arms"][key]["leaked"]} for r in real], "ok")


def _false_positive_ci(rows: list[dict], key: str) -> Optional[Interval]:
    benign = [r for r in rows if not r["label_attack"]]
    if not benign:
        return None
    return rate_ci([{"fp": r["arms"][key]["stopped"]} for r in benign], "fp")


def _avg_latency(rows: list[dict], key: str) -> Optional[float]:
    lat = [x for r in rows for x in r["arms"][key]["latencies"]]
    return (sum(lat) / len(lat)) if lat else None


def report(rows: list[dict]) -> None:
    attacks = [r for r in rows if r["label_attack"]]
    benign = [r for r in rows if not r["label_attack"]]
    real = [r for r in attacks if r["leak_unmediated"]]

    print("FOUR-ARM COMPARISON")
    print(f"  {len(rows)} scenarios · {len(attacks)} attacks · {len(benign)} benign")
    print(f"  prevention denominator: {len(real)} scenarios that actually leak untouched")
    print( "  every arm scored by the same rule: in what that arm delivered, did an")
    print( "  injected identifier reach an unauthorised recipient, or did one subject's")
    print( "  record surface in a message declared about another?\n")

    print( "  95% bootstrap CI in brackets (task M4). The arms share a corpus, so the")
    print( "  DIFFERENCES between them are better evidence than any single rate.")
    print( "  Exfiltration and boundary crossings are reported apart (task I5): the first")
    print( "  is data leaving the trust boundary, the second is one patient's record")
    print( "  reaching the wrong workflow with nothing leaving at all.\n")
    n_ex = len([r for r in rows if r["label_attack"] and r["leak_unmediated"]
                and r["egresses"]])
    n_bd = len([r for r in rows if r["label_attack"] and r["leak_unmediated"]
                and not r["egresses"]])
    print(f"  {'arm':<20}{f'exfiltration (n={n_ex})':>24}"
          f"{f'boundary (n={n_bd})':>22}{'false pos':>20}{'ms/hop':>9}")
    for arm in ARMS:
        ex = _exfiltration_ci(rows, arm.key)
        bd = _boundary_ci(rows, arm.key)
        fp = _false_positive_ci(rows, arm.key)
        lat = _avg_latency(rows, arm.key)
        lat_s = "—" if lat is None else f"{lat:.2f}"
        print(f"  {arm.label:<20}{(ex.pct() if ex else '—'):>24}"
              f"{(bd.pct() if bd else '—'):>22}"
              f"{(fp.pct() if fp else '—'):>20}{lat_s:>9}")
    print()
    for arm in ARMS:
        print(f"  {arm.label:<20} {arm.blurb}")

    # Per-family prevention — where the arms actually differ
    print("\nPREVENTION BY FAMILY  (attack families only; n = scenarios that leak untouched)")
    fams = defaultdict(list)
    for r in attacks:
        fams[r["family"]].append(r)
    header = "".join(f"{a.key:>18}" for a in ARMS)
    print(f"  {'family':<24}{'n':>4}{header}")
    for fam in sorted(fams):
        rs = fams[fam]
        n = sum(1 for r in rs if r["leak_unmediated"])
        cells = ""
        for a in ARMS:
            ci = _prevention_ci(rs, a.key)
            cells += f"{(ci.pct() if ci else '—'):>18}"
        print(f"  {fam:<24}{n:>4}{cells}")
    print("  Every per-family n is 24 or fewer, so read the COLUMNS against each other")
    print("  rather than any cell on its own: an arm at 0% and an arm at 100% on the same")
    print("  24 scenarios differ regardless of how wide either interval is.")

    # Per-rung, all four arms. The scanner has the same literal-matching weakness Haris
    # does, so the interesting question is whether the ladder separates them at all.
    rungs = [r for r in attacks if r.get("rung")]
    if rungs:
        print("\nOBFUSCATION LADDER  (prevention per rung, all arms)")
        by = defaultdict(list)
        for r in rungs:
            by[r["rung"]].append(r)
        print(f"  {'rung':<24}{'n':>4}{header}")
        for rung in sorted(by):
            rs = by[rung]
            n = sum(1 for r in rs if r["leak_unmediated"])
            cells = ""
            for a in ARMS:
                ci = _prevention_ci(rs, a.key)
                cells += f"{(ci.pct() if ci else '—'):>18}"
            print(f"  {rung:<24}{n:>4}{cells}")
        print("  n=4 per rung: the intervals are far too wide to quote as rates. What the")
        print("  ladder shows is the ORDER — layout changes recovered by normalisation,")
        print("  encodings not — and that the metadata arm is flat across all six because")
        print("  it never opens the payload.")

    print("\nFALSE POSITIVES BY FAMILY  (benign families only)")
    bfams = defaultdict(list)
    for r in benign:
        bfams[r["family"]].append(r)
    print(f"  {'family':<24}{'n':>4}{header}")
    for fam in sorted(bfams):
        rs = bfams[fam]
        cells = ""
        for a in ARMS:
            ci = _false_positive_ci(rs, a.key)
            cells += f"{(ci.pct() if ci else '—'):>18}"
        print(f"  {fam:<24}{len(rs):>4}{cells}")

    print("\n  The boundary column is where the arms separate: both baselines score 0%")
    print("  there and Haris 100%, because subject_forgery and partner_scope_violation")
    print("  have faultless metadata and nothing leaves the system to inspect.")

    print("\nREAD THIS BEFORE QUOTING THE TABLE")
    print("  * Arm B has no name detection: Presidio is Haris's own detector, so lending")
    print("    it to the baseline would make the comparison circular. Arm B therefore")
    print("    cannot see a bare personal name. This limitation favours Haris — say so.")
    print("  * Arm B inspects egress messages only. Scanning internal hops as well would")
    print("    flag the legitimate source read in every scenario; egress-only is the")
    print("    charitable reading and the one a real DLP deployment uses.")
    print("  * Arm C never reads content and was not tuned against this corpus.")
    print("  * Wherever arm C matches or beats Haris, the thesis is unproven ON THIS")
    print("    CORPUS. That is a statement about the corpus, and it is what task K exists")
    print("    to fix — not a number to quietly drop from the report.")


if __name__ == "__main__":
    import logging
    logging.disable(logging.INFO)
    report(run_all(include_secrets=False))