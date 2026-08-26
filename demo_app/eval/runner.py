"""Two-arm runner + metrics (Steps 9 and 11 of the plan).

Runs every generated scenario through Haris two ways and compares the result against the
generated label:

  * monitor   (agents, MONITOR)      -> DETECTION: did any agent raise a concern on the
                                        scenario's DECISIVE hop (see `_run_arm`)?
  * enforce   (agents, ENFORCE)      -> PREVENTION: was the message actually blocked/redacted?

There is deliberately no "no-Haris" arm here. Running an empty agent list in monitor mode
cannot stop anything, so its 100% leak rate was fixed before the run started -- a constant,
not a measurement. The reference point is measured instead, by leak_check.py: a scenario
leaks when content reaching an unauthorised recipient still carries an injected identifier,
or when one subject's record surfaces in a message declared about another. The same rule
scores every arm. Measured on untouched traffic: 120 of 192 attack scenarios leak, not 192.

Non-Haris comparison arms -- a no-op, a per-message content scanner, and the six-line
metadata heuristic from finding 01 -- live in `demo_app/eval/baselines.py` (task L) and are
scored by the same rule. Run `python -m demo_app.eval.baselines` for the four-arm table.

Then it reports, overall and broken down by leak-style / domain / family:
  * detection rate       (of labelled attacks, fraction detected in monitor)
  * EXFILTRATION prevention and BOUNDARY-CROSSING prevention, separately (task I5):
    an identifier reaching an outside address and one patient's record reaching the
    wrong workflow are both violations, but they are different claims and a single
    combined rate lets a reader hear the first when half the denominator is the second
  * false-positive rate  (of labelled benign, fraction wrongly stopped in enforce)
  * latency              (avg + p95 per hop, from the tamper-evident audit log)

Presidio is OFF by default so the run is deterministic and dependency-free (Info-flow's
structured taint carries verbatim/derived/credential). Pass include_secrets=True on a box
with the spaCy model to add the Secrets/PII agent's contribution.

Run:  python -m demo_app.eval.runner
"""
from __future__ import annotations

from collections import defaultdict
from typing import Optional

from haris.audit import AuditLog
from haris.orchestrator.orchestrator import Orchestrator
from haris.schemas.decision import HarisBlocked
from haris.schemas.message import Message
from haris.schemas.policy import Mode, Policy
from haris.state.graph_store import GraphStateStore

from demo_app.eval.domains import DOMAINS, build_agents
from demo_app.eval.generate import Scenario, generate
from demo_app.eval.leak_check import egresses, leaked
from demo_app.eval.stats import rate_ci
from demo_app.eval.oracle import label_consistency_check

STOPPED = {"block", "redact"}


def _run_arm(scn: Scenario, agents: list, mode: Mode, want_latency: bool = False):
    """Return (stopped, detected, latencies, delivered) for one scenario under one arm.

    `delivered` is what actually reached each receiver: blocked messages are absent,
    redacted ones appear in their scrubbed form. It is what the leak metric reads, so the
    score reflects the OUTCOME rather than the verdict a detector produced.

    DETECTION IS SCOPED TO THE DECISIVE HOP -- the scenario's LAST message, which is the
    violating one by construction in every family (the egress hop for the exfiltration
    families, the second subject's record for subject_mismatch, the untokened message for
    spoof). It used to be "any non-PASS verdict on any message anywhere in the scenario",
    which is not detection of the violation: it is detection of anything, anywhere. With
    Presidio ON that is satisfied trivially by the INTERNAL SOURCE HOP, which legitimately
    carries the record and always flags PERSON -- so every scenario scored as detected and
    the rate pinned at 100%. The tell was the paraphrase family reading detect=100% /
    prevent=0% on messages carrying no injected identifier at all: nothing in them can be
    detected, so the 100% was measuring a different hop than the one the claim is about.

    Scoping to the EGRESSING hop instead was tried and is wrong: spoof and subject_mismatch
    never egress (0 of 24 each), so they would report detect=0% for two threat classes
    Haris blocks 100% of the time.
    """
    audit = AuditLog() if want_latency else None
    orch = Orchestrator(GraphStateStore(), agents=agents,
                        policy=Policy(mode=mode), audit_log=audit)
    stopped = detected = False
    delivered: list[Message] = []
    for m in scn.messages:
        try:
            d = orch.process(m)
            if d.action.value in STOPPED:
                stopped = True
            if m is scn.messages[-1] and any(v.label.name != "PASS" for v in d.verdicts):
                detected = True
            content = d.final_content if d.final_content is not None else m.content
            delivered.append(m.model_copy(update={"content": content}))
        except HarisBlocked:          # enforce-mode block halts the flow (correct semantics)
            stopped = True
            detected = detected or m is scn.messages[-1]
            break                     # nothing further is delivered, and neither was this
    latencies = [r.latency_ms for r in audit.records()] if audit else []
    return stopped, detected, latencies, delivered


# Difficulty gradient for the data-exfiltration threat — how hard the attacker works to
# hide the leaked identifier.
#
# STATE (2026-08-24): "medium" is now a real six-rung ladder rather than one transform
# (task M2) — see OBFUSCATION_LADDER in generate.py and the BY RUNG table below, which is
# the figure to report. "hard" still carries no injected identifier at all, so there is
# nothing in those messages to detect; task M3 replaces it with paraphrases that genuinely
# retain the secret. Read the per-rung curve, not this three-way split.
_DIFFICULTY = {
    "external_verbatim": "easy",     # full record copied (exact token present)
    "external_derived": "easy",      # exact identifier reused
    "external_obfuscated": "medium", # identifier transformed — see the rung breakdown
    "external_paraphrase": "hard",   # identifier semantically reworded (no literal token)
}


def run_scenario(scn: Scenario, include_secrets: bool = False) -> dict:
    agents = build_agents(DOMAINS[scn.domain], include_secrets)
    label_attack, _ = label_consistency_check(scn)
    # NOTE: there is no "without Haris" arm in THIS module. Running an EMPTY agent list in
    # monitor mode cannot stop anything -- most_restrictive([]) is ALLOW and monitor clamps
    # above FLAG anyway -- so its output was a constant, not a measurement. That every
    # attack scenario leaks absent mediation is a property of how the corpus is
    # CONSTRUCTED; it is stated in report() and must not be presented as an experimental
    # result. Comparison arms that are not Haris live in baselines.py (task L) and are
    # scored by the same rule as this module; see `python -m demo_app.eval.baselines`.
    _, detected, _, _ = _run_arm(scn, agents, Mode.MONITOR)              # detection
    stopped, _, lat, delivered = _run_arm(scn, agents, Mode.ENFORCE, want_latency=True)

    # The reference arm. NOT "Haris with no agents" -- that configuration always allows, so
    # its result was a constant. This is the scenario's own traffic delivered untouched,
    # scored by the same external rule as every other arm: did an unauthorised recipient
    # actually receive the injected secret, or did one subject's record surface under
    # another subject's label? It can, and does, come out below 100%.
    dom = DOMAINS[scn.domain]
    args = (scn.all_identifiers(), scn.authorized_recipients, dom.internal_at)
    subj_ids = scn.subject_identifiers()
    scopes = scn.partner_scopes
    return {
        "id": scn.id, "domain": scn.domain, "topology": scn.topology,
        "family": scn.family, "leak_style": scn.leak_style,
        "rung": scn.rung,                            # obfuscation ladder rung (task M2)
        "depth": scn.depth,                          # chain depth in hops (task K2)
        "rewrite": scn.rewrite,                      # rewrite-chain level (task K2)
        "record_format": scn.record_format,          # source record shape (task N1)
        "difficulty": _DIFFICULTY.get(scn.family),   # None for non-exfiltration threats
        "label_attack": label_attack,
        "detected": detected, "stopped": stopped,
        # measured outcomes, independent of any detector's verdict
        "egresses": egresses(scn.messages, scn.authorized_recipients, dom.internal_at),
        "leak_unmediated": leaked(list(scn.messages), *args, subject_identifiers=subj_ids,
                              partner_scopes=scopes),
        "leak_haris": leaked(delivered, *args, subject_identifiers=subj_ids,
                              partner_scopes=scopes),
        "latencies": lat,
    }


def run_all(include_secrets: bool = False, seed: Optional[int] = None) -> list[dict]:
    scenarios = generate() if seed is None else generate(seed=seed)
    # small warm-up so reported latency is steady-state, not cold-start
    for scn in scenarios[:5]:
        _run_arm(scn, build_agents(DOMAINS[scn.domain], include_secrets), Mode.ENFORCE, True)
    return [run_scenario(scn, include_secrets) for scn in scenarios]


# --------------------------------------------------------------------------- #
# Metrics (first cut of Step 11)
# --------------------------------------------------------------------------- #

def _rate(rows, key) -> float:
    return (sum(1 for r in rows if r[key]) / len(rows)) if rows else 0.0


def _pct(x) -> str:
    return f"{x*100:.0f}%"


def report(records: list[dict]) -> None:
    attacks = [r for r in records if r["label_attack"]]
    benign = [r for r in records if not r["label_attack"]]
    all_lat = sorted(x for r in records for x in r["latencies"])

    print(f"scenarios: {len(records)}  (attacks {len(attacks)} · benign {len(benign)})\n")

    # ------------------------------------------------------------------ #
    # TWO CLAIMS, TWO DENOMINATORS (task I5)
    # ------------------------------------------------------------------ #
    #
    # A single "leak prevention" number over every attack that goes wrong mixes two
    # different things. `external_verbatim` sends an identifier to an address outside the
    # trust boundary: data leaves, and stopping it is exfiltration prevention.
    # `subject_forgery` hands one patient's record to a workflow bound to another, and
    # `spoof` arrives without a token — both are real violations, and in both cases
    # nothing leaves the building at all.
    #
    # Reporting them together lets a reader hear "we prevented 152 leaks" when a third of
    # those scenarios had no egress path to leak through. Neither claim is weaker than
    # the other; they are answers to different questions, and the split is what lets a
    # reader check which one a given family supports.
    egress_leaks = [r for r in attacks if r["egresses"] and r["leak_unmediated"]]
    inside_only = [r for r in attacks if not r["egresses"] and r["leak_unmediated"]]
    no_leak_path = [r for r in attacks if not r["leak_unmediated"]]

    print("CORPUS  (measured by outcome, not by any detector's verdict)")
    print(f"  attack scenarios                    : {len(attacks)}")
    print(f"  ...EXFILTRATION: reach an outside address with an identifier")
    print(f"                                      : {len(egress_leaks)}")
    print(f"  ...BOUNDARY CROSSINGS: wrong subject, or outside a partner's agreement,")
    print(f"     with nothing leaving the system  : {len(inside_only)}")
    print(f"  ...no leak path at all              : {len(no_leak_path)}  "
          f"(policy violations that carry nothing to leak)")
    print( "  A secret 'leaks' when content reaching an unauthorised recipient still")
    print( "  carries an injected identifier, when one subject's record surfaces in a")
    print( "  message declared about another, or when it reaches a partner whose")
    print( "  agreement does not cover that subject. Same rule scores every arm.\n")

    def _stopped_ci(rows):
        return rate_ci([{"ok": not r["leak_haris"]} for r in rows], "ok") if rows else None

    exfil_ci = _stopped_ci(egress_leaks)
    inside_ci = _stopped_ci(inside_only)
    both_ci = _stopped_ci(egress_leaks + inside_only)

    print("HEADLINE  (95% bootstrap CI in brackets — task M4; a rate without one hides")
    print( "           whether it rests on 168 observations or on four)")
    print(f"  exfiltration prevented   : {exfil_ci.pct() if exfil_ci else '—'}  "
          f"(n={len(egress_leaks)}) — an identifier reached an outside address")
    print(f"  boundary crossings caught: {inside_ci.pct() if inside_ci else '—'}  "
          f"(n={len(inside_only)}) — wrong subject or outside an agreement, no egress")
    print(f"  ...combined              : {both_ci.pct() if both_ci else '—'}  "
          f"(n={len(egress_leaks) + len(inside_only)})  <- quote the two above, not this")

    det_ci = rate_ci(attacks, "detected")
    fp_ci = rate_ci(benign, "stopped")
    print(f"  detection                : {det_ci.pct() if det_ci else '—'}  (monitor arm)")
    print(f"  false positive           : {fp_ci.pct() if fp_ci else '—'}  "
          f"({sum(1 for r in benign if r['stopped'])}/{len(benign)} benign wrongly stopped)")
    print(f"  utility                  : {_pct(1 - _rate(benign, 'stopped'))}  "
          f"(benign traffic delivered unharmed)")
    print(f"  (verdict-based           : {sum(1 for r in attacks if r['stopped'])}"
          f"/{len(attacks)} stopped -> {_pct(_rate(attacks, 'stopped'))}  "
          f"— counts scenarios with nothing to leak)")
    if all_lat:
        p95 = all_lat[min(len(all_lat) - 1, int(0.95 * len(all_lat)))]
        print(f"  latency/hop              : {sum(all_lat)/len(all_lat):.2f} ms avg · "
              f"{p95:.2f} ms p95")

    def breakdown(title, key, rows):
        """Every column carries its 95% interval (task M4).

        An earlier version put one only on the false-positive column, on the grounds
        that it was the number most likely to be over-read. That was the wrong call: a
        family reading `prevent=33%` from 24 observations is exactly as easy to quote as
        a result, and the four-arm table already showed the same figure with its
        interval. Printing a number two ways, one of them bare, invites a reader to pick
        the confident-looking one.
        """
        print(f"\n{title}")
        groups = defaultdict(list)
        for r in rows:
            groups[r[key]].append(r)
        for g in sorted(groups):
            rs = groups[g]
            atk = [r for r in rs if r["label_attack"]]
            ben = [r for r in rs if not r["label_attack"]]
            det_i = rate_ci(atk, "detected") if atk else None
            prev_i = rate_ci(atk, "stopped") if atk else None
            fp_i = rate_ci(ben, "stopped") if ben else None
            det = det_i.pct() if det_i else "—"
            prev = prev_i.pct() if prev_i else "—"
            fp = fp_i.pct() if fp_i else "—"
            print(f"  {str(g):<20} detect={det:<16} prevent={prev:<16} "
                  f"fp={fp:<16} (n={len(rs)})")

    breakdown("BY LEAK STYLE  (paraphrase carries no identifier — see the corpus note)",
              "leak_style", records)
    breakdown("BY DOMAIN  (consistency = generalization)", "domain", records)
    breakdown("BY TOPOLOGY  (near-flat by design: Haris judges each hop independently)",
              "topology", records)

    # Difficulty gradient — see the _DIFFICULTY note above for its current honest state.
    diff = [r for r in records if r.get("difficulty")]
    if diff:
        print("\nBY DIFFICULTY  (easy/medium are real; the 'hard' rung is not yet a "
              "genuine leak — task M3)")
        by = defaultdict(list)
        for r in diff:
            by[r["difficulty"]].append(r)
        for level in ("easy", "medium", "hard"):
            rs = by.get(level, [])
            if not rs:
                continue
            det_i = rate_ci(rs, "detected")
            prev_i = rate_ci(rs, "stopped")
            print(f"  {level:<8} detect={det_i.pct():<16} prevent={prev_i.pct():<16} "
                  f"(n={len(rs)})")

    # THE OBFUSCATION LADDER (task M2). This is the curve, and it is the figure worth
    # printing: the family average above is a function of which rungs we chose to
    # include, so it says more about the corpus than about Haris.
    rungs = [r for r in records if r.get("rung")]
    if rungs:
        print("\nBY OBFUSCATION RUNG  (easy -> hard; layout changes, then encodings)")
        by = defaultdict(list)
        for r in rungs:
            by[r["rung"]].append(r)
        wide = 0
        for rung in sorted(by):
            rs = by[rung]
            ci = rate_ci(rs, "stopped")
            leaks = sum(1 for r in rs if r["leak_haris"])
            bar = "#" * int(round(ci.rate * 10)) or "."
            flag = "" if ci.is_informative else "  (!)"
            wide += 0 if ci.is_informative else 1
            print(f"  {rung:<18} prevent={ci.pct():<16} leaked={leaks:<3} "
                  f"(n={ci.n}) {bar}{flag}")
        if wide:
            print(f"  (!) {wide} of {len(by)} rungs have an interval too wide to quote as a")
            print( "      rate. Report the SHAPE of this curve — layout changes recovered,")
            print( "      encodings not — and treat the percentages as indicative only.")

    # THE DEPTH LADDER (task K2). Two questions in one table: does lineage still catch
    # the leak when the identifier is read at hop 1 and resurfaces at hop 8 with nothing
    # identifying in between, and what does keeping that memory cost per hop?
    #
    # The second is the one nobody had measured. The orchestrator replays session history
    # on every hop, so a deeper chain does strictly more work; whether that grows linearly
    # or worse decides whether this design survives a long-running agent session.
    deep = [r for r in records if r.get("depth")]
    if deep:
        print("\nBY CHAIN DEPTH  (identifier read at hop 1, resurfaces at the last hop)")
        by = defaultdict(list)
        for r in deep:
            by[r["depth"]].append(r)
        print(f"  {'hops':>6}{'prevented':>20}{'ms/hop':>10}{'ms/session':>13}")
        for d in sorted(by):
            rs = by[d]
            ci = rate_ci(rs, "stopped")
            lat = [x for r in rs for x in r["latencies"]]
            per_hop = sum(lat) / len(lat) if lat else 0.0
            per_session = sum(lat) / len(rs) if rs else 0.0
            print(f"  {d:>6}{ci.pct():>20}{per_hop:>10.3f}{per_session:>13.3f}")
        print("  If ms/hop climbs with depth, the cost of remembering is superlinear in")
        print("  session length and belongs in §8 as a scaling limit; if it is flat, the")
        print("  history replay is not the bottleneck it looks like.")

    # THE REWRITE CHAIN (task K2). The record is restated at every hop, degrading, so no
    # message holds the source record by the time it egresses. The level where prevention
    # falls names the identifier the matcher was actually relying on: everything above it
    # survived on that identifier and nothing below it has anything left to survive on.
    rewrites = [r for r in records if r.get("rewrite")]
    if rewrites:
        print("\nBY REWRITE LEVEL  (the record degrades as it is passed along)")
        by = defaultdict(list)
        for r in rewrites:
            by[r["rewrite"]].append(r)
        for level in sorted(by):
            rs = by[level]
            ci = rate_ci(rs, "stopped")
            bar = "#" * int(round(ci.rate * 10)) or "."
            print(f"  {level:<20} prevent={ci.pct():<16} (n={ci.n}) {bar}")
        print("  Distinct from the obfuscation ladder: that transforms one identifier's")
        print("  encoding in a single step, this degrades the content cumulatively across")
        print("  hops. They fail for different reasons and are reported apart.")

    # BY RECORD FORMAT (task N1). The egress hop is identical across these scenarios, so
    # any variation here is the source PARSER and not the threat. With Presidio off the
    # structured extractor is the only source of taint tags, and this is the measurement
    # of how much that matters.
    fmts = [r for r in records if r.get("record_format")]
    if fmts:
        print("\nBY RECORD FORMAT  (same leak, four source shapes)")
        by = defaultdict(list)
        for r in fmts:
            by[r["record_format"]].append(r)
        for fmt in sorted(by):
            rs = by[fmt]
            ci = rate_ci(rs, "stopped")
            bar = "#" * int(round(ci.rate * 10)) or "."
            print(f"  {fmt:<18} prevent={ci.pct():<16} (n={ci.n}) {bar}")
        print("  Every other family in the corpus uses the structured shape, so the")
        print("  headline rates are conditioned on it. Quote this table beside them.")

    breakdown("BY FAMILY", "family", records)


if __name__ == "__main__":
    import logging
    logging.disable(logging.INFO)
    report(run_all(include_secrets=False))