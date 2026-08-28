"""Which agent catches what — derived from the corpus, not from design intent.

Appendix C used to be a hand-written table over the nine curated hospital cases, asserting
which agent was *supposed* to catch each threat. This module measures it instead: it replays
every generated scenario through the full agent line-up and records, per family, which agents
actually objected at the decisive hop.

The distinction matters. A hand-written matrix says what we believe; this one can disagree
with us.

Runs in MONITOR. A block in enforce mode raises and halts the flow, which would leave no
Decision to inspect on exactly the hops Haris catches hardest — so the families we handle
best would be the ones we could say least about. Monitor runs every agent and records every
verdict while stopping nothing, which is precisely what a census of objections needs (the
mode gate is applied last and does not change what the agents return — see report §3.4).

Run:
    python -m demo_app.eval.agent_matrix
    python -m demo_app.eval.agent_matrix --secrets
"""
from __future__ import annotations

from collections import defaultdict

from haris.orchestrator.orchestrator import Orchestrator
from haris.schemas.policy import Mode, Policy
from haris.state.graph_store import GraphStateStore

from demo_app.eval.domains import DOMAINS, build_agents
from demo_app.eval.generate import generate

# An agent that returns PASS looked and had no objection. Everything else is a contribution
# to the decision — FLAG included, since a flag is what drives redaction and what the
# monitor arm scores as detection.
_OBJECTING = {"FLAG", "BLOCK", "REDACT"}

AGENT_ORDER = ["secrets_pii", "authorization", "subject_binding", "infoflow", "identity"]

AGENT_LABELS = {
    "secrets_pii": "Secrets & PII",
    "authorization": "Authorization",
    "subject_binding": "Data-Subject",
    "infoflow": "Info-Flow",
    "identity": "Identity",
}


def _domain_index() -> dict:
    """Map a domain NAME to its Domain object.

    `Scenario.domain` carries the name; `build_agents` wants the object. DOMAINS may be
    either a dict keyed by name or a sequence of Domain objects, so handle both rather than
    depending on which.
    """
    if isinstance(DOMAINS, dict):
        return dict(DOMAINS)
    index = {}
    for d in DOMAINS:
        key = getattr(d, "name", None) or getattr(d, "key", None) or str(d)
        index[key] = d
    return index


_DOMAIN_BY_NAME = _domain_index()


def _resolve_domain(value):
    """Accept either a domain name or an already-resolved Domain object."""
    if hasattr(value, "rules"):
        return value
    return _DOMAIN_BY_NAME[value]


def _decisive_verdicts(scn, agents) -> list:
    """Replay one scenario in MONITOR; return the verdicts on its decisive hop.

    Decisive hop = the scenario's last message, the same scoping runner.py uses. An earlier
    hop legitimately carries the record and flags on it, so tallying every hop would credit
    every agent with catching everything — the bug runner.py's docstring describes.
    """
    orch = Orchestrator(GraphStateStore(), agents=agents, policy=Policy(mode=Mode.MONITOR))
    last = scn.messages[-1]
    verdicts: list = []
    for m in scn.messages:
        d = orch.process(m)
        if m is last:
            verdicts = list(d.verdicts)
    return verdicts


def build_matrix(include_secrets: bool = False) -> dict:
    hits: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    seen: dict[str, int] = defaultdict(int)

    for scn in generate():
        domain = _resolve_domain(scn.domain)
        agents = build_agents(domain, include_secrets=include_secrets)
        seen[scn.family] += 1
        for v in _decisive_verdicts(scn, agents):
            if v.label.name in _OBJECTING:
                hits[scn.family][v.agent_name] += 1

    return {"hits": hits, "seen": seen}


def main() -> None:
    import sys
    include_secrets = "--secrets" in sys.argv

    m = build_matrix(include_secrets=include_secrets)
    hits, seen = m["hits"], m["seen"]

    width = max(len(f) for f in seen)
    header = "family".ljust(width) + "    n  " + "  ".join(
        AGENT_LABELS[a].rjust(14) for a in AGENT_ORDER)
    print(header)
    print("-" * len(header))

    for fam in sorted(seen):
        cells = []
        for a in AGENT_ORDER:
            c = hits[fam].get(a, 0)
            cells.append(("—" if c == 0 else f"{c}/{seen[fam]}").rjust(14))
        print(fam.ljust(width) + f"  {seen[fam]:>3}  " + "  ".join(cells))

    print()
    print(f"Presidio {'ON' if include_secrets else 'OFF'}. Counts are objections "
          "(FLAG/BLOCK/REDACT) at the decisive hop —")
    print("the scenario's last message, the same scoping demo_app/eval/runner.py uses.")
    print("A dash means the agent never objected in that family.")


if __name__ == "__main__":
    main()