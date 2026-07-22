"""Data layer for the Haris monitoring dashboard (Module 11).

Runs the vulnerable hospital demo through all three real security agents in ONE
orchestrator and captures, per hop, the Message + resolved Decision. This is the
"observe-only" audit feed the Streamlit dashboard renders: it never alters the
pipeline, it just records what Haris decided.

Kept free of any Streamlit import so it can be unit-tested on its own.

It replays each threat scenario hop-by-hop through `Orchestrator.process()` and
CATCHES `HarisBlocked`, so a block is recorded as an event instead of halting the
whole run — that lets the dashboard show the full picture (every hop, including the
blocked ones) in a single pass.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

from demo_app.hospital.app import (
    INTERNAL_DOCTOR, EXTERNAL_EXAMPLE, record_reader, summarizer,
)
from haris.agents.authorization import AuthorizationAgent
from haris.agents.infoflow import InformationFlowAgent
from haris.agents.secrets_pii import SecretsPIIAgent
from haris.orchestrator.orchestrator import Orchestrator
from haris.schemas.decision import HarisBlocked
from haris.schemas.message import Message
from haris.schemas.policy import Mode, Policy

# --------------------------------------------------------------------------- #
# Palette (mirrors the UI design tokens) so data + UI agree on meaning.        #
# --------------------------------------------------------------------------- #
COLOR = {
    "allow": "#35D6A4",
    "block": "#FF5C72",
    "flag": "#F5B851",
    "redact": "#B487FF",
    "sensitive": "#B487FF",
    "agent": "#5AA9FF",
    "muted": "#8B95AC",
    "external": "#FF5C72",
}
# Which final action each verdict-driving agent maps to, for "triggered by".
ACTION_COLOR = {"allow": COLOR["allow"], "log": COLOR["muted"], "flag": COLOR["flag"],
                "redact": COLOR["redact"], "block": COLOR["block"]}


@dataclass(frozen=True)
class Scenario:
    session_id: str
    label: str
    subject: str
    leak: str
    recipient: str


# The threat-model battery. patient-B on TC5 gives a second data_subject so the
# subject filter has something to do.
SCENARIOS: list[Scenario] = [
    Scenario("s-tc1", "TC1 · clean → internal", "patient-A", "clean", INTERNAL_DOCTOR),
    Scenario("s-tc2", "TC2 · verbatim → external", "patient-A", "verbatim", EXTERNAL_EXAMPLE),
    Scenario("s-tc3", "TC3 · derived → external", "patient-A", "identified", EXTERNAL_EXAMPLE),
    Scenario("s-tc5", "TC5 · derived → internal", "patient-B", "identified", INTERNAL_DOCTOR),
]

AGENT_LABELS = {
    "secrets_pii": "Secrets & PII Scanner",
    "infoflow": "Cross-Agent Info-Flow",
    "authorization": "Authorization Monitor",
}


def _verdict_dict(v) -> dict[str, Any]:
    return {
        "agent": v.agent_name,
        "agent_label": AGENT_LABELS.get(v.agent_name, v.agent_name),
        "label": v.label.value,
        "score": round(float(v.score), 3),
        "reason": v.reason,
        "redacts": v.redacted_content is not None,
    }


def _triggered_by(action: str, verdicts: list[dict]) -> str:
    """Human label for which check drove the final action."""
    if action == "block":
        who = [v["agent_label"] for v in verdicts if v["label"] == "block"]
    elif action == "redact":
        who = [v["agent_label"] for v in verdicts if v["redacts"]]
    elif action == "flag":
        who = [v["agent_label"] for v in verdicts if v["label"] == "flag"]
    else:
        who = []
    return ", ".join(dict.fromkeys(who)) or "—"


def _process_capture(orch: Orchestrator, msg: Message, scenario: Scenario,
                     hop: int) -> dict[str, Any]:
    """Run one hop through the orchestrator, capturing the Decision even on block."""
    t0 = time.perf_counter()
    try:
        decision = orch.process(msg)
    except HarisBlocked as exc:      # enforce-mode block: record it, don't halt
        decision = exc.decision
    latency_ms = (time.perf_counter() - t0) * 1000.0

    verdicts = [_verdict_dict(v) for v in decision.verdicts]
    action = decision.action.value
    md = msg.metadata or {}
    return {
        "session": scenario.label,
        "session_id": scenario.session_id,
        "hop": hop,
        "sender": msg.sender,
        "receiver": msg.receiver,
        "data_type": md.get("data_type"),
        "data_subject": md.get("data_subject"),
        "recipient": md.get("recipient"),
        "action": action,
        "enforced": bool(decision.enforced),
        "verdicts": verdicts,
        "triggered_by": _triggered_by(action, verdicts),
        "reason": decision.reason,
        "content": msg.content,
        "final_content": decision.final_content if action == "redact" else msg.content,
        "redacted": action == "redact",
        "timestamp": msg.timestamp.strftime("%H:%M:%S.") + f"{msg.timestamp.microsecond // 1000:03d}",
        "latency_ms": round(latency_ms, 1),
    }


def _build_agents(include_secrets: bool) -> list:
    # Single source of truth: the canonical hospital line-up lives in the pipeline
    # module, so the dashboard and the live `run_secured` pipeline can never drift.
    from demo_app.hospital.haris_pipeline import build_hospital_agents
    return build_hospital_agents(include_secrets)


def presidio_available() -> bool:
    try:
        SecretsPIIAgent().pii.analyze("warm up")
        return True
    except Exception:
        return False


def run_battery(mode: Mode = Mode.ENFORCE, include_secrets: bool = True) -> list[dict]:
    """Replay every scenario through one Orchestrator; return one record per hop."""
    from haris.state.graph_store import GraphStateStore

    store = GraphStateStore()
    orch = Orchestrator(store, agents=_build_agents(include_secrets),
                        policy=Policy(mode=mode))
    records: list[dict] = []
    for sc in SCENARIOS:
        state: dict[str, Any] = {"subject": sc.subject, "leak": sc.leak,
                                 "recipient": sc.recipient}
        state.update(record_reader(state))   # -> state["record"] (PHI)
        m1 = Message(session_id=sc.session_id, sender="record_reader",
                     receiver="summarizer", content=state["record"],
                     metadata={"data_type": "PHI", "data_subject": sc.subject})
        records.append(_process_capture(orch, m1, sc, hop=1))

        state.update(summarizer(state))      # -> state["summary"]
        m2 = Message(session_id=sc.session_id, sender="summarizer", receiver="emailer",
                     content=state["summary"],
                     metadata={"data_type": "summary", "recipient": sc.recipient,
                               "data_subject": sc.subject})
        records.append(_process_capture(orch, m2, sc, hop=2))
    return records


def compute_kpis(records: list[dict]) -> dict[str, Any]:
    actions = [r["action"] for r in records]
    flagged = sum(1 for r in records
                  if any(v["agent"] == "secrets_pii" and v["label"] == "flag"
                         for v in r["verdicts"]))
    agents = {r["sender"] for r in records} | {r["receiver"] for r in records}
    subjects = {r["data_subject"] for r in records if r["data_subject"]}
    latencies = sorted(r["latency_ms"] for r in records)
    p95 = latencies[min(len(latencies) - 1, int(0.95 * len(latencies)))] if latencies else 0.0
    return {
        "inspected": len(records),
        "blocked": actions.count("block"),
        "redacted": actions.count("redact"),
        "allowed": actions.count("allow"),
        "flagged": flagged,
        "agents": len(agents),
        "subjects_touching_sensitive": len(subjects),
        "sessions": len({r["session_id"] for r in records}),
        "latency_p95_ms": p95,
    }


def compute_modules(records: list[dict]) -> list[dict]:
    def count(agent: str, label: Optional[str] = None) -> int:
        return sum(1 for r in records for v in r["verdicts"]
                   if v["agent"] == agent and (label is None or v["label"] == label))

    infoflow_blocked = sum(1 for r in records if r["action"] == "block")
    return [
        {"name": "Secrets & PII Scanner", "status": "ACTIVE", "accent": "flag",
         "num": count("secrets_pii", "flag"), "unit": "caught this run"},
        {"name": "Cross-Agent Info-Flow", "status": "ACTIVE", "accent": "block",
         "num": infoflow_blocked, "unit": "leaks blocked"},
        {"name": "Authorization Monitor", "status": "ACTIVE", "accent": "allow",
         "num": count("authorization", "block"), "unit": "egress violations"},
        {"name": "Injection · Semantic", "status": "PLANNED", "accent": "muted",
         "num": None, "unit": "pluggable detectors · roadmap"},
    ]


def build_graph(records: list[dict]) -> dict[str, list[dict]]:
    """Aggregate interaction graph: agents + recipients as nodes, hops as edges.

    Edge color = the most severe decision seen on that route; `sensitive` marks
    edges carrying PHI-derived data (rendered dashed by the UI)."""
    severity = {"allow": 0, "log": 1, "flag": 2, "redact": 3, "block": 4}

    nodes: dict[str, dict] = {}
    def add_node(nid, label, role, kind):
        nodes.setdefault(nid, {"id": nid, "label": label, "role": role, "kind": kind})

    edges: dict[tuple, dict] = {}
    def add_edge(src, dst, action, data_type, subject, sensitive, extra_label=""):
        key = (src, dst)
        e = edges.get(key)
        if e is None or severity[action] > severity[e["action"]]:
            edges[key] = {"source": src, "target": dst, "action": action,
                          "data_type": data_type, "data_subject": subject,
                          "sensitive": sensitive, "label": extra_label}

    roles = {"record_reader": ("Records", "patient DB", "source"),
             "summarizer": ("Summarizer", "llm", "agent"),
             "emailer": ("Emailer", "egress", "sink")}
    for r in records:
        for nid in (r["sender"], r["receiver"]):
            label, role, kind = roles.get(nid, (nid, "agent", "agent"))
            add_node(nid, label, role, kind)
        sensitive = r["data_type"] == "PHI" or any(
            v["agent"] == "infoflow" and v["label"] == "flag" for v in r["verdicts"])
        add_edge(r["sender"], r["receiver"], r["action"], r["data_type"],
                 r["data_subject"], sensitive)
        # illustrative egress edge: emailer -> the actual recipient, colored by the
        # summary hop's decision (that hop is where the recipient is authorized).
        if r["receiver"] == "emailer" and r["recipient"]:
            rcpt = r["recipient"]
            external = not rcpt.endswith("@hospital.internal")
            add_node(rcpt, rcpt, "external" if external else "internal",
                     "external" if external else "internal")
            add_edge("emailer", rcpt, r["action"], r["data_type"],
                     r["data_subject"], sensitive)
    return {"nodes": list(nodes.values()), "edges": list(edges.values())}


def get_dashboard(mode: Mode = Mode.ENFORCE, include_secrets: bool = True) -> dict[str, Any]:
    """Everything the dashboard needs, in one call."""
    records = run_battery(mode=mode, include_secrets=include_secrets)
    return {
        "mode": mode.value,
        "records": records,
        "kpis": compute_kpis(records),
        "modules": compute_modules(records),
        "graph": build_graph(records),
        "sessions": [sc.label for sc in SCENARIOS],
        "subjects": sorted({r["data_subject"] for r in records if r["data_subject"]}),
    }