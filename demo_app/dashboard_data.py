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

from dataclasses import dataclass, field
from typing import Any, Optional

from demo_app.hospital.app import (
    INTERNAL_DOCTOR, EXTERNAL_EXAMPLE, record_reader, summarizer,
)
from haris.agents.authorization import AuthorizationAgent
from haris.agents.infoflow import InformationFlowAgent
from haris.agents.secrets_pii import SecretsPIIAgent
from haris.audit import AuditLog, AuditRecord
from haris.orchestrator.orchestrator import Orchestrator
from haris.schemas.decision import HarisBlocked
from haris.schemas.message import Message
from haris.schemas.policy import Mode, Policy

# Recipients not under this domain are treated as outside the trust boundary in the
# interaction graph. Derived from the demo's internal address; a real deployment sets its
# own. (The dashboard is otherwise app-agnostic — it renders whatever the audit log holds.)
INTERNAL_DOMAIN = "@" + INTERNAL_DOCTOR.split("@", 1)[-1]  # "@hospital.internal"

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
# subject filter has something to do; TC4 (leak="mixed-subject") stages the
# data-subject case — a second patient's record entering the first patient's session.
SCENARIOS: list[Scenario] = [
    Scenario("s-tc1", "TC1 · clean → internal", "patient-A", "clean", INTERNAL_DOCTOR),
    Scenario("s-tc2", "TC2 · verbatim → external", "patient-A", "verbatim", EXTERNAL_EXAMPLE),
    Scenario("s-tc3", "TC3 · derived → external", "patient-A", "identified", EXTERNAL_EXAMPLE),
    Scenario("s-tc4", "TC4 · patient-B into patient-A's session", "patient-A", "mixed-subject", INTERNAL_DOCTOR),
    Scenario("s-tc5", "TC5 · derived → internal", "patient-B", "identified", INTERNAL_DOCTOR),
]

AGENT_LABELS = {
    "secrets_pii": "Secrets & PII Scanner",
    "infoflow": "Cross-Agent Info-Flow",
    "authorization": "Authorization Monitor",
    "subject_binding": "Data-Subject Authorization",
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


def _safe_process(orch: Orchestrator, msg: Message) -> None:
    """Push one hop through Haris. The decision (including a block) is written to the
    orchestrator's audit log inside process(); we swallow the enforce-mode raise so the
    battery keeps running and the block is still on record."""
    try:
        orch.process(msg)
    except HarisBlocked:
        pass


def _fmt_ts(iso: str) -> str:
    # "2026-07-22T14:23:01.123456" -> "14:23:01.123"
    t = iso.split("T")[-1]
    return t[:12] if "." in t else t[:8]


def _display_records(audit: AuditLog) -> list[dict[str, Any]]:
    """Turn the app-agnostic audit log into the display rows the UI renders. The audit
    log is the single source of truth; this only adds presentation (friendly session
    label, per-agent display names, and which check drove the action)."""
    label_by_sid = {sc.session_id: sc.label for sc in SCENARIOS}
    hop_counter: dict[str, int] = {}
    rows: list[dict[str, Any]] = []
    for rec in audit.records():
        hop_counter[rec.session_id] = hop_counter.get(rec.session_id, 0) + 1
        verdicts = [{**v, "agent_label": AGENT_LABELS.get(v["agent"], v["agent"])}
                    for v in rec.verdicts]
        rows.append({
            "session": label_by_sid.get(rec.session_id, rec.session_id),
            "session_id": rec.session_id,
            "hop": hop_counter[rec.session_id],
            "sender": rec.sender,
            "receiver": rec.receiver,
            "data_type": rec.data_type,
            "data_subject": rec.data_subject,
            "recipient": rec.recipient,
            "action": rec.action,
            "enforced": rec.enforced,
            "verdicts": verdicts,
            "triggered_by": _triggered_by(rec.action, verdicts),
            "reason": rec.reason,
            "final_content": rec.delivered_content or "",
            "content_sha256": rec.content_sha256,
            "redacted": rec.action == "redact",
            "timestamp": _fmt_ts(rec.timestamp),
            "latency_ms": round(rec.latency_ms, 1),
        })
    return rows


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


def run_battery(mode: Mode = Mode.ENFORCE, include_secrets: bool = True) -> AuditLog:
    """Replay every scenario through one Orchestrator wired to an AuditLog, and return
    that log. Haris writes the log; the dashboard reads it — so the dashboard is a
    consumer of Haris's audit trail, not of the hospital demo. Any app that runs through
    an Orchestrator with an AuditLog produces the same, renderable, log."""
    from haris.state.graph_store import GraphStateStore

    audit = AuditLog()
    orch = Orchestrator(GraphStateStore(), agents=_build_agents(include_secrets),
                        policy=Policy(mode=mode), audit_log=audit)
    for sc in SCENARIOS:
        if sc.leak == "mixed-subject":
            _emit_mixed_subject(orch, sc)
            continue
        state: dict[str, Any] = {"subject": sc.subject, "leak": sc.leak,
                                 "recipient": sc.recipient}
        state.update(record_reader(state))   # -> state["record"] (PHI)
        _safe_process(orch, Message(
            session_id=sc.session_id, sender="record_reader", receiver="summarizer",
            content=state["record"],
            metadata={"data_type": "PHI", "data_subject": sc.subject}))

        state.update(summarizer(state))      # -> state["summary"]
        _safe_process(orch, Message(
            session_id=sc.session_id, sender="summarizer", receiver="emailer",
            content=state["summary"],
            metadata={"data_type": "summary", "recipient": sc.recipient,
                      "data_subject": sc.subject}))
    return audit


def _emit_mixed_subject(orch: Orchestrator, sc: Scenario) -> None:
    """TC4 — data-subject authorization: the session is about `sc.subject`; a SECOND
    patient's record then tries to enter the same session and is blocked."""
    other = "patient-B" if sc.subject == "patient-A" else "patient-A"
    _safe_process(orch, Message(
        session_id=sc.session_id, sender="record_reader", receiver="summarizer",
        content=record_reader({"subject": sc.subject})["record"],
        metadata={"data_type": "PHI", "data_subject": sc.subject}))     # binds the session
    _safe_process(orch, Message(
        session_id=sc.session_id, sender="record_reader", receiver="summarizer",
        content=record_reader({"subject": other})["record"],
        metadata={"data_type": "PHI", "data_subject": other}))          # blocked: wrong subject


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

    return [
        {"name": "Secrets & PII Scanner", "status": "ACTIVE", "accent": "flag",
         "num": count("secrets_pii", "flag"), "unit": "PII/secrets flagged"},
        {"name": "Cross-Agent Info-Flow", "status": "ACTIVE", "accent": "flag",
         "num": count("infoflow", "flag"), "unit": "derived leaks caught"},
        {"name": "Authorization Monitor", "status": "ACTIVE", "accent": "block",
         "num": count("authorization", "block"), "unit": "egress blocks"},
        {"name": "Data-Subject Authorization", "status": "ACTIVE", "accent": "block",
         "num": count("subject_binding", "block"), "unit": "cross-subject blocks"},
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

    # Generic, app-agnostic roles: a node that only sends is a source, only receives is a
    # sink, and one that does both is an agent. No app-specific names are hardcoded, so
    # this renders any protected multi-agent system, not just the hospital demo.
    senders = {r["sender"] for r in records}
    receivers = {r["receiver"] for r in records}
    def role_of(nid: str) -> str:
        sends, recvs = nid in senders, nid in receivers
        if sends and not recvs:
            return "source"
        if recvs and not sends:
            return "sink"
        return "agent"

    for r in records:
        for nid in (r["sender"], r["receiver"]):
            add_node(nid, nid, role_of(nid), role_of(nid))
        sensitive = r["data_type"] == "PHI" or any(
            v["agent"] == "infoflow" and v["label"] == "flag" for v in r["verdicts"])
        add_edge(r["sender"], r["receiver"], r["action"], r["data_type"],
                 r["data_subject"], sensitive)
        # Any hop that carries a recipient gets an egress edge to that endpoint, colored by
        # the hop's decision. External vs internal is by the configured trust-boundary domain.
        if r["recipient"]:
            rcpt = r["recipient"]
            external = not str(rcpt).endswith(INTERNAL_DOMAIN)
            kind = "external" if external else "internal"
            add_node(rcpt, rcpt, kind, kind)
            add_edge(r["receiver"], rcpt, r["action"], r["data_type"],
                     r["data_subject"], sensitive)
    return {"nodes": list(nodes.values()), "edges": list(edges.values())}


def get_dashboard(mode: Mode = Mode.ENFORCE, include_secrets: bool = True) -> dict[str, Any]:
    """Everything the dashboard needs, in one call. Reads from Haris's audit log."""
    audit = run_battery(mode=mode, include_secrets=include_secrets)
    records = _display_records(audit)
    return {
        "mode": mode.value,
        "records": records,
        "kpis": compute_kpis(records),
        "modules": compute_modules(records),
        "graph": build_graph(records),
        "sessions": [sc.label for sc in SCENARIOS],
        "subjects": sorted({r["data_subject"] for r in records if r["data_subject"]}),
    }