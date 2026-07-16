"""Haris — Security Monitoring Dashboard (Module 11).

A Streamlit app that renders the live hospital demo through all three security agents,
styled to match the team's UI design: interaction graph, live inspection stream,
security-check modules, message inspector, and a filterable audit log.

Run:
    pip install -r requirements.txt
    python -m spacy download en_core_web_sm     # for the Secrets & PII (Presidio) agent
    streamlit run demo_app/dashboard.py

Read-only / observe-only: it replays the demo and renders Haris's decisions; it never
alters the pipeline.
"""
from __future__ import annotations

import html
import os
import sys

# When launched via `streamlit run demo_app/dashboard.py`, Streamlit puts this file's
# own folder (demo_app/) on sys.path, not the project root — so `demo_app` and `haris`
# aren't importable. Add the repo root (the parent of this file's folder) so they are.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st

from demo_app.dashboard_data import (
    COLOR, ACTION_COLOR, get_dashboard, presidio_available,
    compute_kpis, compute_modules, build_graph,
)
from haris.schemas.policy import Mode

st.set_page_config(page_title="Haris · Security Monitoring", page_icon="🛡️",
                   layout="wide", initial_sidebar_state="expanded")

# --------------------------------------------------------------------------- #
# Theme (mirrors the design tokens from the UI mockup)                         #
# --------------------------------------------------------------------------- #
CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap');
:root{
  --bg:#0A0E17; --surface-1:#0F1523; --surface-2:#141C2E; --surface-3:#1B2438;
  --hairline:#26314A; --hairline-soft:#1B2436;
  --text:#E7ECF6; --text-mut:#8B95AC; --text-dim:#5C6580;
  --allow:#35D6A4; --allow-dim:#14342A; --block:#FF5C72; --block-dim:#351520;
  --flag:#F5B851; --flag-dim:#33290F; --sensitive:#B487FF; --sensitive-dim:#241834;
  --agent:#5AA9FF;
  --f-display:"Space Grotesk",sans-serif; --f-ui:"IBM Plex Sans",sans-serif; --f-mono:"IBM Plex Mono",monospace;
}
.stApp{ background:
  radial-gradient(900px 600px at 78% -8%, rgba(90,169,255,.06), transparent 60%),
  radial-gradient(700px 500px at 10% 110%, rgba(180,135,255,.05), transparent 55%),
  var(--bg); color:var(--text); font-family:var(--f-ui); }
/* keep the header (it holds the reopen-sidebar arrow) but make it blend in */
#MainMenu, footer{ visibility:hidden; }
header[data-testid="stHeader"]{ background:transparent; }
[data-testid="stSidebarCollapsedControl"]{ visibility:visible !important; opacity:1 !important; }
.block-container{ padding:1.1rem 1.6rem 3rem; max-width:100%; }
section[data-testid="stSidebar"]{ background:linear-gradient(180deg,var(--surface-1),rgba(15,21,35,.5)); border-right:1px solid var(--hairline-soft); }
section[data-testid="stSidebar"] *{ color:var(--text); }
h1,h2,h3{ font-family:var(--f-display); }
.brand{ display:flex; align-items:center; gap:12px; padding:2px 2px 14px; }
.brand .mark{ width:40px;height:40px;border-radius:11px;flex:none;display:grid;place-items:center;
  background:linear-gradient(150deg,#12b184,#0c7f9c); box-shadow:0 6px 18px -6px rgba(53,214,164,.6); font-size:20px;}
.brand .ar{ font-family:var(--f-display); font-size:20px; font-weight:700; line-height:1; }
.brand .sub{ font-size:10px; color:var(--text-mut); letter-spacing:.14em; text-transform:uppercase; margin-top:3px; }
.adapter{ display:flex; align-items:center; gap:9px; font-size:12px; color:var(--text-mut); padding:4px 2px; }
.adapter .dot{ width:7px;height:7px;border-radius:50%;background:var(--allow);box-shadow:0 0 8px var(--allow); }
.adapter .dot.off{ background:var(--text-dim); box-shadow:none; }
.topbar{ display:flex; align-items:center; gap:14px; padding:2px 2px 12px; flex-wrap:wrap; }
.topbar h1{ font-size:19px; font-weight:600; margin:0; }
.topbar h1 .muted{ color:var(--text-dim); font-weight:400; }
.pill{ font-family:var(--f-mono); font-size:12px; color:var(--text-mut); background:var(--surface-2);
  border:1px solid var(--hairline); padding:5px 11px; border-radius:20px; }
.pill.env{ color:var(--agent); background:rgba(90,169,255,.1); border-color:rgba(90,169,255,.2); border-radius:8px; }
.pill.live{ color:var(--allow); background:var(--allow-dim); border-color:rgba(53,214,164,.25); font-weight:600; letter-spacing:.06em; }
.pill.live .pulse{ display:inline-block; width:8px;height:8px;border-radius:50%;background:var(--allow); margin-right:6px; box-shadow:0 0 6px var(--allow);}
.kpis{ display:grid; grid-template-columns:repeat(6,1fr); gap:14px; margin-bottom:6px; }
.kpi{ background:var(--surface-1); border:1px solid var(--hairline-soft); border-radius:12px; padding:14px 16px; }
.kpi .k-label{ font-size:10.5px; letter-spacing:.11em; text-transform:uppercase; color:var(--text-mut); }
.kpi .k-val{ font-family:var(--f-display); font-size:30px; font-weight:600; line-height:1.1; margin-top:8px; }
.kpi .k-delta{ font-family:var(--f-mono); font-size:11px; margin-top:2px; color:var(--text-dim); }
.kpi.block .k-val{ color:var(--block); } .kpi.flag .k-val{ color:var(--flag); }
.panel-head{ display:flex; align-items:center; gap:10px; margin:6px 0 4px; }
.panel-head h2{ font-size:15px; font-weight:600; margin:0; }
.panel-head .hint{ font-size:12px; color:var(--text-dim); }
.mods{ display:grid; grid-template-columns:1fr 1fr; gap:12px; }
.mod{ background:var(--surface-2); border:1px solid var(--hairline-soft); border-radius:10px; padding:13px 14px; }
.mod .name{ font-weight:600; font-size:13px; }
.mod .st{ font-family:var(--f-mono); font-size:10px; padding:2px 7px; border-radius:20px; float:right; }
.st-on{ color:var(--allow); background:var(--allow-dim); } .st-plan{ color:var(--text-mut); background:var(--surface-3); }
.mod .num{ font-family:var(--f-display); font-size:22px; font-weight:600; margin-top:10px; }
.mod .num small{ font-family:var(--f-ui); font-size:11px; color:var(--text-mut); font-weight:400; margin-left:5px; }
.banner{ display:flex; align-items:center; gap:11px; padding:12px 14px; border-radius:10px; }
.banner .vt{ font-family:var(--f-display); font-weight:600; font-size:14px; }
.banner .vs{ font-size:11.5px; color:var(--text-mut); margin-top:1px; }
.kv{ display:grid; grid-template-columns:110px 1fr; gap:6px 10px; font-size:12.5px; margin-top:10px; }
.kv .k{ color:var(--text-dim); font-size:11px; } .kv .v{ font-family:var(--f-mono); color:var(--text); }
.kv .v .pii{ color:var(--sensitive); }
.label-dim{ font-size:11px; color:var(--text-dim); letter-spacing:.04em; margin:12px 0 6px; }
.payload{ font-family:var(--f-mono); font-size:11.5px; background:var(--bg); border:1px solid var(--hairline);
  border-radius:8px; padding:11px 12px; line-height:1.6; color:var(--text-mut); white-space:pre-wrap; word-break:break-word; }
.payload .redact{ background:var(--block-dim); color:var(--block); padding:0 5px; border-radius:4px; }
.lineage{ font-size:12px; color:var(--text-mut); font-family:var(--f-mono); }
.lineage .hop{ color:var(--sensitive); } .lineage .x{ color:var(--block); font-weight:700; }
div[data-testid="stVerticalBlock"] .stButton>button{ width:100%; text-align:left; font-family:var(--f-mono);
  font-size:12.5px; background:var(--surface-1); border:1px solid var(--hairline-soft); color:var(--text);
  border-radius:10px; padding:9px 12px; }
div[data-testid="stVerticalBlock"] .stButton>button:hover{ background:var(--surface-2); border-color:var(--hairline); }
.legend{ display:flex; flex-wrap:wrap; gap:16px; padding:8px 2px 0; font-size:11.5px; color:var(--text-mut); }
.legend .item{ display:flex; align-items:center; gap:7px; }
.legend .sw{ width:16px; height:3px; border-radius:2px; display:inline-block; }
.legend .sw.dash{ background:repeating-linear-gradient(90deg,var(--sensitive) 0 5px, transparent 5px 9px); }
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)

VERDICT_DOT = {"allow": "🟢", "log": "⚪", "flag": "🟡", "redact": "🟣", "block": "🔴"}


# --------------------------------------------------------------------------- #
# Cached heavy calls (Presidio init is the slow part — do it at most once)     #
# --------------------------------------------------------------------------- #
@st.cache_data(show_spinner=False)
def _presidio_ok() -> bool:
    return presidio_available()


@st.cache_data(show_spinner="Running the hospital demo through Haris (first load boots Presidio)…")
def _load(mode_value: str, include_secrets: bool):
    return get_dashboard(Mode(mode_value), include_secrets=include_secrets)


# --------------------------------------------------------------------------- #
# Sidebar                                                                      #
# --------------------------------------------------------------------------- #
def _sidebar():
    st.sidebar.markdown(
        '<div class="brand"><div class="mark">🛡️</div>'
        '<div><div class="ar">حارس <span style="font-size:14px">Haris</span></div>'
        '<div class="sub">Agent Security</div></div></div>', unsafe_allow_html=True)

    st.sidebar.caption("MONITOR")
    page = st.sidebar.radio("Section", ["Overview", "Agent Graph", "Live Traffic",
                                        "Data Lineage", "Audit Log"],
                            label_visibility="collapsed")
    st.sidebar.markdown("---")
    st.sidebar.caption("CONTROL")
    mode_label = st.sidebar.radio("Enforcement mode", ["Enforce", "Monitor"],
                                  help="Enforce blocks/redacts; Monitor logs & flags only.")
    include_secrets = st.sidebar.checkbox("Secrets & PII agent (Presidio)", value=True,
                                          help="Uncheck to run without Presidio/spaCy.")
    st.sidebar.markdown("---")
    st.sidebar.markdown(
        '<div class="adapter"><span class="dot"></span> LangGraph adapter · connected</div>'
        '<div class="adapter"><span class="dot off"></span> CrewAI adapter · available</div>',
        unsafe_allow_html=True)
    return page, (Mode.ENFORCE if mode_label == "Enforce" else Mode.MONITOR), include_secrets


# --------------------------------------------------------------------------- #
# Sections                                                                     #
# --------------------------------------------------------------------------- #
def _topbar(mode, scenario):
    st.markdown(
        '<div class="topbar"><h1>Haris <span class="muted">/ clinical-assistant · hospital-demo</span></h1>'
        f'<span class="pill">{html.escape(scenario)}</span>'
        '<span class="pill env">langgraph · haris</span>'
        f'<span class="pill">mode · {mode.value}</span>'
        '<span class="pill live"><span class="pulse"></span>LIVE</span></div>',
        unsafe_allow_html=True)


def _kpis(k):
    cells = [
        ("Messages inspected", f"{k['inspected']}", "hops this run", ""),
        ("Blocked", f"{k['blocked']}", "info-flow / egress", "block"),
        ("Flagged", f"{k['flagged']}", "PII / secrets seen", "flag"),
        ("Redacted", f"{k['redacted']}", "sanitized in place", ""),
        ("Sessions", f"{k['sessions']}", "live trajectories", ""),
        ("Added latency", f"{k['latency_p95_ms']:.0f}<span style='font-size:15px;color:var(--text-mut)'>ms</span>",
         "p95 per message", ""),
    ]
    html_cells = "".join(
        f'<div class="kpi {cls}"><div class="k-label">{lbl}</div>'
        f'<div class="k-val">{val}</div><div class="k-delta">{delta}</div></div>'
        for lbl, val, delta, cls in cells)
    st.markdown(f'<div class="kpis">{html_cells}</div>', unsafe_allow_html=True)


def _graph(graph):
    try:
        from streamlit_agraph import agraph, Node, Edge, Config
    except Exception:
        st.error("Install the graph renderer:  pip install streamlit-agraph")
        return
    node_color = {"source": COLOR["flag"], "agent": COLOR["agent"], "sink": COLOR["muted"],
                  "external": COLOR["external"], "internal": COLOR["allow"]}
    nodes = [Node(id=n["id"], label=n["label"],
                  size=24 if n["kind"] in ("agent", "source") else 18,
                  color=node_color.get(n["kind"], COLOR["agent"]),
                  font={"color": "#E7ECF6", "face": "IBM Plex Sans"})
             for n in graph["nodes"]]
    edges = [Edge(source=e["source"], target=e["target"],
                  color=ACTION_COLOR.get(e["action"], COLOR["muted"]),
                  label=e["action"], dashes=bool(e["sensitive"]),
                  width=3 if e["action"] == "block" else 2)
             for e in graph["edges"]]
    # physics OFF + hierarchical => fast, deterministic layout (no wandering nodes)
    cfg = Config(width=760, height=430, directed=True, physics=False, hierarchical=True,
                 nodeHighlightBehavior=True, highlightColor=COLOR["agent"],
                 collapsible=False, backgroundColor="#0F1523")
    agraph(nodes=nodes, edges=edges, config=cfg)
    st.markdown(
        '<div class="legend">'
        '<div class="item"><span class="sw" style="background:var(--allow)"></span>Allowed</div>'
        '<div class="item"><span class="sw" style="background:var(--flag)"></span>Flagged</div>'
        '<div class="item"><span class="sw" style="background:var(--sensitive)"></span>Redacted</div>'
        '<div class="item"><span class="sw" style="background:var(--block)"></span>Blocked</div>'
        '<div class="item"><span class="sw dash"></span>Carries sensitive data</div></div>',
        unsafe_allow_html=True)


def _highlight_payload(text: str) -> str:
    esc = html.escape(text)
    for tok in ("[REDACTED]", "<PERSON>", "<DATE_TIME>", "<PII>", "<SECRET>", "<LOCATION>"):
        esc = esc.replace(html.escape(tok), f'<span class="redact">{html.escape(tok)}</span>')
    return esc


def _stream(records):
    st.markdown('<div class="panel-head"><h2>Live inspection stream</h2>'
                '<span class="hint">— click a hop to inspect</span></div>',
                unsafe_allow_html=True)
    for i, r in enumerate(records):
        dot = VERDICT_DOT.get(r["action"], "⚪")
        label = f"{dot}  {r['sender']} → {r['receiver']}   ·   {r['action'].upper()}   ·   {r['timestamp']}"
        if st.button(label, key=f"row-{i}", use_container_width=True):
            st.session_state["sel"] = i


def _inspector(records):
    if not records:
        st.info("No hops for this scenario.")
        return
    sel = st.session_state.get("sel", 0)
    sel = max(0, min(sel, len(records) - 1))
    r = records[sel]
    colmap = {"allow": ("--allow-dim", "--allow", "Allowed"),
              "flag": ("--flag-dim", "--flag", "Flagged & tracked"),
              "redact": ("--sensitive-dim", "--sensitive", "Redacted"),
              "block": ("--block-dim", "--block", "Blocked")}
    bg, fg, title = colmap.get(r["action"], ("--surface-2", "--text", r["action"]))
    st.markdown('<div class="panel-head"><h2>Message inspector</h2>'
                f'<span class="hint">— {r["session"]} · hop {r["hop"]}</span></div>',
                unsafe_allow_html=True)
    label_color = {"pass": "--allow", "flag": "--flag", "block": "--block"}
    verdict_lines = "".join(
        f'<div class="kv"><span class="k">{v["agent_label"]}</span>'
        f'<span class="v" style="color:var({label_color.get(v["label"], "--text")})">'
        f'{v["label"].upper()} · {html.escape(v["reason"][:90])}</span></div>'
        for v in r["verdicts"])
    lineage = ('<span class="hop">record_reader</span> → <span class="hop">summarizer</span>'
               ' → <span class="hop">emailer</span>')
    if r["recipient"]:
        lineage += f' → <span class="hop">{html.escape(r["recipient"])}</span>'
    if r["action"] == "block":
        lineage += ' <span class="x">✕ blocked</span>'
    st.markdown(
        f'<div class="banner" style="background:var({bg});border:1px solid var({fg})">'
        f'<div><div class="vt" style="color:var({fg})">{title}</div>'
        f'<div class="vs">{html.escape(r["triggered_by"])}</div></div></div>'
        f'<div class="kv"><span class="k">Route</span><span class="v">{r["sender"]} → {r["receiver"]}</span>'
        f'<span class="k">Data type</span><span class="v"><span class="pii">{r["data_type"]}</span></span>'
        f'<span class="k">Data subject</span><span class="v">{r["data_subject"] or "—"}</span>'
        f'<span class="k">Recipient</span><span class="v">{html.escape(str(r["recipient"] or "—"))}</span>'
        f'<span class="k">Mode</span><span class="v">{"enforce" if r["enforced"] else "monitor"}</span></div>'
        f'<div class="label-dim">CONTRIBUTING VERDICTS</div>{verdict_lines}'
        f'<div class="label-dim">DELIVERED PAYLOAD</div>'
        f'<div class="payload">{_highlight_payload(r["final_content"])}</div>'
        f'<div class="label-dim">DATA LINEAGE</div><div class="lineage">{lineage}</div>',
        unsafe_allow_html=True)


def _modules(modules):
    st.markdown('<div class="panel-head"><h2>Security checks</h2>'
                '<span class="hint">— run on every intercepted message</span></div>',
                unsafe_allow_html=True)
    cards = ""
    for m in modules:
        stcls = "st-on" if m["status"] == "ACTIVE" else "st-plan"
        numcolor = {"block": "var(--block)", "flag": "var(--flag)", "allow": "var(--text)",
                    "muted": "var(--text-mut)"}.get(m["accent"], "var(--text)")
        num = (f'{m["num"]} <small>{m["unit"]}</small>' if m["num"] is not None
               else f'<small style="margin-left:0">{m["unit"]}</small>')
        cards += (f'<div class="mod"><span class="st {stcls}">{m["status"]}</span>'
                  f'<div class="name">{m["name"]}</div>'
                  f'<div class="num" style="color:{numcolor}">{num}</div></div>')
    st.markdown(f'<div class="mods">{cards}</div>', unsafe_allow_html=True)


def _audit_log(records, sessions, subjects):
    import pandas as pd
    st.markdown('<div class="panel-head"><h2>Audit log</h2>'
                '<span class="hint">— every intercepted hop</span></div>', unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)
    f_sess = c1.multiselect("Session", sessions, default=sessions)
    f_dec = c2.multiselect("Decision", ["allow", "flag", "redact", "block"],
                           default=["allow", "flag", "redact", "block"])
    f_subj = c3.multiselect("Data subject", subjects, default=subjects)
    rows = [{
        "session": r["session"], "hop": r["hop"], "sender": r["sender"],
        "receiver": r["receiver"], "data_type": r["data_type"],
        "data_subject": r["data_subject"], "recipient": r["recipient"],
        "secrets_pii": next((v["label"] for v in r["verdicts"] if v["agent"] == "secrets_pii"), "—"),
        "authorization": next((v["label"] for v in r["verdicts"] if v["agent"] == "authorization"), "—"),
        "infoflow": next((v["label"] for v in r["verdicts"] if v["agent"] == "infoflow"), "—"),
        "decision": r["action"], "mode": "enforce" if r["enforced"] else "monitor",
    } for r in records
        if r["session"] in f_sess and r["action"] in f_dec
        and (r["data_subject"] in f_subj or r["data_subject"] is None)]
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


# --------------------------------------------------------------------------- #
# App                                                                          #
# --------------------------------------------------------------------------- #
def main():
    page, mode, include_secrets = _sidebar()

    if include_secrets and not _presidio_ok():
        st.warning("Presidio/spaCy not available — running without the Secrets & PII agent. "
                   "Install with `pip install -r requirements.txt` and "
                   "`python -m spacy download en_core_web_sm`.")
        include_secrets = False

    data = _load(mode.value, include_secrets)

    # Scenario filter — this is what makes every panel dynamic.
    scenario = st.selectbox("Scenario", ["All scenarios"] + data["sessions"], key="scenario")
    if scenario == "All scenarios":
        recs, sessions = data["records"], data["sessions"]
    else:
        recs = [r for r in data["records"] if r["session"] == scenario]
        sessions = [scenario]
    kpis = compute_kpis(recs)
    modules = compute_modules(recs)
    graph = build_graph(recs)
    subjects = sorted({r["data_subject"] for r in recs if r["data_subject"]})
    st.session_state.setdefault("sel", 0)

    _topbar(mode, scenario)

    if page == "Overview":
        _kpis(kpis)
        left, right = st.columns([1.55, 1], gap="large")
        with left:
            st.markdown('<div class="panel-head"><h2>Agent interaction graph</h2>'
                        '<span class="hint">— sensitive data traced across hops</span></div>',
                        unsafe_allow_html=True)
            _graph(graph)
        with right:
            _stream(recs)
        st.markdown("<br>", unsafe_allow_html=True)
        b1, b2 = st.columns([1.4, 1], gap="large")
        with b1:
            _modules(modules)
        with b2:
            _inspector(recs)
        st.markdown("<br>", unsafe_allow_html=True)
        _audit_log(recs, sessions, subjects)

    elif page == "Agent Graph":
        st.markdown('<div class="panel-head"><h2>Agent interaction graph</h2>'
                    '<span class="hint">— full trajectory</span></div>', unsafe_allow_html=True)
        _graph(graph)

    elif page == "Live Traffic":
        c1, c2 = st.columns([1, 1.2], gap="large")
        with c1:
            _stream(recs)
        with c2:
            _inspector(recs)

    elif page == "Data Lineage":
        _stream(recs)
        st.markdown("<br>", unsafe_allow_html=True)
        _inspector(recs)

    elif page == "Audit Log":
        _audit_log(recs, sessions, subjects)


if __name__ == "__main__":
    main()