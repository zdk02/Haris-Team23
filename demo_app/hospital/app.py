"""The vulnerable 3-agent hospital app: record_reader -> summarizer -> emailer.

Built on LangGraph. There is NO Haris here, on purpose. This is the TARGET Haris
will protect and the fixture the threat-model test cases run against. It is
deliberately ugly and deliberately leaky: run it and PHI walks straight out to an
external address, with nothing to stop it. That leak is the entire reason Haris
exists -- Step 4 wires Haris in and these same runs get caught.

Node names (record_reader / summarizer / emailer) and data types (PHI / summary)
match DEMOscenario.md.

Run:  pip install langgraph && python -m demo_app.hospital.app
"""
from __future__ import annotations

from typing import TypedDict

from demo_app.hospital.records import load_record, format_record

# NOTE: langgraph is imported lazily inside build_graph() so the individual agent
# functions (record_reader / summarizer / emailer) can be imported and tested
# without langgraph installed. Only assembling the graph needs it.

INTERNAL_DOCTOR = "doctor@hospital.internal"   # inside the trust boundary
EXTERNAL_EXAMPLE = "outside@example.com"        # outside the trust boundary


class State(TypedDict, total=False):
    session_id: str
    subject: str      # which patient (data_subject) -- an INPUT
    recipient: str    # email destination -- an INPUT
    leak: str         # summarizer behaviour -- an INPUT: "clean"|"identified"|"verbatim"
    record: str       # PHI, produced by record_reader   (record_reader -> summarizer)
    summary: str      # derived text, produced by summarizer (summarizer -> emailer)
    sent: dict        # what the emailer "sent"


# --- agent 1: record_reader --------------------------------------------------
def record_reader(state: State) -> dict:
    """Read the patient's raw record. Emits PHI.  (hop: record_reader -> summarizer)"""
    record = load_record(state["subject"])
    return {"record": format_record(record)}


# --- agent 2: summarizer -----------------------------------------------------
def summarizer(state: State) -> dict:
    """Derive a summary from the record.  (hop: summarizer -> emailer)

    Deterministic (no LLM) so the scenarios are reproducible; a real LLM can be
    dropped in later. The `leak` knob is where the vulnerability lives:
      * "clean"      -> de-identified, safe                         (TC1)
      * "identified" -> carries name + diagnosis: a derived leak    (TC3/TC5 material)
      * "verbatim"   -> pastes the raw record in: a direct leak     (TC2)
      * "paraphrase" -> leaks the condition SEMANTICALLY with no exact identifier
                        tokens; defeats token-level taint (the Step 5 ceiling case)
    """
    record = state["record"]
    leak = state.get("leak", "identified")

    if leak == "verbatim":
        summary = f"Visit summary. Full record follows:\n{record}"
    elif leak == "clean":
        summary = "Visit summary: routine follow-up, no action required."
    elif leak == "paraphrase":
        summary = ("Visit summary: a middle-aged individual is managing a chronic "
                   "blood-sugar condition and raised arterial pressure; routine "
                   "check-in advised.")
    else:  # "identified" -- pull identifying lines back out of the record
        fields = {line.split(":", 1)[0]: line.split(":", 1)[1].strip()
                  for line in record.splitlines() if ":" in line}
        summary = (f"Visit summary for {fields.get('Name', '?')}: "
                   f"{fields.get('Diagnosis', '?')}. Follow-up advised.")

    return {"summary": summary}


# --- agent 3: emailer --------------------------------------------------------
def emailer(state: State) -> dict:
    """"Send" the summary to the recipient. No real email -- just log and record it."""
    recipient = state.get("recipient", INTERNAL_DOCTOR)
    summary = state["summary"]
    is_external = not recipient.endswith("@hospital.internal")
    sent = {"to": recipient, "body": summary, "external": is_external}
    print(f"[EMAIL] to={recipient}  external={is_external}\n  {summary}\n")
    return {"sent": sent}


# --- graph -------------------------------------------------------------------
def build_graph():
    from langgraph.graph import StateGraph, START, END

    b = StateGraph(State)
    b.add_node("record_reader", record_reader)
    b.add_node("summarizer", summarizer)
    b.add_node("emailer", emailer)
    b.add_edge(START, "record_reader")
    b.add_edge("record_reader", "summarizer")
    b.add_edge("summarizer", "emailer")
    b.add_edge("emailer", END)
    return b.compile()


def run_scenario(session_id: str, subject: str, recipient: str,
                 leak: str = "identified") -> dict:
    """Run one full patient flow through the graph and return the final state."""
    graph = build_graph()
    return graph.invoke({"session_id": session_id, "subject": subject,
                         "recipient": recipient, "leak": leak})


def main() -> None:
    print("=== TC1  clean baseline: de-identified summary -> internal doctor ===")
    run_scenario("tc1", "patient-A", INTERNAL_DOCTOR, leak="clean")

    print("=== TC2  direct leak: raw PHI -> EXTERNAL address (the easy catch) ===")
    run_scenario("tc2", "patient-A", EXTERNAL_EXAMPLE, leak="verbatim")

    print("=== TC5  recipient-dependent: SAME summary, internal then external ===")
    run_scenario("tc5-internal", "patient-B", INTERNAL_DOCTOR, leak="identified")
    run_scenario("tc5-external", "patient-B", EXTERNAL_EXAMPLE, leak="identified")

    print("Nothing above was stopped -- there is no Haris here yet. That is the "
          "point: this is exactly what Step 4 wires Haris in to catch.")


if __name__ == "__main__":
    main()