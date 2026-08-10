"""Focused tests for the dashboard's data-driven protection map."""

from demo_app.dashboard_data import build_graph


def _record(*, receiver="summarizer", verdicts=None):
    return {
        "sender": "record_reader",
        "receiver": receiver,
        "recipient": None,
        "action": "allow",
        "data_type": "PHI",
        "data_subject": "patient-A",
        "verdicts": verdicts or [],
    }


def test_protection_nodes_are_derived_from_verdicts():
    graph = build_graph([_record(verdicts=[{
        "agent": "custom_guard",
        "agent_label": "Custom Guard",
        "label": "flag",
        "redacts": False,
    }])])

    node = next(n for n in graph["nodes"] if n["id"] == "haris::custom_guard")
    assert node["label"] == "Custom Guard"
    assert node["kind"] == "protection"
    assert any(
        edge["source"] == "haris::custom_guard"
        and edge["target"] == "summarizer"
        and edge["relationship"] == "inspection"
        and edge["action"] == "flag"
        for edge in graph["edges"]
    )


def test_redacting_verdict_is_rendered_as_redaction_protection():
    graph = build_graph([_record(verdicts=[{
        "agent": "pii_guard",
        "agent_label": "PII Guard",
        "label": "pass",
        "redacts": True,
    }])])

    inspection = next(e for e in graph["edges"] if e["relationship"] == "inspection")
    assert inspection["action"] == "redact"

