"""Fake patient records for the hospital demo -- the PHI Haris must protect.

Two patients (A and B) so subject-confusion cases (TC4) become possible later.
Every record carries a `data_subject` -- which patient it belongs to -- matching the
field reserved in the Policy schema. None of this is real data.
"""
from __future__ import annotations

RECORDS: dict[str, dict] = {
    "patient-A": {
        "data_subject": "patient-A",
        "name": "Jane Doe",
        "mrn": "MRN-0001",
        "dob": "1980-02-14",
        "diagnosis": "Type 2 diabetes; hypertension",
        "note": "Patient reports increased thirst and fatigue over three weeks.",
    },
    "patient-B": {
        "data_subject": "patient-B",
        "name": "John Smith",
        "mrn": "MRN-0002",
        "dob": "1975-11-03",
        "diagnosis": "Mild persistent asthma",
        "note": "Follow-up on inhaler use; symptoms well controlled.",
    },
}


def load_record(subject: str) -> dict:
    """Return one patient's raw record, or raise if the subject is unknown."""
    try:
        return RECORDS[subject]
    except KeyError:
        raise KeyError(f"no record for subject {subject!r}; known: {list(RECORDS)}")


def format_record(record: dict) -> str:
    """The raw PHI blob record_reader emits. This is the text that must not leak."""
    return (
        f"PATIENT RECORD [{record['data_subject']}]\n"
        f"Name: {record['name']}\n"
        f"MRN: {record['mrn']}\n"
        f"DOB: {record['dob']}\n"
        f"Diagnosis: {record['diagnosis']}\n"
        f"Note: {record['note']}"
    )