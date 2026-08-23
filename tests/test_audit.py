"""Security audit log: Haris records every decision, app-agnostically, hashing content."""
from __future__ import annotations

from dataclasses import replace

import pytest

from haris.agents.base import SecurityAgent
from haris.audit import AuditLog, _sha256
from haris.orchestrator.orchestrator import Orchestrator
from haris.schemas.decision import HarisBlocked
from haris.schemas.message import Message
from haris.schemas.policy import Mode, Policy
from haris.schemas.verdict import Label, Verdict
from haris.state.memory import InMemoryStateStore


class _Blocker(SecurityAgent):
    name = "blocker"

    def check(self, m, c):
        return Verdict(agent_name="blocker", label=Label.BLOCK, score=1.0, reason="nope")


def _msg(content="hi", **md):
    return Message(session_id="s", sender="a", receiver="b", content=content, metadata=md)


def _orch(log, agents=None, mode=Mode.MONITOR):
    return Orchestrator(InMemoryStateStore(), agents=agents or [],
                        policy=Policy(mode=mode), audit_log=log)


def test_orchestrator_writes_a_record_per_decision():
    log = AuditLog()
    _orch(log).process(_msg("hello", data_type="PHI", data_subject="patient-A"))
    assert len(log) == 1
    rec = log.records()[0]
    assert (rec.sender, rec.receiver) == ("a", "b")
    assert rec.data_type == "PHI" and rec.data_subject == "patient-A"
    assert rec.action == "allow" and rec.latency_ms >= 0.0


def test_content_is_hashed_not_stored_raw():
    log = AuditLog(store_delivered_content=False)     # hardened mode
    secret = "AKIA-super-secret-key"
    _orch(log).process(_msg(secret))
    rec = log.records()[0]
    assert rec.content_sha256 == _sha256(secret)
    assert rec.delivered_content is None
    assert secret not in str(rec.as_dict())           # the raw secret is nowhere in the log


def test_blocked_decision_is_recorded_before_raising():
    log = AuditLog()
    with pytest.raises(HarisBlocked):
        _orch(log, agents=[_Blocker()], mode=Mode.ENFORCE).process(_msg())
    assert len(log) == 1 and log.records()[0].action == "block"


def test_records_returns_an_append_only_snapshot():
    log = AuditLog()
    orch = _orch(log)
    orch.process(_msg())
    snap = log.records()
    orch.process(_msg())
    assert len(snap) == 1 and len(log.records()) == 2   # the returned list is a copy


def test_orchestrator_without_audit_log_is_unaffected():
    d = Orchestrator(InMemoryStateStore(), agents=[]).process(_msg())
    assert d.action.value == "allow"


# ---- tamper-evidence: the hash chain (append-only in effect) -----------------

def test_hash_chain_links_records_and_verifies():
    log = AuditLog()
    orch = _orch(log)
    for _ in range(3):
        orch.process(_msg())
    recs = log.records()
    assert recs[0].prev_hash == ""                      # genesis
    assert recs[1].prev_hash == recs[0].entry_hash      # each links to the previous
    assert recs[2].prev_hash == recs[1].entry_hash
    assert log.verify_chain() is True


def test_editing_a_past_record_breaks_the_chain():
    log = AuditLog()
    orch = _orch(log)
    orch.process(_msg("one"))
    orch.process(_msg("two"))
    assert log.verify_chain() is True
    log._records[0] = replace(log._records[0], action="allow-tampered")   # attacker edit
    assert log.verify_chain() is False


def test_deleting_a_record_breaks_the_chain():
    log = AuditLog()
    orch = _orch(log)
    for _ in range(3):
        orch.process(_msg())
    del log._records[1]                                  # drop the middle record
    assert log.verify_chain() is False


def test_jsonl_persistence_roundtrips_and_verifies(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    log = AuditLog(store_delivered_content=False, path=path)   # hardened: hashes only
    orch = _orch(log)
    orch.process(_msg("alpha", data_type="PHI"))
    orch.process(_msg("beta"))
    loaded = AuditLog.load_jsonl(path)
    assert len(loaded) == 2
    assert loaded.verify_chain() is True                # the file wasn't tampered with
    disk = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert '"delivered_content": null' in disk          # no raw bodies persisted

def test_blocked_content_is_never_retained():
    """A message Haris refused to deliver leaves no plaintext behind - even with
    store_delivered_content explicitly ON. Decision.final_content is only set
    for REDACT, so BLOCK used to fall back to the raw message content."""
    log = AuditLog(store_delivered_content=True)                                     
    secret = "AKIA-super-secret-key"
    with pytest.raises(HarisBlocked):
        _orch(log, agents=[_Blocker()], mode=Mode.ENFORCE).process(_msg(secret))

    rec = log.records()[0]
    assert rec.action == "block"
    assert rec.delivered_content is None
    assert secret not in str(rec.as_dict())            # nowhere in the record
    assert rec.content_sha256 == _sha256(secret)       # the reference still survives

def test_delivered_messages_still_keep_their_delivered_form():
    """The dashboard needs this - retention must still work when explicitly asked for."""
    log = AuditLog(store_delivered_content=True)
    _orch(log).process(_msg("hello"))
    assert log.records()[0].delivered_content == "hello"

def _forge_whole_chain(log, key=b""):
    """The real attack: edit every record AND recompute every link, so the chain ends up
    internally consistent again. Trivial unkeyed; impossible without the key."""
    from haris.audit import _entry_hash
    forged, prev = [], ""
    for rec in log._records:
        rec = replace(rec, action="allow-tampered", prev_hash=prev)
        rec = replace(rec, entry_hash=_entry_hash(rec._fields(), prev, key))
        forged.append(rec)
        prev = rec.entry_hash
    log._records = forged


def test_keyed_chain_rejects_a_recomputed_rewrite():
    """B1: an attacker who can write the log but has no key cannot rebuild it."""
    log = AuditLog(key=b"operator-secret")
    orch = _orch(log)
    orch.process(_msg("one"))
    orch.process(_msg("two"))
    assert log.verify_chain() is True
    _forge_whole_chain(log, key=b"")
    assert log.verify_chain() is False


def test_unkeyed_chain_is_forgeable_a_documented_limitation():
    """Without HARIS_AUDIT_KEY the chain is corruption-evident, not tamper-evident.
    Pinned as a test so the limitation stays visible instead of being forgotten."""
    log = AuditLog(key=b"")
    orch = _orch(log)
    orch.process(_msg("one"))
    orch.process(_msg("two"))
    _forge_whole_chain(log, key=b"")
    assert log.verify_chain() is True


def test_forged_append_is_rejected_when_keyed():
    """B1: a record sealed without the key fails verification."""
    from haris.audit import _entry_hash
    log = AuditLog(key=b"operator-secret")
    _orch(log).process(_msg("one"))
    prev = log.head()
    forged = replace(log._records[-1], prev_hash=prev)
    forged = replace(forged, entry_hash=_entry_hash(forged._fields(), prev, b""))
    log._records.append(forged)
    assert log.verify_chain() is False


def test_persisted_chain_continues_across_a_restart(tmp_path):
    """B3: a new process appending to an existing file must continue ITS chain."""
    path = str(tmp_path / "audit.jsonl")
    _orch(AuditLog(path=path, key=b"k")).process(_msg("one"))
    _orch(AuditLog(path=path, key=b"k")).process(_msg("two"))      # the "restart"
    loaded = AuditLog.load_jsonl(path, key=b"k")
    assert len(loaded) == 2
    assert loaded.verify_chain() is True


def test_truncation_needs_a_head_held_outside_the_log(tmp_path):
    """B2: dropping records off the end leaves a chain that still verifies internally."""
    p = tmp_path / "audit.jsonl"
    log = AuditLog(path=str(p), key=b"k")
    orch = _orch(log)
    for _ in range(3):
        orch.process(_msg())
    head, count = log.head(), len(log)

    lines = p.read_text(encoding="utf-8").splitlines()
    p.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")    # attacker truncates

    t = AuditLog.load_jsonl(str(p), key=b"k")
    assert t.verify_chain() is True                                        # looks intact
    assert t.verify_chain(expected_head=head, expected_count=count) is False


def test_concurrent_writes_keep_the_chain_valid():
    """B4: six threads sharing one audit log."""
    import threading
    log = AuditLog()

    def worker():
        o = _orch(log)                    # own state store, shared audit log
        for _ in range(50):
            o.process(_msg())

    ts = [threading.Thread(target=worker) for _ in range(6)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert len(log) == 300
    assert log.verify_chain() is True

# ---- B2 completed: the reference that makes truncation detectable ------------

def test_checkpoint_reports_the_head_and_count():
    """The two values an operator holds OUTSIDE the log. Without them, truncation is
    undetectable: dropping records off the end leaves a shorter chain that still verifies."""
    log = AuditLog(key=b"k")
    orch = _orch(log)
    for _ in range(3):
        orch.process(_msg())
    cp = log.checkpoint()
    assert cp == {"head": log.head(), "count": 3}
    assert log.verify_checkpoint(cp) is True


def test_verify_checkpoint_catches_truncation(tmp_path):
    """The point of the whole mechanism, end to end: a truncated log still verifies against
    itself and fails against a checkpoint taken before the truncation."""
    p = tmp_path / "audit.jsonl"
    log = AuditLog(path=str(p), key=b"k")
    orch = _orch(log)
    for _ in range(3):
        orch.process(_msg())
    cp = log.checkpoint()                       # operator keeps this elsewhere

    lines = p.read_text(encoding="utf-8").splitlines()
    p.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")   # attacker truncates

    reloaded = AuditLog.load_jsonl(str(p), key=b"k")
    assert reloaded.verify_chain() is True                  # internally consistent...
    assert reloaded.verify_checkpoint(cp) is False          # ...but shorter than we recorded


def test_checkpoints_reach_the_operational_log(caplog):
    """Checkpoints are emitted to the OPERATIONAL stream, never into the audit log itself.
    That separation is what puts the reference beyond the reach of whoever can write the
    audit file."""
    import logging
    log = AuditLog(checkpoint_every=2)
    orch = _orch(log)
    with caplog.at_level(logging.INFO, logger="haris.audit.checkpoint"):
        for _ in range(4):
            orch.process(_msg())
    emitted = [r for r in caplog.records if r.name == "haris.audit.checkpoint"]
    assert len(emitted) == 2                       # after record 2 and record 4
    assert "count=4" in emitted[-1].getMessage()


def test_checkpoint_emission_can_be_disabled():
    log = AuditLog(checkpoint_every=0)
    _orch(log).process(_msg())
    assert log.checkpoint()["count"] == 1          # the method still works