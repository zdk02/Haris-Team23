"""Audit-log integrity demo (Tier-2 security log — task 7).

Shows the two protections the mentor asked for on the sensitive audit log:
  * MINIMIZE — it stores a SHA-256 of each message, not the raw content, so a breach of
    the log yields hashes, not secrets.
  * TAMPER-EVIDENT — every record is hash-chained to the one before it, so editing or
    deleting an entry breaks the chain, which verify_chain() detects. An attacker who
    reaches the log cannot quietly erase their tracks.

Run:  python -m demo_app.hospital.audit_demo
"""
from __future__ import annotations

from dataclasses import replace

from demo_app.dashboard_data import run_battery
from haris.schemas.policy import Mode


def main() -> None:
    import logging
    logging.disable(logging.INFO)

    audit = run_battery(Mode.ENFORCE, include_secrets=False)   # populates the audit log
    recs = audit.records()

    print("=== Haris security audit log (Tier 2) ===\n")
    print(f"records written        : {len(recs)}")
    print(f"chain intact           : {audit.verify_chain()}")
    print(f"content stored as hash  : {recs[0].content_sha256[:24]}…  (not the raw body)")

    print("\n-- simulate an attacker editing a past decision to hide a block --")
    idx = next(i for i, r in enumerate(recs) if r.action == "block")
    audit._records[idx] = replace(recs[idx], action="allow")   # tamper in place
    print(f"   edited record #{idx}: action 'block' -> 'allow'")
    print(f"   chain intact now    : {audit.verify_chain()}   <-- tampering detected")

    print("\nThe hash chain means the audit trail is append-only in effect: any edit or "
          "deletion\nis detectable, so a compromised Haris can't quietly rewrite what it "
          "decided.")


if __name__ == "__main__":
    main()
