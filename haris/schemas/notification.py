"""FROZEN CONTRACT: NotificationEvent schema.

The single object every notification trigger emits, and the only thing the Notifier and its
channels ever pass around — exactly as every security agent hands back a `Verdict`. One
shape for a crashed detector, a fail-closed block, a blocked leak, a failed health check, or
a client-app error, so the Notifier can route them all uniformly. See `NOTIFICATIONS.md` for
the design and the trigger table.

Two rules make this safe, and they match the posture we already have elsewhere:

  * SANITIZED — `summary` and `metadata` are human-readable and MUST NOT carry a raw secret.
    An alert says "a credential flow record_reader -> external was blocked", never the
    credential. `reference` carries the `content_sha256` that already lives on the
    `AuditRecord`, so an operator can find the full (protected) record in the audit log
    without the secret ever entering the alert or a channel. Same "minimize what Haris
    stores" principle, applied to alerts. (The Notifier enforces this at its boundary; the
    schema documents it.)
  * DE-DUP KEY — `dedup_key` decides which alerts the Notifier treats as "the same alert".
    It is derived from already-whitelisted fields only, so it is safe across the sanitize
    boundary. `.security()` sets one carrying `session_id` and `reference`; `.operational()`
    leaves it None on purpose. See the constructors.
  * SERIALIZABLE — `timestamp` is an isoformat STRING, consistent with `AuditRecord.timestamp`,
    so an event drops straight into a JSONL line or a webhook JSON body with no conversion.

Frozen: new fields may be added later, but existing ones must not change without telling
your teammate — the Notifier, the channels, the dashboard banner and the tests all depend on
this shape.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


def _now_iso() -> str:
    """UTC timestamp as an isoformat string — same clock and format as AuditRecord."""
    return datetime.now(timezone.utc).isoformat()


class Category(str, Enum):
    """What kind of thing happened. Decides which part of the story an alert belongs to."""
    OPERATIONAL = "operational"    # Haris's own health/failure: a crash, fail-closed, down
    SECURITY = "security"          # a security event worth a human's eyes: a leak blocked
    CLIENT_ERROR = "client_error"  # the protected app reported its own failure


class Severity(str, Enum):
    """How urgently a human should look. Drives channel routing in the Notifier."""
    INFO = "info"          # noteworthy, no action needed        -> log only
    WARNING = "warning"    # a human should look soon            -> log + dashboard banner
    CRITICAL = "critical"  # a human should look now (Haris down)-> log + banner + webhook


class NotificationEvent(BaseModel):
    """One notifiable event. Emitted by a trigger, routed by the Notifier, sent by channels."""

    category: Category
    severity: Severity
    source: str                                    # component that raised it ("orchestrator", "health", ...)
    summary: str                                   # SANITIZED, human-readable. Never a raw secret.
    reference: Optional[str] = None                # content_sha256 / record id — a pointer, not the data
    session_id: Optional[str] = None               # ties an alert to a session in the audit log
    timestamp: str = Field(default_factory=_now_iso)   # isoformat string, like AuditRecord.timestamp
    metadata: dict[str, Any] = Field(default_factory=dict)  # escape hatch — same convention as Message
    dedup_key: Optional[str] = None                # collapse key; None => category|source|summary

    def one_line(self) -> str:
        """Canonical single-line rendering, reused by the operational log, the webhook body,
        and the dashboard banner so every channel phrases an alert the same way."""
        ref = f" [ref {self.reference[:12]}]" if self.reference else ""
        sess = f" (session {self.session_id})" if self.session_id else ""
        return (f"{self.severity.value.upper()} · {self.category.value} · "
                f"{self.source}: {self.summary}{sess}{ref}")

    # --- Ergonomic constructors: keep trigger call-sites short and force a summary. -------
    # These add no logic beyond sensible severity defaults; the schema itself stays the
    # single source of truth for the shape.

    @classmethod
    def operational(cls, source: str, summary: str, *,
                    severity: Severity = Severity.CRITICAL,
                    reference: Optional[str] = None,
                    session_id: Optional[str] = None,
                    dedup_key: Optional[str] = None,
                    **metadata: Any) -> "NotificationEvent":
        """Haris's own health/failure (detector crash, fail-closed, health-check down).

        No default dedup_key ON PURPOSE: one detector crashing on every hop SHOULD collapse
        into a single alert with a suppressed-count. That storm is what the Notifier's
        de-duplication exists to contain."""
        return cls(category=Category.OPERATIONAL, severity=severity, source=source,
                   summary=summary, reference=reference, session_id=session_id,
                   dedup_key=dedup_key, metadata=metadata)

    @classmethod
    def security(cls, source: str, summary: str, *,
                 severity: Severity = Severity.WARNING,
                 reference: Optional[str] = None,
                 session_id: Optional[str] = None,
                 dedup_key: Optional[str] = None,
                 **metadata: Any) -> "NotificationEvent":
        """A security event a human should review (a real leak blocked at egress).

        Unlike an operational storm, two security incidents are two incidents even when they
        phrase identically: a leak in session A and a leak in session B are different
        subjects, different content, different investigations. Collapsing them DELETES one -
        measured in our own demo, where the KPI tile read "Blocked 3" and the banner showed
        2. So the default key carries session_id and reference (the content hash) as well.
        A genuine storm inside ONE session still collapses, because both are then equal."""
        key = dedup_key or "|".join(
            ["security", source, summary, session_id or "", reference or ""])
        return cls(category=Category.SECURITY, severity=severity, source=source,
                   summary=summary, reference=reference, session_id=session_id,
                   dedup_key=key, metadata=metadata)

    @classmethod
    def client_error(cls, source: str, summary: str, *,
                     severity: Severity = Severity.WARNING,
                     reference: Optional[str] = None,
                     session_id: Optional[str] = None,
                     dedup_key: Optional[str] = None,
                     **metadata: Any) -> "NotificationEvent":
        """The protected app ('client') reported its own failure via the error hook."""
        return cls(category=Category.CLIENT_ERROR, severity=severity, source=source,
                   summary=summary, reference=reference, session_id=session_id,
                   dedup_key=dedup_key, metadata=metadata)