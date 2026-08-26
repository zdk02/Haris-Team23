"""The Notifier — Haris's single notification dispatcher.

One entry point, `notify(event)`, that the whole system calls when something happens a human
may need to know about (see the trigger table in `NOTIFICATIONS.md`). Keeping it a single
choke point — rather than each trigger talking to channels directly — is what lets us
enforce the secret-safe rule and the de-dup rule in exactly one place.

`notify()` does three things, in order:

  1. DE-DUPLICATE / RATE-LIMIT. A crashing detector can fire on every hop. Events sharing a
     de-dup key inside a short window are collapsed into one alert with a suppressed-count,
     so a storm becomes a single message, not a hundred. The key is `event.dedup_key` when
     set, else category|source|summary. `.security()` sets one that carries `session_id` and
     `reference`, because two subjects' blocked leaks are two incidents, not one repeat;
     `.operational()` leaves it unset, because one detector crashing on every hop IS one
     repeat. The table is bounded: keys older than 2x the window are evicted, the table is
     hard-capped, and anything evicted while still holding a suppressed count emits a rollup
     rather than vanishing.
  2. ALWAYS LOG. Every event that gets through de-dup is written to the Tier-1 operational
     logger (`haris/logging_config.py`), at a level matching its severity. The log stays the
     complete record even if every external channel is off — the Notifier *leverages* the
     log, it does not replace it.
  3. ROUTE BY SEVERITY to the external channels. Each `Channel` declares a `min_severity`;
     the Notifier sends an event to a channel only if the event is at least that severe. That
     reproduces the routing table from the design (banner = WARNING+, webhook = CRITICAL+)
     without the Notifier hard-coding any channel's name.

SECRET-SAFE BOUNDARY. External channels receive a *sanitized* copy: the whitelist fields
(category / severity / source / summary / reference / session_id / timestamp) only. The
free-form `metadata` escape hatch is dropped before an event leaves the process, because it
is the one field that could accidentally carry sensitive detail. The operational log (which
stays inside our own infrastructure) keeps `metadata`.

ROBUSTNESS. A channel that raises (a webhook that times out, say) must never take down the
protected app or suppress the other channels — a broken alerter is not allowed to become an
outage. Each `send()` runs behind a guard, in the same spirit as the orchestrator's
reliability guard around agents.
"""
from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod
from typing import Optional

from haris.logging_config import get_logger
from haris.schemas.notification import NotificationEvent, Severity

# Severity ordering for min_severity thresholds. INFO < WARNING < CRITICAL.
_SEVERITY_RANK = {Severity.INFO: 0, Severity.WARNING: 1, Severity.CRITICAL: 2}

# Hard cap on the de-dup table. The Notifier lives for the life of the process - in the
# deployed dashboard that is days - and an unbounded dict keyed by summary text is a slow
# memory leak in the component whose whole job is to still be working when things go wrong.
_MAX_RECENT_KEYS = 1000


def _rank(severity: Severity) -> int:
    return _SEVERITY_RANK[severity]


class Channel(ABC):
    """A place an alert can be delivered. One method, `send(event)`, so the Notifier treats
    every channel uniformly — the same way the Orchestrator treats every SecurityAgent.

    A channel declares the least-severe event it wants via `min_severity`; the Notifier does
    the threshold check, so a channel's `send()` only ever runs for events it should handle.
    """
    name: str = "base"
    min_severity: Severity = Severity.WARNING  # default: ignore INFO noise

    @abstractmethod
    def send(self, event: NotificationEvent) -> None:
        """Deliver one (already sanitized) event. May raise; the Notifier contains it."""
        raise NotImplementedError


class Notifier:
    """Routes NotificationEvents to the operational log and a set of external channels.

    Wire it in like the audit log: the Orchestrator takes an optional `notifier=None`, and
    when it is None Haris behaves exactly as before — notifications are purely additive.
    """

    def __init__(self, channels: Optional[list[Channel]] = None,
                 dedup_window_s: float = 60.0) -> None:
        self.channels: list[Channel] = list(channels or [])
        self.dedup_window_s = dedup_window_s
        self._log = get_logger("notify")
        self._lock = threading.Lock()
        # key -> {"last": monotonic_ts, "suppressed": int}
        self._recent: dict[str, dict] = {}
        # Lightweight observability counters. `delivered`/`failed`/`skipped` are per
        # channel-send, not per event: one event fanning out to two channels counts twice.
        # `skipped` is a channel that is present but UNCONFIGURED (no webhook URL, no SES
        # sender) - counting that as delivered would report a delivery that never happened.
        self.counts = {"emitted": 0, "suppressed": 0,
                       "delivered": 0, "failed": 0, "skipped": 0}

    def add_channel(self, channel: Channel) -> None:
        self.channels.append(channel)

    # -- the single entry point -----------------------------------------------------------
    def notify(self, event: NotificationEvent) -> None:
        """Emit one event: de-dup, always log, then fan out to channels by severity."""
        emit_event, rollups = self._dedup(event)
        # Rollups are emitted OUTSIDE the lock (_dedup released it) and through _emit rather
        # than notify(), so an eviction can neither deadlock nor re-enter de-duplication.
        for rollup in rollups:
            self._emit(rollup)
        if emit_event is None:
            return  # collapsed into a recent identical alert
        self._emit(emit_event)

    def _emit(self, event: NotificationEvent) -> None:
        """Log, then fan out to channels by severity. The tail of notify(), and the path an
        eviction rollup takes. Deliberately performs no de-duplication."""
        self.counts["emitted"] += 1

        # 2. Always log (internal tier — keeps metadata).
        self._log_event(event)

        # 3. Route to external channels (sanitized — metadata stripped).
        safe = self._sanitize(event)
        for channel in self.channels:
            if _rank(safe.severity) < _rank(channel.min_severity):
                continue
            if getattr(channel, "enabled", True) is False:
                self.counts["skipped"] += 1
                continue
            try:
                channel.send(safe)
                self.counts["delivered"] += 1
            except Exception as exc:  # noqa: BLE001 — a broken alerter must not break the app
                self.counts["failed"] += 1
                self._log.error("notify: channel %r failed to send (%s: %s)",
                                getattr(channel, "name", channel.__class__.__name__),
                                type(exc).__name__, exc)

    # -- internals ------------------------------------------------------------------------
    def _dedup(self, event: NotificationEvent
               ) -> tuple[Optional[NotificationEvent], list[NotificationEvent]]:
        """Return (event-to-emit-or-None, rollup-events-the-caller-must-emit).

        None means the event is a duplicate inside the window. If identical events were
        suppressed since the last emit, the summary is annotated with the count so the
        collapse is visible, not silent."""
        now = time.monotonic()
        key = event.dedup_key or f"{event.category.value}|{event.source}|{event.summary}"
        with self._lock:
            rec = self._recent.get(key)
            duplicate = rec is not None and (now - rec["last"]) < self.dedup_window_s
            if duplicate:
                rec["suppressed"] += 1
                self.counts["suppressed"] += 1
                suppressed = 0
            else:
                suppressed = rec["suppressed"] if rec is not None else 0
                self._recent[key] = {"last": now, "suppressed": 0}
            # Prune AFTER this event's key is handled, never before. THIS key now carries
            # last=now, so it can never be what gets evicted -- which means an alert being
            # re-emitted with its suppressed-count does not ALSO produce a rollup for the
            # same suppressions. Pruning first double-reports one collapse as two alerts.
            rollups = self._prune_locked(now)

        if duplicate:
            return None, rollups
        if suppressed:
            window = self.dedup_window_s
            return event.model_copy(update={
                "summary": f"{event.summary} (+{suppressed} similar suppressed in last "
                           f"{window:.0f}s)"}), rollups
        return event, rollups

    def _prune_locked(self, now: float) -> list[NotificationEvent]:
        """Evict stale keys and cap the table. MUST be called with `self._lock` held, and
        MUST NOT emit: `threading.Lock` is not reentrant, so notifying from in here would
        deadlock. It returns the rollups for the caller to emit after releasing the lock.

        Why a rollup at all: a key that expires while `suppressed > 0` means real alerts were
        collapsed into an alert that never got a follow-up. Dropping that silently is the
        same failure as the de-dup bug itself, one level up."""
        ttl = 2 * self.dedup_window_s
        evicted: list[tuple[str, int]] = []

        for k in [k for k, r in self._recent.items() if (now - r["last"]) > ttl]:
            rec = self._recent.pop(k)
            if rec["suppressed"]:
                evicted.append((k, rec["suppressed"]))

        if len(self._recent) > _MAX_RECENT_KEYS:
            overflow = len(self._recent) - _MAX_RECENT_KEYS
            for k, rec in sorted(self._recent.items(),
                                 key=lambda kv: kv[1]["last"])[:overflow]:
                self._recent.pop(k, None)
                if rec["suppressed"]:
                    evicted.append((k, rec["suppressed"]))

        return [
            NotificationEvent.operational(
                "notifier",
                f"{n} alert(s) matching '{k}' were suppressed and expired without a "
                f"follow-up alert",
                severity=Severity.WARNING,
                dedup_key=f"rollup|{k}",
            )
            for k, n in evicted
        ]

    def _log_event(self, event: NotificationEvent) -> None:
        line = event.one_line()
        if event.severity is Severity.CRITICAL:
            self._log.error(line)
        elif event.severity is Severity.WARNING:
            self._log.warning(line)
        else:
            self._log.info(line)

    @staticmethod
    def _sanitize(event: NotificationEvent) -> NotificationEvent:
        """The secret-safe boundary: strip the free-form metadata before an event leaves the
        process. Everything a channel needs to render an alert is in the whitelist fields."""
        return event.model_copy(update={"metadata": {}})