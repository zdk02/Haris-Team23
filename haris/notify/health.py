"""Haris health check — a self-check that ACTS, not one that just reports.

The mentor's sharpest version of the notification note was: "a health check nobody acts on
is theater." So this module is deliberately wired to *do* two things when Haris is unhealthy,
not merely expose a status:

  1. NOTIFY. On a failed check it fires a CRITICAL operational alert through the Notifier
     (task 3), so a human is told "Haris itself is down" — the out-of-band channel matters
     here, because if Haris is broken nobody may be watching the dashboard.
  2. FAIL CLOSED. `assert_serviceable(mode)` raises `HarisUnhealthy` when Haris is unhealthy
     *in enforce mode*, so the protected app is told to stop rather than run unprotected
     behind a broken guard. This is the same fail-open-in-monitor / fail-closed-in-enforce
     rule the orchestrator already uses for a crashed detector, lifted to "the whole guard
     is down."

A health check runs a set of registered PROBES — small callables that answer "is this part
of Haris OK right now?" (audit chain intact, state store reachable, agents present, ...). A
probe that returns falsy or raises counts as a failure. `check()` aggregates them into a
`HealthStatus` that also serializes cleanly to a `/health` JSON body for a deployed service.

The optional `Heartbeat` runs `check()` on a timer in a background thread, so degradation is
noticed even when no message is flowing. Repeated failures don't spam the channel: the
Notifier's de-dup collapses identical CRITICAL alerts within its window.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Callable, Optional

from pydantic import BaseModel, Field

from haris.logging_config import get_logger
from haris.notify.notifier import Notifier
from haris.schemas.notification import NotificationEvent, Severity
from haris.schemas.policy import Mode

# A probe answers "is this part of Haris healthy right now?" — truthy = OK. Raising = failed.
Probe = Callable[[], bool]

_log = get_logger("health")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class HarisUnhealthy(Exception):
    """Raised by `assert_serviceable()` when Haris is unhealthy in ENFORCE mode. The protected
    app should treat Haris as down and fail closed — do not proceed unprotected."""

    def __init__(self, status: "HealthStatus") -> None:
        super().__init__(f"Haris unhealthy — failed: {', '.join(status.failures)}")
        self.status = status


class HealthStatus(BaseModel):
    """The result of one health check. Serializes straight to a `/health` JSON response."""
    healthy: bool
    checks: dict[str, bool] = Field(default_factory=dict)   # probe name -> passed?
    failures: list[str] = Field(default_factory=list)       # probe names that failed
    timestamp: str = Field(default_factory=_now_iso)


class HealthCheck:
    """Runs probes, and on failure both notifies (CRITICAL) and enables fail-closed.

    Register whatever probes make sense for your deployment; a few ready-made ones are
    provided below (`audit_chain_probe`, etc.). Pass the `Notifier` so a failed check is
    pushed to a human, not just returned to the caller.
    """

    def __init__(self, notifier: Optional[Notifier] = None,
                 source: str = "health") -> None:
        self._probes: dict[str, Probe] = {}
        self._probe_reasons: dict[str, str] = {}
        self.notifier = notifier
        self.source = source

    def register(self, name: str, probe: Probe) -> None:
        """Add a named probe. `name` shows up in the status and in the alert."""
        self._probes[name] = probe

    def check(self) -> HealthStatus:
        """Run every probe, build the status, and notify CRITICAL if anything failed."""
        results: dict[str, bool] = {}
        reasons: dict[str, str] = {}
        for name, probe in self._probes.items():
            try:
                ok = bool(probe())
                results[name] = ok
                if not ok:
                    reasons[name] = "probe returned False"
            except Exception as exc:  # noqa: BLE001 — a probe crash is itself an unhealthy signal
                results[name] = False
                reasons[name] = f"{type(exc).__name__}: {exc}"

        healthy = all(results.values()) if results else True
        failures = [n for n, ok in results.items() if not ok]
        status = HealthStatus(healthy=healthy, checks=results, failures=failures)

        if not healthy:
            _log.error("health: Haris UNHEALTHY — failed probes: %s", failures)
            if self.notifier is not None:
                # summary is sanitized (probe names only); detailed reasons go in metadata,
                # which the Notifier keeps for the internal log but strips before any channel.
                self.notifier.notify(NotificationEvent.operational(
                    self.source,
                    f"Haris health check FAILED — {len(failures)} probe(s) down: "
                    f"{', '.join(failures)}",
                    severity=Severity.CRITICAL,
                    **{"failed_probes": failures, "reasons": reasons},
                ))
        return status

    def is_healthy(self) -> bool:
        return self.check().healthy

    def assert_serviceable(self, mode: Mode) -> HealthStatus:
        """Run a check and enforce the fail-closed rule. In ENFORCE mode an unhealthy Haris
        raises `HarisUnhealthy` (fail closed — refuse rather than run unprotected). In MONITOR
        mode it never raises (fail open — a health blip must not break the app while we only
        watch). Either way the failure was already notified inside `check()`."""
        status = self.check()
        if not status.healthy and mode is Mode.ENFORCE:
            raise HarisUnhealthy(status)
        return status


class Heartbeat:
    """Runs `HealthCheck.check()` on a timer in a background daemon thread, so degradation is
    noticed even when no traffic is flowing. Failed checks alert via the Notifier (with de-dup
    preventing a flood). Start it once at service/dashboard startup; stop it on shutdown."""

    def __init__(self, health: HealthCheck, interval_s: float = 30.0) -> None:
        self.health = health
        self.interval_s = interval_s
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> "Heartbeat":
        if self._thread is not None:
            return self
        self._thread = threading.Thread(target=self._run, name="haris-heartbeat", daemon=True)
        self._thread.start()
        _log.info("health: heartbeat started (every %.0fs)", self.interval_s)
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self.interval_s + 1)
            self._thread = None

    def _run(self) -> None:
        # Fire once immediately, then every interval, until stopped.
        while True:
            try:
                self.health.check()
            except Exception as exc:  # noqa: BLE001 — the heartbeat must never die silently
                _log.error("health: heartbeat check raised %s: %s", type(exc).__name__, exc)
            if self._stop.wait(self.interval_s):
                return


# --- ready-made probes ---------------------------------------------------------------------
# Small factories so a caller can wire the common checks without writing lambdas.

def audit_chain_probe(audit_log) -> Probe:
    """Healthy iff the audit log's hash chain still verifies — i.e. the tamper-evident record
    hasn't been broken. Reuses the AuditLog.verify_chain() we already have."""
    return lambda: audit_log.verify_chain()


def state_store_probe(state_store, session_id: str = "__health__") -> Probe:
    """Healthy iff the state store answers a trivial context read without raising."""
    def _probe() -> bool:
        state_store.get_context(session_id)
        return True
    return _probe


def agents_present_probe(orchestrator, minimum: int = 1) -> Probe:
    """Healthy iff the orchestrator actually has agents wired in — guards against the
    empty-agents pass-through skeleton being shipped by accident."""
    return lambda: len(getattr(orchestrator, "agents", [])) >= minimum