"""Tier 1 — operational logging: system health, errors, and lifecycle.

Haris keeps two deliberately separate kinds of log, exactly as the mentor framed it:

  * TIER 1 — OPERATIONAL (this module). "Is anything going wrong inside Haris?" Startup,
    configuration, agent crashes (the reliability guard logs here), and unexpected errors.
    It is for operators/developers debugging Haris. It logs only METADATA — who → whom, the
    action, an agent's error type — and never message bodies or secrets, so the operational
    log is safe to ship to ordinary log infrastructure.

  * TIER 2 — SECURITY AUDIT (`haris/audit.py`). "What did Haris decide, and why?" The
    durable, hash-chained, app-agnostic record of every inter-agent decision. It is
    sensitive (it concerns the protected traffic), so it is minimized (content hashed, not
    stored raw), tamper-evident (hash chain), and access-controlled (the dashboard's
    operator gate).

Splitting them matters: the operational log can be verbose and widely readable; the audit
log is protected and leveraged (the dashboard's metrics are computed from it). Keeping
secrets out of the operational tier is part of "minimize what Haris stores."

Usage:
    from haris.logging_config import configure_logging
    configure_logging()            # once, at process start (dashboards / demos / services)
"""
from __future__ import annotations

import logging
import sys
from typing import Optional

# All Haris operational logs live under this namespace (haris.orchestrator, etc. inherit).
OPERATIONAL_LOGGER = "haris"


def configure_logging(level: int = logging.INFO,
                      stream=None,
                      fmt: Optional[str] = None) -> logging.Logger:
    """Configure the Tier-1 operational logger and return it. Idempotent: calling it again
    replaces the handler rather than stacking duplicates."""
    logger = logging.getLogger(OPERATIONAL_LOGGER)
    logger.setLevel(level)
    logger.propagate = False

    # Replace any handler we previously attached so repeated calls don't duplicate output.
    for h in list(logger.handlers):
        if getattr(h, "_haris_operational", False):
            logger.removeHandler(h)

    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(logging.Formatter(
        fmt or "%(asctime)s | haris.ops | %(levelname)-7s | %(name)s | %(message)s",
        datefmt="%H:%M:%S"))
    handler._haris_operational = True  # type: ignore[attr-defined]
    logger.addHandler(handler)
    return logger


def get_logger(name: str = OPERATIONAL_LOGGER) -> logging.Logger:
    """A child of the operational logger (e.g. get_logger('orchestrator'))."""
    if name == OPERATIONAL_LOGGER or name.startswith(OPERATIONAL_LOGGER + "."):
        return logging.getLogger(name)
    return logging.getLogger(f"{OPERATIONAL_LOGGER}.{name}")
