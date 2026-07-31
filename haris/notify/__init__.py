"""Haris notification system.

The Notifier turns events — a crashed detector, a fail-closed block, a blocked leak, a failed
health check, a client-app error — into alerts delivered to the operational log and to
external channels (dashboard banner, webhook). See `NOTIFICATIONS.md` for the design.

Public surface:
    from haris.notify import Notifier, Channel
    from haris.notify import NotificationEvent, Category, Severity   # re-exported for convenience
"""
from __future__ import annotations

from haris.notify.notifier import Channel, Notifier
from haris.schemas.notification import Category, NotificationEvent, Severity

__all__ = ["Notifier", "Channel", "NotificationEvent", "Category", "Severity"]