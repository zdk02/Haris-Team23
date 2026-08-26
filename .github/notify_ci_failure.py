"""Post a CI test-failure alert to the team webhook (HARIS_ALERT_WEBHOOK).

Run by the CI workflow's `if: failure()` step. It reuses Haris's own Notifier, so:
  * the Slack/Discord formatting is identical to the runtime alerts,
  * the sanitisation, de-dup and always-log rules are the SAME ones the runtime uses, and
  * if the HARIS_ALERT_WEBHOOK secret is not configured it is a SILENT NO-OP — CI never
    fails just because the webhook isn't set up.

Values come from the workflow's env (github context), never interpolated into the command,
so there is nothing to inject. This is the same "leverage one alerting path for everything"
idea: a failed build lands in the same channel as a detector crash or a blocked leak.

WHY Notifier().notify() AND NOT WebhookChannel().send(). Those three rules are properties of
the DISPATCHER, not of any channel. This file used to call `send()` directly, which walked
around all of them — so NOTIFICATIONS.md's claim that sanitisation is enforced at exactly one
choke point was false of the one caller that lived outside the package. Going through the
Notifier is what makes that claim true rather than aspirational.
"""
from __future__ import annotations

import logging
import os
import sys

# Running `python .github/notify_ci_failure.py` puts THIS file's folder (.github/) on the
# path, not the repo root, so `import haris` would fail. Add the repo root (the parent of
# this file's folder) so the package resolves — same trick demo_app/dashboard.py uses.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from haris.logging_config import configure_logging
from haris.notify import NotificationEvent, Notifier, Severity
from haris.notify.channels import WebhookChannel


def build_summary() -> str:
    """The alert text, from the workflow's env. Separated so a test can read it without
    sending anything."""
    ref = os.environ.get("CI_REF", "?")
    sha = os.environ.get("CI_SHA", "")[:8]
    actor = os.environ.get("CI_ACTOR", "?")
    run_url = os.environ.get("CI_RUN_URL", "")
    return (f"Integration tests FAILED on '{ref}' — commit {sha} by @{actor}. "
            f"Details: {run_url}")


def main(notifier: Notifier | None = None) -> Notifier:
    """Raise one CRITICAL alert for a red build. Returns the Notifier so the caller (CI, or
    a test) can read `counts` and see what actually happened."""
    # This script IS an entry point, so it configures the operational logger. That also means
    # the alert is PRINTED into the build log even when no webhook is configured — the
    # always-log rule doing real work, instead of the notification vanishing on a fork that
    # has no secrets.
    configure_logging(level=logging.INFO)

    notifier = notifier or Notifier(
        channels=[WebhookChannel(min_severity=Severity.CRITICAL)])
    try:
        notifier.notify(NotificationEvent.operational(
            "ci", build_summary(), severity=Severity.CRITICAL))
    except Exception as exc:  # noqa: BLE001
        # Best-effort: a webhook hiccup must not add a confusing traceback to an already-red
        # build. (The Notifier already contains channel errors; this is belt and braces.)
        print(f"CI failure notification could not be delivered: {type(exc).__name__}: {exc}")
        return notifier
    # `skipped` means the channel exists but has no URL; `delivered` means it posted.
    print(f"CI failure notification: {notifier.counts}")
    return notifier


if __name__ == "__main__":
    main()