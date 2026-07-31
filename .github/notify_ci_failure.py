"""Post a CI test-failure alert to the team webhook (HARIS_ALERT_WEBHOOK).

Run by the CI workflow's `if: failure()` step. It reuses Haris's own WebhookChannel, so:
  * the Slack/Discord formatting is identical to the runtime alerts, and
  * if the HARIS_ALERT_WEBHOOK secret is not configured it is a SILENT NO-OP — CI never
    fails just because the webhook isn't set up.

Values come from the workflow's env (github context), never interpolated into the command,
so there is nothing to inject. This is the same "leverage one alerting path for everything"
idea: a failed build lands in the same channel as a detector crash or a blocked leak.
"""
from __future__ import annotations

import os
import sys

# Running `python .github/notify_ci_failure.py` puts THIS file's folder (.github/) on the
# path, not the repo root, so `import haris` would fail. Add the repo root (the parent of
# this file's folder) so the package resolves — same trick demo_app/dashboard.py uses.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from haris.notify import NotificationEvent, Severity
from haris.notify.channels import WebhookChannel

ref = os.environ.get("CI_REF", "?")
sha = os.environ.get("CI_SHA", "")[:8]
actor = os.environ.get("CI_ACTOR", "?")
run_url = os.environ.get("CI_RUN_URL", "")

summary = (f"Integration tests FAILED on '{ref}' — commit {sha} by @{actor}. "
           f"Details: {run_url}")

# send() posts regardless of severity; it is a no-op when no webhook URL is configured.
WebhookChannel().send(NotificationEvent.operational("ci", summary, severity=Severity.CRITICAL))
print("CI failure notification sent (or skipped if no webhook configured).")
