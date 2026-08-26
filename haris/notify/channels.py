"""External notification channels — where an alert is actually delivered.

Right now this holds the webhook channel (the out-of-band push), the SES email channel, and
the in-memory buffer the dashboard banner reads. The banner itself renders in a UI rather
than POSTing anywhere, which is why it is a buffer the dashboard drains
(`demo_app/dashboard.py`) rather than a channel that delivers.

WebhookChannel posts an alert to a Slack or Discord *incoming webhook*. Two deliberate design
choices for a student team:

  * ZERO CONFIG TO BREAK. The URL comes from an environment variable (default
    `HARIS_ALERT_WEBHOOK`). If it is unset the channel is a silent no-op — local runs, tests,
    and a teammate who hasn't set up the webhook all keep working, and no secret URL is ever
    committed to the repo.
  * PLATFORM-AGNOSTIC. It detects Slack vs Discord from the URL and formats the payload for
    whichever you use, so switching platforms is just changing the env var — no code change.

It uses only the standard library (`urllib`), so it adds nothing to `requirements.txt`. The
event it receives has already been sanitized by the Notifier (metadata stripped), and it only
ever transmits `event.one_line()` — sender/receiver/summary/severity — never message content.

A failed POST (timeout, 4xx/5xx) raises; the Notifier contains it and logs it, so a broken
webhook can never take down the protected app or block the other channels.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections import deque
from typing import Optional

from haris.logging_config import get_logger
from haris.notify.notifier import Channel
from haris.schemas.notification import NotificationEvent, Severity

_log = get_logger("notify.webhook")

# Brand-ish accent colors by severity (red / amber / green). Discord wants an int, Slack a hex.
_DISCORD_COLOR = {Severity.CRITICAL: 0xE01E5A, Severity.WARNING: 0xECB22E, Severity.INFO: 0x2EB67D}
_SLACK_COLOR = {Severity.CRITICAL: "#E01E5A", Severity.WARNING: "#ECB22E", Severity.INFO: "#2EB67D"}

_DEFAULT_ENV_VAR = "HARIS_ALERT_WEBHOOK"

_SES_SENDER_ENV = "HARIS_SES_SENDER"
_SES_RECIPIENTS_ENV = "HARIS_SES_RECIPIENTS"   # comma-separated
_SES_REGION_ENV = "HARIS_SES_REGION"

_ses_log = get_logger("notify.ses")


class WebhookChannel(Channel):
    """Posts alerts to a Slack or Discord incoming webhook. No-op when no URL is configured.

    By default it only fires for CRITICAL events (Haris down, a detector crash), matching the
    routing table in NOTIFICATIONS.md — the out-of-band channel is reserved for "look now".
    For a demo where you also want blocked-leak WARNINGs to hit the channel, construct it with
    `min_severity=Severity.WARNING`.
    """
    name = "webhook"

    def __init__(self, url: Optional[str] = None, *,
                 min_severity: Severity = Severity.CRITICAL,
                 timeout_s: float = 5.0,
                 env_var: str = _DEFAULT_ENV_VAR) -> None:
        # Explicit url wins; otherwise read the env var. None => disabled (silent no-op).
        self.url = url or os.environ.get(env_var)
        self.min_severity = min_severity
        self.timeout_s = timeout_s
        self._env_var = env_var
        if not self.url:
            _log.info("notify.webhook: no %s set — webhook channel disabled (no-op)", env_var)

    @property
    def enabled(self) -> bool:
        return bool(self.url)

    def send(self, event: NotificationEvent) -> None:
        if not self.url:
            return  # unconfigured — nothing to do, and that is fine
        payload = self._format(event)
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.url, data=data,
            headers={
                "Content-Type": "application/json",
                # Discord sits behind Cloudflare, which returns 403 Forbidden to requests
                # carrying urllib's default "Python-urllib/x.y" User-Agent. Send an explicit
                # one so the POST is accepted. (Slack and generic receivers accept it too.)
                "User-Agent": "Haris-Notifier/1.0 (+https://github.com/zdk02/Haris-Team23)",
            },
            method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                status = getattr(resp, "status", None) or resp.getcode()
                if status >= 300:  # Discord=204, Slack=200 on success
                    raise RuntimeError(f"webhook POST returned HTTP {status}")
        except urllib.error.URLError as exc:
            # Re-raise as a plain error the Notifier's guard will log; keep the URL out of it.
            raise RuntimeError(f"webhook POST failed: {exc.reason}") from exc

    # -- payload formatting ---------------------------------------------------------------
    def _platform(self) -> str:
        u = self.url or ""
        if "discord.com" in u or "discordapp.com" in u:
            return "discord"
        if "hooks.slack.com" in u:
            return "slack"
        return "generic"

    def _format(self, event: NotificationEvent) -> dict:
        text = event.one_line()
        platform = self._platform()
        if platform == "discord":
            return {"embeds": [{
                "title": f"Haris · {event.severity.value.upper()}",
                "description": text,
                "color": _DISCORD_COLOR.get(event.severity, 0x808080),
            }]}
        if platform == "slack":
            return {"attachments": [{
                "color": _SLACK_COLOR.get(event.severity, "#808080"),
                "fallback": text,
                "text": text,
            }]}
        # Unknown target: a plain body most webhook receivers accept.
        return {"text": f"Haris alert — {text}"}

class SESChannel(Channel):
    """Emails an alert via Amazon SES. Deliberately the SAME SHAPE as WebhookChannel:
    env-var configuration, a silent no-op when unset, CRITICAL-only by default.

    That symmetry is the point. The `Channel` abstraction claims a new delivery mechanism is
    a new class and nothing else — this is the class that tests the claim, and not one line
    of `notifier.py` changed to accept it.

    boto3 is imported LAZILY inside `send()`, so SES costs nothing to anyone who does not use
    it: it is not in `requirements.lock.txt` and not in the container image. That is a
    decision, not an oversight. The deployed ECS task role carries NO policies at all
    (`haris-infra.yaml`), so the container holds credentials that cannot call SES — and it
    should not. Alerting for "Haris is not running" is out-of-process (a CloudWatch alarm on
    HealthyHostCount -> SNS -> email), because an in-process alerter cannot report its own
    absence: the code that would send the message is the code that stopped.

    SES SANDBOX. Until production access is granted, BOTH the sender and every recipient must
    be a verified SES identity. For a demo whose recipients are verified team addresses that
    is sufficient, and it is why production access is not on the critical path.
    """
    name = "ses"

    def __init__(self, sender: Optional[str] = None, recipients=None, *,
                 region: Optional[str] = None,
                 min_severity: Severity = Severity.CRITICAL,
                 client=None) -> None:
        self.sender = sender or os.environ.get(_SES_SENDER_ENV)
        raw = recipients if recipients is not None else os.environ.get(_SES_RECIPIENTS_ENV, "")
        if isinstance(raw, str):
            raw = [a.strip() for a in raw.split(",") if a.strip()]
        self.recipients = list(raw)
        self.region = (region or os.environ.get(_SES_REGION_ENV)
                       or os.environ.get("AWS_REGION"))
        self.min_severity = min_severity
        self._client = client      # injectable, so tests need neither boto3 nor network
        if not self.enabled:
            _ses_log.info("notify.ses: %s / %s not set — SES channel disabled (no-op)",
                          _SES_SENDER_ENV, _SES_RECIPIENTS_ENV)

    @property
    def enabled(self) -> bool:
        return bool(self.sender and self.recipients)

    def _get_client(self):
        if self._client is None:
            import boto3          # lazy: never a hard dependency of the package or the image
            self._client = boto3.client("ses", region_name=self.region)
        return self._client

    def send(self, event: NotificationEvent) -> None:
        if not self.enabled:
            return  # unconfigured — nothing to do, and that is fine
        # Only ever one_line(): severity, category, source, summary, session and the
        # truncated reference. The event was already sanitized by the Notifier; this
        # transmits no message content, exactly as the webhook does. It matters more here —
        # an email is forwarded far more easily than a chat message.
        self._get_client().send_email(
            Source=self.sender,
            Destination={"ToAddresses": self.recipients},
            Message={
                "Subject": {"Data": f"Haris · {event.severity.value.upper()} · {event.source}"},
                "Body": {"Text": {"Data": event.one_line()}},
            },
        )

class BufferChannel(Channel):
    """An in-memory ring buffer of the most recent alerts, for a UI to read and render.

    Unlike the webhook it doesn't *send* anywhere — it *keeps* the latest events so the
    dashboard's alert banner can display them (the same way the dashboard reads the audit
    log rather than the pipeline). Bounded by `capacity` so it can't grow without limit.

    Events are stored most-recent-first. Default `min_severity=WARNING`, so the banner
    surfaces blocked-leak WARNINGs and Haris-down CRITICALs but not routine INFO.
    """
    name = "buffer"

    def __init__(self, capacity: int = 50,
                 min_severity: Severity = Severity.WARNING) -> None:
        self.min_severity = min_severity
        self._events: deque[NotificationEvent] = deque(maxlen=capacity)

    def send(self, event: NotificationEvent) -> None:
        self._events.appendleft(event)

    def events(self) -> list[NotificationEvent]:
        """Most recent first."""
        return list(self._events)

    def clear(self) -> None:
        self._events.clear()
