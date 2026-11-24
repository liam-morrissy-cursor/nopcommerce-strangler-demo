"""Format a finding as a Slack message and post it through an incoming webhook."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from urllib.parse import urlparse

from .model import Finding

SEVERITY_EMOJI = {
    "critical": ":rotating_light:",
    "high": ":red_circle:",
    "medium": ":large_orange_circle:",
    "low": ":large_yellow_circle:",
    "info": ":information_source:",
}
REMEDIATE_LINE = "@ the bot to remediate"
ALLOWED_WEBHOOK_HOSTS = {"hooks.slack.com"}


def escape(text: str) -> str:
    """Slack mrkdwn treats &, < and > as control characters."""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def format_text(finding: Finding) -> str:
    """Plain mrkdwn body. Line order is stable so a bot can parse it."""
    location = f"{finding.file}:{finding.line}"
    why = finding.why or finding.details.get("message") or finding.title
    machine = {
        "id": finding.id,
        "rule": finding.rule,
        "severity": finding.severity,
        "file": finding.file,
        "line": finding.line,
        "fix_hint": finding.fix_hint,
    }
    return "\n".join(
        [
            f"{SEVERITY_EMOJI.get(finding.severity, '')} *{finding.severity.upper()}*: {escape(finding.title)}".strip(),
            f"`{escape(location)}`",
            f"Why it matters: {escape(why)}",
            f"Fix hint: {escape(finding.fix_hint)}",
            "```" + escape(json.dumps(machine, separators=(",", ":"))) + "```",
            REMEDIATE_LINE,
        ]
    )


def build_payload(finding: Finding, channel: str | None) -> dict:
    payload: dict = {"text": format_text(finding), "unfurl_links": False, "unfurl_media": False}
    if channel:
        payload["channel"] = channel
    return payload


def validate_webhook(url: str | None) -> str:
    if not url:
        raise ValueError("SLACK_WEBHOOK_URL is not set")
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_WEBHOOK_HOSTS:
        raise ValueError("SLACK_WEBHOOK_URL must be an https://hooks.slack.com/ incoming webhook")
    return url


def post(payload: dict, webhook_url: str, timeout: int = 15) -> None:
    """Errors never include the webhook URL, because it is itself a credential."""
    url = validate_webhook(webhook_url)
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", "replace")
            if response.status != 200 or body.strip() != "ok":
                raise RuntimeError(f"Slack rejected the message (HTTP {response.status}): {body[:200]}")
    except urllib.error.HTTPError as err:
        raise RuntimeError(f"Slack webhook returned HTTP {err.code}: {err.read()[:200]!r}") from None
    except urllib.error.URLError as err:
        raise RuntimeError(f"Could not reach Slack: {err.reason}") from None
