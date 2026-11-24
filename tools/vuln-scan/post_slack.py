#!/usr/bin/env python3
"""Post the top finding from scan-results.json to Slack.

Reads the webhook from SLACK_WEBHOOK_URL and the channel from SLACK_CHANNEL. The webhook is
never printed; use --dry-run to preview the payload without sending anything.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from vulnscan.gate import blocking  # noqa: E402
from vulnscan.model import sort_findings  # noqa: E402
from vulnscan.report import load_findings  # noqa: E402
from vulnscan.slack import build_payload, post  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("results", nargs="?", default="scan-results.json")
    parser.add_argument("--min-severity", default="low", help="Only post if the top finding is at/above this")
    parser.add_argument("--dry-run", action="store_true", help="Print the Slack payload instead of posting")
    args = parser.parse_args(argv)

    findings = sort_findings(blocking(load_findings(Path(args.results)), args.min_severity))
    if not findings:
        print(f"No findings at or above '{args.min_severity}'; nothing to post.")
        return 0

    channel = os.environ.get("SLACK_CHANNEL")
    payload = build_payload(findings[0], channel)
    if args.dry_run:
        print(json.dumps(payload, indent=2))
        print("\n--- rendered text ---\n" + payload["text"])
        return 0

    if not channel:
        print("SLACK_CHANNEL is not set.", file=sys.stderr)
        return 2
    try:
        post(payload, os.environ.get("SLACK_WEBHOOK_URL"))
    except (ValueError, RuntimeError) as err:
        print(f"Slack post failed: {err}", file=sys.stderr)
        return 1
    print(f"Posted {findings[0].id} ({findings[0].severity}) to {channel}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
