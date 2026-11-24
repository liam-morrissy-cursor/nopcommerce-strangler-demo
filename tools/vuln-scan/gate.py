#!/usr/bin/env python3
"""Exit non-zero when scan-results.json contains findings at or above a severity."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from vulnscan.gate import blocking  # noqa: E402
from vulnscan.model import sort_findings  # noqa: E402
from vulnscan.report import load_findings  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", nargs="?", default="scan-results.json")
    parser.add_argument("--fail-on", default="high")
    args = parser.parse_args(argv)

    hits = sort_findings(blocking(load_findings(Path(args.results)), args.fail_on))
    if not hits:
        print(f"No findings at or above '{args.fail_on}'.")
        return 0
    print(f"{len(hits)} finding(s) at or above '{args.fail_on}':")
    for f in hits:
        print(f"::error file={f.file},line={f.line},title={f.rule}::[{f.severity}] {f.title}. {f.fix_hint}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
