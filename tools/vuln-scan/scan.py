#!/usr/bin/env python3
"""Run the dependency and code checks and write scan-results.json + scan-summary.md."""
from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from vulnscan.advisories import AdvisoryResolver  # noqa: E402
from vulnscan.antiforgery import run_antiforgery_check  # noqa: E402
from vulnscan.code import run_code_check  # noqa: E402
from vulnscan.deps import run_dependency_check  # noqa: E402
from vulnscan.gate import exit_code_for  # noqa: E402
from vulnscan.projects import discover_projects, scan_targets  # noqa: E402
from vulnscan.report import build_results, render_markdown, write_json  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOLUTIONS = ["src/NopCommerce.sln"]
DEFAULT_CODE_PATHS = ["src", "tools/vuln-scan/sample"]
# Test code and the rule fixtures contain intentionally vulnerable snippets and fake credentials.
DEFAULT_EXCLUDE = ["src/Tests", "tools/vuln-scan/rules", "tools/vuln-scan/tests"]


def _commit() -> str | None:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="scan-results.json", help="JSON results path")
    parser.add_argument("--summary", default="scan-summary.md", help="Markdown summary path")
    parser.add_argument("--solution", action="append", help=f"Solution(s) to check (default: {DEFAULT_SOLUTIONS})")
    parser.add_argument("--code-path", action="append", help=f"Paths for code rules (default: {DEFAULT_CODE_PATHS})")
    parser.add_argument("--exclude", action="append", default=[], help="Extra repo-relative paths to skip")
    parser.add_argument("--skip-deps", action="store_true", help="Skip the dotnet dependency check")
    parser.add_argument("--skip-code", action="store_true", help="Skip the code rules")
    parser.add_argument("--no-restore", action="store_true", help="Assume projects are already restored")
    parser.add_argument("--offline", action="store_true", help="Do not query GitHub for fixed versions")
    parser.add_argument("--fail-on", default="none", help="Exit 1 if any finding is at/above this severity (none|low|medium|high|critical)")
    args = parser.parse_args(argv)

    exclude = DEFAULT_EXCLUDE + args.exclude
    findings, errors, stats = [], [], {}

    if not args.skip_deps:
        solutions = [REPO_ROOT / s for s in (args.solution or DEFAULT_SOLUTIONS)]
        targets = scan_targets(REPO_ROOT, solutions, exclude)
        stats["projects_discovered"] = len(discover_projects(REPO_ROOT, exclude))
        stats["dependency_targets"] = len(targets)
        print(f"[deps] checking {len(targets)} target(s)", file=sys.stderr)
        dep_findings, dep_errors = run_dependency_check(
            targets, REPO_ROOT, AdvisoryResolver(offline=args.offline), restore=not args.no_restore
        )
        findings += dep_findings
        errors += dep_errors

    if not args.skip_code:
        paths = args.code_path or DEFAULT_CODE_PATHS
        print(f"[code] semgrep rules on {', '.join(paths)}", file=sys.stderr)
        code_findings, code_errors, code_stats = run_code_check(paths, REPO_ROOT, exclude)
        findings += code_findings
        errors += code_errors
        stats.update({f"semgrep_{k}": v for k, v in code_stats.items()})
        print("[code] antiforgery check", file=sys.stderr)
        findings += run_antiforgery_check(REPO_ROOT, paths, exclude)

    results = build_results(
        findings,
        {
            "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "commit": _commit(),
            "errors": errors,
            "stats": stats,
        },
    )
    write_json(results, Path(args.output))
    Path(args.summary).write_text(render_markdown(results), encoding="utf-8")

    by_sev = ", ".join(f"{k}={v}" for k, v in results["summary"]["by_severity"].items())
    print(f"[done] {results['summary']['total']} finding(s): {by_sev} -> {args.output}, {args.summary}", file=sys.stderr)
    for err in errors:
        print(f"[warn] {err[:500]}", file=sys.stderr)
    return exit_code_for(findings, args.fail_on)


if __name__ == "__main__":
    sys.exit(main())
