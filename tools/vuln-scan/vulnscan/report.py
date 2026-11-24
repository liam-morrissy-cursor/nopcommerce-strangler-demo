from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from .model import SEVERITY_ORDER, Finding, sort_findings

SCHEMA_VERSION = 1


def build_results(findings: list[Finding], meta: dict) -> dict:
    ordered = sort_findings(findings)
    counts = Counter(f.severity for f in ordered)
    return {
        "schema_version": SCHEMA_VERSION,
        **meta,
        "summary": {
            "total": len(ordered),
            "by_severity": {sev: counts.get(sev, 0) for sev in reversed(SEVERITY_ORDER)},
        },
        "findings": [f.to_dict() for f in ordered],
    }


def write_json(results: dict, path: Path) -> None:
    path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")


def load_findings(path: Path) -> list[Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [Finding.from_dict(f) for f in data.get("findings") or []]


def _cell(text: str) -> str:
    return str(text).replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;").replace("\n", " ")


def render_markdown(results: dict) -> str:
    findings = [Finding.from_dict(f) for f in results["findings"]]
    by_sev = results["summary"]["by_severity"]
    lines = [
        "# Vulnerability scan summary",
        "",
        f"Scanned at {results.get('scanned_at', 'n/a')} (commit `{results.get('commit') or 'n/a'}`).",
        "",
        "| Severity | Count |",
        "| --- | --- |",
        *[f"| {sev} | {count} |" for sev, count in by_sev.items()],
        "",
    ]
    if not findings:
        lines += ["No findings.", ""]
    else:
        lines += [
            "| # | Severity | Title | Location | Rule | Fix hint |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for i, f in enumerate(findings, start=1):
            lines.append(
                f"| {i} | **{f.severity}** | {_cell(f.title)} | `{f.file}:{f.line}` | `{f.rule}` | {_cell(f.fix_hint)} |"
            )
        lines.append("")
    errors = results.get("errors") or []
    if errors:
        lines += ["## Scanner errors", ""] + [f"- {_cell(e)[:300]}" for e in errors] + [""]
    stats = results.get("stats") or {}
    if stats:
        lines += ["## Coverage", ""] + [f"- {k.replace('_', ' ')}: {v}" for k, v in stats.items()] + [""]
    return "\n".join(lines)
