"""Code check: runs the Semgrep rules in ../rules and converts results to findings."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .model import Finding, finding_id, normalize_severity

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def semgrep_results_to_findings(report: dict, repo_root: Path) -> list[Finding]:
    findings = []
    for result in report.get("results") or []:
        meta = (result.get("extra") or {}).get("metadata") or {}
        rule = result["check_id"].rsplit(".", 1)[-1]
        path = Path(result["path"])
        if path.is_absolute():
            try:
                path = path.relative_to(repo_root.resolve())
            except ValueError:
                pass
        line = int((result.get("start") or {}).get("line") or 0)
        findings.append(
            Finding(
                id=finding_id("code", rule, path.as_posix(), line),
                title=meta.get("title") or result.get("extra", {}).get("message", rule),
                severity=normalize_severity(meta.get("vulnscan_severity") or result["extra"].get("severity")),
                file=path.as_posix(),
                line=line,
                rule=f"code/{rule}",
                fix_hint=meta.get("fix_hint", ""),
                category="code",
                why=meta.get("why", ""),
                details={"cwe": meta.get("cwe"), "message": result.get("extra", {}).get("message", "").strip()},
            )
        )
    return findings


def run_code_check(
    paths: list[str], repo_root: Path, exclude: list[str]
) -> tuple[list[Finding], list[str], dict]:
    """Returns findings, errors, and scan stats (files scanned, files Semgrep only partially parsed)."""
    if shutil.which("semgrep") is None:
        return [], ["semgrep is not installed (pip install -r tools/vuln-scan/requirements.txt)"], {}
    cmd = [
        "semgrep", "scan", "--config", str(RULES_DIR), "--json", "--metrics=off",
        "--disable-version-check", "--quiet",
    ]
    for pattern in exclude:
        cmd += ["--exclude", pattern]
    cmd += paths
    result = subprocess.run(cmd, cwd=repo_root, capture_output=True, text=True)
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        return [], [f"semgrep failed (exit {result.returncode}): {result.stderr[-2000:]}"], {}

    errors = []
    partial = 0
    for err in report.get("errors") or []:
        kind = err.get("type")
        if isinstance(kind, list) and kind and kind[0] == "PartialParsing":
            partial += 1
        elif err.get("level") == "error":
            errors.append(f"semgrep: {err.get('message', err)}"[:500])
    stats = {"files_scanned": len((report.get("paths") or {}).get("scanned") or []), "partially_parsed": partial}
    return semgrep_results_to_findings(report, repo_root), errors, stats
