from __future__ import annotations

from .model import Finding, normalize_severity, severity_rank


def blocking(findings: list[Finding], fail_on: str) -> list[Finding]:
    if not fail_on or fail_on.lower() == "none":
        return []
    threshold = severity_rank(normalize_severity(fail_on))
    return [f for f in findings if severity_rank(f.severity) >= threshold]


def exit_code_for(findings: list[Finding], fail_on: str) -> int:
    return 1 if blocking(findings, fail_on) else 0
