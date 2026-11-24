from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

_SEVERITY_ALIASES = {
    "moderate": "medium",
    "warning": "medium",
    "error": "high",
    "note": "low",
    "informational": "info",
}


def normalize_severity(value: str | None) -> str:
    sev = (value or "").strip().lower()
    sev = _SEVERITY_ALIASES.get(sev, sev)
    return sev if sev in SEVERITY_ORDER else "medium"


def severity_rank(value: str) -> int:
    return SEVERITY_ORDER.index(normalize_severity(value))


def finding_id(*parts: object) -> str:
    digest = hashlib.sha1("|".join(str(p) for p in parts).encode("utf-8")).hexdigest()
    return f"VS-{digest[:10]}"


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    file: str
    line: int
    rule: str
    fix_hint: str
    category: str
    why: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        return cls(
            id=data["id"],
            title=data["title"],
            severity=normalize_severity(data.get("severity")),
            file=data.get("file", ""),
            line=int(data.get("line") or 0),
            rule=data.get("rule", ""),
            fix_hint=data.get("fix_hint", ""),
            category=data.get("category", ""),
            why=data.get("why", ""),
            details=data.get("details") or {},
        )


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Most severe first; dependency findings before code findings at equal severity."""
    return sorted(
        findings,
        key=lambda f: (-severity_rank(f.severity), f.category != "dependency", f.file, f.line, f.rule),
    )
