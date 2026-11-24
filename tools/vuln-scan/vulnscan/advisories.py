"""Resolve the first patched version for a GitHub security advisory (GHSA)."""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request

_GHSA = re.compile(r"GHSA(-[23456789cfghjmpqrvwx]{4}){3}", re.IGNORECASE)
_TIMEOUT = 15


def advisory_id_from_url(url: str) -> str:
    match = _GHSA.search(url or "")
    if match:
        return "GHSA" + match.group(0)[4:].lower()
    return (url or "").rstrip("/").rsplit("/", 1)[-1] or "UNKNOWN"


def _version_key(version: str) -> tuple:
    core = version.split("-", 1)[0].split("+", 1)[0]
    nums = []
    for part in core.split("."):
        nums.append(int(part) if part.isdigit() else 0)
    while len(nums) < 4:
        nums.append(0)
    return tuple(nums)


def version_in_range(version: str, range_expr: str) -> bool:
    """Evaluate a GitHub advisory range such as '>= 1.0, < 1.2.3' against a version."""
    if not range_expr:
        return False
    v = _version_key(version)
    for clause in range_expr.split(","):
        clause = clause.strip()
        m = re.match(r"(>=|<=|>|<|=)?\s*(\S+)", clause)
        if not m:
            continue
        op, bound = m.group(1) or "=", _version_key(m.group(2))
        ok = {
            ">=": v >= bound, "<=": v <= bound, ">": v > bound, "<": v < bound, "=": v == bound,
        }[op]
        if not ok:
            return False
    return True


def pick_patched_version(vulnerabilities: list[dict], package: str, installed: str) -> str | None:
    """From GitHub's advisory `vulnerabilities` list, the patch that applies to this package+version."""
    candidates = [
        v for v in vulnerabilities
        if (v.get("package") or {}).get("name", "").lower() == package.lower()
        and (v.get("package") or {}).get("ecosystem", "nuget").lower() == "nuget"
    ]
    for vuln in candidates:
        if version_in_range(installed, vuln.get("vulnerable_version_range", "")):
            return vuln.get("first_patched_version") or None
    patched = [v.get("first_patched_version") for v in candidates if v.get("first_patched_version")]
    return max(patched, key=_version_key) if patched else None


def _get_json(url: str, headers: dict[str, str]) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": "nop-vuln-scan", **headers})
    with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8"))


class AdvisoryResolver:
    """Looks up advisories once per id; tolerates network failures by returning None."""

    def __init__(self, offline: bool = False):
        self.offline = offline
        self._cache: dict[str, dict | None] = {}

    def _fetch(self, ghsa_id: str) -> dict | None:
        if ghsa_id in self._cache:
            return self._cache[ghsa_id]
        data = None
        if not self.offline and ghsa_id.upper().startswith("GHSA-"):
            headers = {"Accept": "application/vnd.github+json"}
            token = os.environ.get("GITHUB_TOKEN")
            if token:
                headers["Authorization"] = f"Bearer {token}"
            try:
                data = _get_json(f"https://api.github.com/advisories/{ghsa_id}", headers)
            except (urllib.error.URLError, TimeoutError, ValueError):
                data = None
        self._cache[ghsa_id] = data
        return data

    def resolve(self, ghsa_id: str, package: str, installed: str) -> dict:
        data = self._fetch(ghsa_id) or {}
        return {
            "fixed_version": pick_patched_version(data.get("vulnerabilities") or [], package, installed),
            "summary": data.get("summary"),
            "cve_id": data.get("cve_id"),
        }
